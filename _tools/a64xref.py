"""Referencias cruzadas EXACTAS sobre el .so de arm64 decodificando ADRP/ADD.

En AArch64 las direcciones se forman con:
    ADRP Xd, pagina        (direccion de pagina relativa a PC)
    ADD  Xd, Xd, #offset   (12 bits bajos)
El linker resuelve las dos sin dejar relocacion, asi que hay que decodificar
las instrucciones. Son dos formatos de longitud fija: trivial.

Uso:
    python _tools/a64xref.py <so-arm64> --xref sjunlockAll
    python _tools/a64xref.py <so-arm64> --func DebugSettings
    python _tools/a64xref.py <so-arm64> --xref currentZone --all
    python _tools/a64xref.py <so-arm64> --dump-rodata     (que funciones usan que cadenas)
"""
import argparse
import collections
import re
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from elf import Elf  # noqa: E402


def sx(value, bits):
    if value & (1 << (bits - 1)):
        value -= (1 << bits)
    return value


def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    rd = insn & 0x1F
    imm = sx((immhi << 2) | immlo, 21)
    return rd, ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFF


def decode_add_imm(insn):
    """ADD (immediate) 32/64 bits. Devuelve (rd, rn, imm, sf) o None."""
    if (insn & 0x7F000000) != 0x11000000:
        return None
    sf = (insn >> 31) & 1
    sh = (insn >> 22) & 1
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return rd, rn, imm12 << (12 if sh else 0), sf


def decode_ldr_imm(insn):
    """LDR Xt, [Xn, #imm12] (64 bits). Devuelve (rt, rn, imm) o None."""
    if (insn & 0xFFC00000) != 0xF9400000:
        return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    return rt, rn, imm12 * 8


class A64(object):
    def __init__(self, path):
        self.el = Elf(path)
        self.named = []
        for s in self.el.functions():
            self.named.append((s['value'], s['name']))
        self.named.sort()
        self.named_addrs = [a for a, _ in self.named]
        self.ranges = self.el.function_ranges()
        self.range_starts = [a for a, _ in self.ranges]
        self.refs = collections.defaultdict(list)   # target -> [(instr_addr, reg)]
        self._scan()

    def owner(self, va):
        """Nombre de la funcion que contiene va (via .eh_frame_hdr + .dynsym)."""
        import bisect
        if not self.ranges:
            return None
        i = bisect.bisect_right(self.range_starts, va) - 1
        if i < 0:
            return None
        start, end = self.ranges[i]
        if not (start <= va < end):
            return None
        # mejor nombre: simbolo .dynsym dentro de este rango
        j = bisect.bisect_right(self.named_addrs, va) - 1
        if j >= 0 and self.named[j][0] >= start:
            return self.named[j][1]
        return 'sub_%X' % start

    def _scan(self):
        sec = self.el.section('.text')
        lo, hi = sec['addr'], sec['addr'] + sec['size']
        buf = self.el.buf
        page = {}          # registro -> (pagina, addr)
        for pc in range(lo, hi - 4, 4):
            insn = struct.unpack_from('<I', buf, pc)[0]
            d = decode_adrp(insn, pc)
            if d:
                page[d[0]] = (d[1], pc)
                continue
            a = decode_add_imm(insn)
            if a:
                rd, rn, imm, sf = a
                if rn in page and pc - page[rn][1] <= 32:
                    self.refs[(page[rn][0] + imm) & 0xFFFFFFFFFFFF].append((pc, rd, 'adrp+add'))
                continue
            l = decode_ldr_imm(insn)
            if l:
                rt, rn, imm = l
                if rn in page and pc - page[rn][1] <= 32:
                    self.refs[(page[rn][0] + imm) & 0xFFFFFFFFFFFF].append((pc, rt, 'adrp+ldr'))

    def string_span(self, va):
        f = self.el.file_of_vaddr(va)
        if f is None:
            return None
        s = f
        while s > 0 and 0x20 <= self.el.buf[s - 1] < 0x7f:
            s -= 1
        e = f
        while e < len(self.el.buf) and 0x20 <= self.el.buf[e] < 0x7f:
            e += 1
        return self.el.buf[s:e].decode('latin1'), s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('--xref')
    ap.add_argument('--func')
    ap.add_argument('--all', action='store_true', help='muestra todos los usos')
    ap.add_argument('--limit', type=int, default=20)
    ap.add_argument('--dump-rodata', action='store_true',
                    help='lista destinos en .rodata agrupados por funcion')
    args = ap.parse_args()

    a = A64(args.so)
    print('referencias ADRP resueltas: %d' % len(a.refs))

    if args.func:
        rx = re.compile(args.func, re.I)
        for lo, hi, n in a.funcs:
            if rx.search(n):
                print('  0x%08x-0x%08x  %s' % (lo, hi, n))
        return

    if args.dump_rodata:
        ro = a.el.section('.rodata')
        rlo, rhi = ro['addr'], ro['addr'] + ro['size']
        byfunc = collections.defaultdict(list)
        for target, sites in a.refs.items():
            if not (rlo <= target < rhi):
                continue
            span = a.string_span(target)
            if not span or len(span[0]) < 3:
                continue
            for pc, rd, kind in sites:
                byfunc[a.owner(pc)].append((pc, span[0]))
        for fn in sorted(byfunc, key=lambda x: (x is None, x)):
            print('--- %s' % fn)
            seen = set()
            for pc, s in sorted(byfunc[fn]):
                if s in seen:
                    continue
                seen.add(s)
                print('      0x%08x  %s' % (pc, s[:95]))
        return

    if not args.xref:
        ap.error('falta --xref o --func o --dump-rodata')

    offs = []
    i = a.el.buf.find(args.xref.encode())
    while i >= 0:
        offs.append(i)
        i = a.el.buf.find(args.xref.encode(), i + 1)
    if not offs:
        print('no encontrado:', args.xref)

    for foff in offs[:8]:
        va = a.el.vaddr_of_file(foff)
        span = a.string_span(va)
        print()
        print('=== "%s"  fichero 0x%08x  VA 0x%08x' %
              ((span[0] if span else '?')[:80], foff, va))
        sites = a.refs.get(va)
        direct = []
        if not sites:
            # buscar referencias a la cadena contenedora o a offsets cercanos
            for cand in range(va - 64, va + 64):
                if cand in a.refs:
                    direct.append((cand, a.refs[cand]))
        if sites:
            for pc, rd, kind in (sites if args.all else sites[:args.limit]):
                print('    @0x%08x  %-9s  [%s]' % (pc, kind, a.owner(pc) or '???'))
        else:
            print('    sin ADRP directo')
        for cand, s2 in direct:
            sp = a.string_span(cand)
            print('    (cercano) 0x%08x = %r' % (cand, (sp[0] if sp else '')[:60]))
            for pc, rd, kind in s2[:args.limit]:
                print('        @0x%08x  [%s]' % (pc, a.owner(pc) or '???'))


if __name__ == '__main__':
    main()
