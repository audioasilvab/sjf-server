"""Busca constantes de 32 bits materializadas con MOVW/MOVT en codigo Thumb-2.

En este .so no hay relocaciones dentro de .text, asi que las direcciones de
cadenas y objetos se construyen con pares MOVW (mitad baja) + MOVT (mitad alta)
o como desplazamiento relativo a PC. Este script decodifica las instrucciones
(no hace falta desensamblador completo, solo 2 formatos) y devuelve que
constantes se materializan y donde.

Uso:
    python _tools/armxref.py <so> --stats
    python _tools/armxref.py <so> --xref sjunlockAll
    python _tools/armxref.py <so> --xref currentZone --window 0x200000
"""
import argparse
import collections
import re
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from elf import Elf  # noqa: E402


def decode_movw_movt(h1, h2):
    """Devuelve (tipo, rd, imm16) si h1:h2 es MOVW/MOVT Thumb-2, si no None.

    MOVW T3: 11110 i 10 0100 imm4 | 0 imm3 Rd imm8
    MOVT T3: 11110 i 10 1100 imm4 | 0 imm3 Rd imm8
    """
    if (h1 & 0xF800) != 0xF000:
        return None
    if (h1 & 0x0300) != 0x0200:      # bits 9..8 deben ser 10
        return None
    op = (h1 >> 4) & 0x0F
    if op not in (0x04, 0x0C):       # 0100 = MOVW, 1100 = MOVT
        return None
    if (h2 & 0x8000) != 0:
        return None
    i = (h1 >> 10) & 1
    imm4 = h1 & 0x0F
    imm3 = (h2 >> 12) & 0x07
    rd = (h2 >> 8) & 0x0F
    imm8 = h2 & 0xFF
    imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
    return ('movw' if op == 0x04 else 'movt'), rd, imm16


def scan_constants(el, secname='.text'):
    sec = el.section(secname)
    lo, hi = sec['addr'], sec['addr'] + sec['size']
    b = el.buf
    out = []
    pending = {}
    for addr in range(lo, hi - 4, 2):
        h1, h2 = struct.unpack_from('<HH', b, addr)
        d = decode_movw_movt(h1, h2)
        if not d:
            continue
        kind, rd, imm = d
        if kind == 'movw':
            pending[rd] = (imm, addr)
        else:
            if rd in pending:
                low, lowaddr = pending.pop(rd)
                if addr - lowaddr <= 64:      # par consecutivo
                    out.append((lowaddr, (imm << 16) | low, rd))
            else:
                out.append((addr, imm << 16, rd))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('--stats', action='store_true')
    ap.add_argument('--xref')
    ap.add_argument('--window', type=lambda x: int(x, 0), default=0x200000)
    ap.add_argument('--limit', type=int, default=20)
    args = ap.parse_args()

    el = Elf(args.so)
    consts = scan_constants(el)
    print('constantes MOVW/MOVT encontradas en .text: %d' % len(consts))

    if args.stats:
        buckets = collections.Counter()
        for addr, val, rd in consts:
            buckets[val >> 16] += 1
        for hi in sorted(buckets):
            print('  0x%04x0000  x%d' % (hi, buckets[hi]))
        return

    if not args.xref:
        return

    hits = []
    i = el.buf.find(args.xref.encode())
    while i >= 0:
        hits.append(i)
        i = el.buf.find(args.xref.encode(), i + 1)
    if not hits:
        print('no encontrado:', args.xref)
        return

    funcs = []
    for s in el.functions():
        v = s['value'] & ~1
        funcs.append((v, v + max(s['size'], 2), s['name']))
    funcs.sort()

    def owner(va):
        prev = None
        for a, b, n in funcs:
            if a <= va < b:
                return n
            if a > va:
                break
            prev = n
        return prev

    for foff in hits[:6]:
        va = el.vaddr_of_file(foff)
        s = foff
        while s > 0 and 0x20 <= el.buf[s - 1] < 0x7f:
            s -= 1
        e = foff
        while e < len(el.buf) and 0x20 <= el.buf[e] < 0x7f:
            e += 1
        print()
        print('=== "%s"  fichero 0x%08x  VA 0x%08x' %
              (el.buf[s:e].decode('latin1')[:80], foff, va))
        found = 0
        for addr, val, rd in consts:
            for k in (0, 2, 4, 8):
                if abs((addr + k + val) - va) == 0:
                    print('    PC-rel: movw/movt @0x%08x (r%d, +%d) -> 0x%08x  [%s]' %
                          (addr, rd, k, va, owner(addr) or '???'))
                    found += 1
            if val == va:
                print('    ABS   : movw/movt @0x%08x (r%d) -> 0x%08x  [%s]' %
                      (addr, rd, val, owner(addr) or '???'))
                found += 1
            elif abs(val - va) <= args.window and val > 0x1000:
                pass
        if not found:
            print('    sin coincidencia exacta; constantes cercanas:')
            near = sorted(consts, key=lambda c: abs(c[1] - va))[:args.limit]
            for addr, val, rd in near:
                print('       @0x%08x r%-2d const=0x%08x delta=%+d  [%s]' %
                      (addr, rd, val, val - va, owner(addr) or '???'))


if __name__ == '__main__':
    main()
