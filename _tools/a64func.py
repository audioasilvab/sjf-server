"""Analisis del .so arm64: que cadenas usa cada funcion y quien llama a quien.

Decodifica ADRP/ADD (direcciones) y BL (llamadas) directamente de las
instrucciones, sin desensamblador completo.

Uso:
    python _tools/a64xref.py <so> --list-func Connect
    python _tools/a64xref.py <so> --strings-of _ZN26SonicJumpConnectionManager15requestSettingsEv
    python _tools/a64xref.py <so> --callers    _ZN7network14ServerSettings11deserializeEPKN2sl9DOMObjectEb
    python _tools/a64xref.py <so> --strings-of ServerSettings
    python _tools/a64xref.py <so> --find _ZN16ZoneChangeScreen
"""
import argparse
import bisect
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


def dec_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    rd = insn & 0x1F
    imm = sx((immhi << 2) | immlo, 21)
    return rd, ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFF


def dec_add(insn):
    if (insn & 0x7F000000) != 0x11000000:
        return None
    sh = (insn >> 22) & 1
    imm12 = (insn >> 10) & 0xFFF
    return insn & 0x1F, (insn >> 5) & 0x1F, imm12 << (12 if sh else 0)


def dec_ldr(insn):
    if (insn & 0xFFC00000) != 0xF9400000:
        return None
    return insn & 0x1F, (insn >> 5) & 0x1F, ((insn >> 10) & 0xFFF) * 8


def dec_bl(insn, pc):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    return (pc + (sx(insn & 0x3FFFFFF, 26) << 2)) & 0xFFFFFFFFFFFF


class A64(object):
    def __init__(self, path):
        self.el = Elf(path)
        self.named = sorted((s['value'], s['name']) for s in self.el.functions())
        self.named_addrs = [a for a, _ in self.named]
        self.ranges = self.el.function_ranges()
        self.range_starts = [a for a, _ in self.ranges]

    # -------------------------------------------------------------- nombres
    def name_at(self, va):
        i = bisect.bisect_right(self.named_addrs, va) - 1
        if i >= 0:
            return self.named[i][1], self.named[i][0]
        return None, None

    def func_range_of(self, va):
        i = bisect.bisect_right(self.range_starts, va) - 1
        if i < 0:
            return None
        s, e = self.ranges[i]
        return (s, e) if s <= va < e else None

    def label(self, va):
        n, a = self.name_at(va)
        r = self.func_range_of(va)
        start = r[0] if r else None
        if n and start is not None and a >= start:
            return n
        return 'sub_%X' % (start if start else va)

    def resolve(self, pattern, limit=60):
        out = []
        rx = re.compile(pattern, re.I)
        for a, n in self.named:
            if rx.search(n):
                out.append((a, n))
        return out[:limit]

    # ------------------------------------------------------------- escaneo
    def scan_function(self, start, end, resolve_calls=True):
        buf = self.el.buf
        page = {}
        strings = []
        calls = []
        for pc in range(start, end - 4, 4):
            insn = struct.unpack_from('<I', buf, pc)[0]
            d = dec_adrp(insn, pc)
            if d:
                page[d[0]] = (d[1], pc)
                continue
            a = dec_add(insn)
            if a:
                rd, rn, imm = a
                if rn in page and pc - page[rn][1] <= 48:
                    tgt = page[rn][0] + imm
                    s = self.read_string(tgt)
                    if s:
                        strings.append((pc, tgt, s))
                continue
            l = dec_ldr(insn)
            if l:
                rt, rn, imm = l
                if rn in page and pc - page[rn][1] <= 48:
                    tgt = page[rn][0] + imm
                    s = self.read_string(tgt)
                    if s:
                        strings.append((pc, tgt, s))
                continue
            if resolve_calls:
                c = dec_bl(insn, pc)
                if c is not None and c != 0:
                    calls.append((pc, c))
        return strings, calls

    def read_string(self, va):
        f = self.el.file_of_vaddr(va)
        if f is None or not (0 <= f < len(self.el.buf)):
            return None
        if not (0x20 <= self.el.buf[f] < 0x7f):
            return None
        s = f
        while s > 0 and 0x20 <= self.el.buf[s - 1] < 0x7f:
            s -= 1
        e = f
        while e < len(self.el.buf) and 0x20 <= self.el.buf[e] < 0x7f:
            e += 1
        txt = self.el.buf[s:e].decode('latin1')
        return txt if 2 <= len(txt) <= 200 else None


def all_callers(a, target_group):
    """Busca quien llama a cualquiera de las direcciones objetivo."""
    buf = a.el.buf
    text = a.el.section('.text')
    out = []
    for pc in range(text['addr'], text['addr'] + text['size'] - 4, 4):
        insn = struct.unpack_from('<I', buf, pc)[0]
        c = dec_bl(insn, pc)
        if c is not None and c in target_group:
            out.append(pc)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('--list-func')
    ap.add_argument('--strings-of')
    ap.add_argument('--callers')
    ap.add_argument('--find')
    ap.add_argument('--limit', type=int, default=80)
    args = ap.parse_args()

    a = A64(args.so)
    print('funciones: %d rangos .eh_frame, %d con nombre' % (len(a.ranges), len(a.named)))

    if args.find:
        for addr, n in a.resolve(args.find, args.limit):
            r = a.func_range_of(addr)
            print('  0x%08x  %-70s  rango 0x%x-0x%x' %
                  (addr, n[:70], r[0], r[1]) if r else '  0x%08x  %s' % (addr, n))
        return

    if args.list_func:
        for addr, n in a.resolve(args.list_func, args.limit):
            print('  0x%08x  %s' % (addr, n))
        return

    if args.callers:
        targets = set()
        for addr, n in a.resolve(args.callers, 40):
            targets.add(addr)
        if not targets:
            print('no encuentro la funcion')
            return
        sites = all_callers(a, targets)
        print('llamadas encontradas: %d' % len(sites))
        groups = collections.Counter(a.label(pc) for pc in sites)
        for name, c in groups.most_common(args.limit):
            print('   x%-3d %s' % (c, name))
        return

    if args.strings_of:
        for addr, n in a.resolve(args.strings_of, 12):
            r = a.func_range_of(addr)
            if not r:
                continue
            print()
            print('### %s  (0x%x-0x%x, %d bytes)' % (n, r[0], r[1], r[1] - r[0]))
            strings, calls = a.scan_function(r[0], r[1])
            seen = set()
            for pc, tgt, s in strings:
                if s in seen:
                    continue
                seen.add(s)
                print('    0x%08x  0x%08x  %s' % (pc, tgt, s[:100]))
            if calls:
                cnt = collections.Counter(a.label(c) for _, c in calls)
                print('    -- llama a: %s' % ', '.join('%s x%d' % (k, v)
                      for k, v in cnt.most_common(12)))
        return

    ap.error('indica --find, --list-func, --strings-of o --callers')


if __name__ == '__main__':
    main()
