"""Referencias cruzadas exactas usando las relocaciones RELA del binario ARM64.

En AArch64 las instrucciones ADRP/ADD llevan relocaciones R_AARCH64_ADR_PREL_PG_HI21
(275) y R_AARCH64_ADD_ABS_LO12_NC (277) cuyo `addend` es la DIRECCION ABSOLUTA
del destino. Eso da, sin desensamblador, un mapa exacto de
"instruccion de .text -> objeto/cadena referenciado".

Uso:
    python _tools/relaxref.py <so-arm64> <cadena>
    python _tools/relaxref.py <so-arm64> --stats
"""
import argparse
import collections
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from elf import Elf  # noqa: E402

R_AARCH64_ADR_PREL_PG_HI21 = 275
R_AARCH64_ADD_ABS_LO12_NC = 277
R_AARCH64_ADR_GOT_PAGE = 311
R_AARCH64_LD64_GOT_LO12_NC = 312
R_AARCH64_ABS64 = 257
R_AARCH64_RELATIVE = 1027

NAMES = {
    275: 'ADR_PREL_PG_HI21', 277: 'ADD_ABS_LO12_NC',
    311: 'ADR_GOT_PAGE', 312: 'LD64_GOT_LO12_NC',
    257: 'ABS64', 1027: 'RELATIVE', 1025: 'GLOB_DAT', 1026: 'JUMP_SLOT',
}


def load_relocs(el):
    out = []
    for secname in ('.rela.dyn', '.rela.plt'):
        sec = el.section(secname)
        if sec is None:
            continue
        n = sec['size'] // sec['entsize']
        for i in range(n):
            off, info, addend = struct.unpack_from(
                '<QQq', el.buf, sec['offset'] + i * sec['entsize'])
            out.append({
                'offset': off, 'type': info & 0xFFFFFFFF,
                'sym': info >> 32, 'addend': addend, 'sec': secname,
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('needle', nargs='?')
    ap.add_argument('--stats', action='store_true')
    ap.add_argument('--limit', type=int, default=25)
    args = ap.parse_args()

    el = Elf(args.so)
    relocs = load_relocs(el)

    if args.stats:
        c = collections.Counter((r['type'], r['sec']) for r in relocs)
        for (t, s), n in c.most_common():
            print('  %-22s %-12s %6d' % (NAMES.get(t, hex(t)), s, n))
        return

    funcs = []
    for s in el.functions():
        funcs.append((s['value'], s['value'] + max(s['size'], 4), s['name']))
    funcs.sort()

    def owner(va):
        prev = None
        for a, b, n in funcs:
            if a <= va < b:
                return n, 'dentro'
            if a > va:
                break
            prev = (n, b)
        if prev:
            return prev[0], '+0x%x' % (va - prev[1])
        return None, None

    if not args.needle:
        ap.error('falta la cadena')

    offs = []
    i = el.buf.find(args.needle.encode())
    while i >= 0:
        offs.append(i)
        i = el.buf.find(args.needle.encode(), i + 1)
    if not offs:
        print('no encontrado:', args.needle)

    for foff in offs[:8]:
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
        got = [r for r in relocs if r['addend'] == va]
        if not got:
            print('    sin relocaciones con ese addend')
        for r in got[:args.limit]:
            name, how = owner(r['offset'])
            print('    %-20s @0x%08x  ->  [%s %s]' %
                  (NAMES.get(r['type'], hex(r['type'])), r['offset'],
                   name or '???', how or ''))


if __name__ == '__main__':
    main()
