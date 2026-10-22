"""Extrae la tabla campo -> tipo de las clases de red, leyendo el desensamblado.

Para cada funcion `...::deserialize(const sl::DOMObject*, bool)` localiza los
pares (carga de la clave con ADRP+ADD, siguiente llamada a ObjectSerializer::deserialize)
y deduce el tipo por el nombre manglado de esa llamada:

    ...EPKcRib     -> int          (R i b)
    ...EPKcRlb     -> long         (R l b)
    ...EPKcRbb     -> bool         (R b b)
    ...EPKcRNS_8DateTimeEb   -> DateTime
    ...EPKcRN5eastl12basic_string...  -> string
    ...EPKcRN5eastl6vectorI...        -> vector<T>

Uso:
    python _tools/schema.py <so> <patron-de-funcion> [...]
    python _tools/schema.py lib/arm64-v8a/libsonicjumpfever.so ConnectResponse SynchronizedPlayerState
"""
import re
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from a64func import A64, dec_add, dec_adrp, dec_bl, dec_ldr  # noqa: E402

TYPE_MAP = [
    (r'EPKcRib$', 'int'),
    (r'EPKcRlb$', 'long(int64)'),
    (r'EPKcRbb$', 'bool'),
    (r'EPKcRNS_8DateTimeEb$', 'DateTime'),
    (r'EPKcRN5eastl12basic_string', 'string'),
    (r'EPKcRN5eastl6vectorIb', 'vector<bool>'),
    (r'EPKcRN5eastl6vectorINS_8DateTime', 'vector<DateTime>'),
    (r'EPKcRi', 'int'),
    (r'EPKcRl', 'long(int64)'),
    (r'EPKcRb', 'bool'),
]


def type_of(sym):
    for pat, name in TYPE_MAP:
        if re.search(pat, sym):
            return name
    if 'deserialize' in sym:
        m = re.search(r'deserialize.*?EPKc(.+)$', sym)
        return 'OTRO:' + (m.group(1) if m else sym[-30:])
    return None


def fields_for(a, start, end):
    buf = a.el.buf
    page = {}
    pending_key = None
    out = []
    for pc in range(start, end - 4, 4):
        insn = struct.unpack_from('<I', buf, pc)[0]
        d = dec_adrp(insn, pc)
        if d:
            page[d[0]] = (d[1], pc)
            continue
        ad = dec_add(insn)
        if ad:
            rd, rn, imm = ad
            if rn in page and pc - page[rn][1] <= 24:
                s = a.read_string(page[rn][0] + imm)
                if s and rd == 1:          # x1 = nombre del campo
                    pending_key = (pc, s)
            continue
        c = dec_bl(insn, pc)
        if c is not None and pending_key:
            name = a.label(c)
            if 'ObjectSerializer' in name and 'deserialize' in name:
                t = type_of(name)
                if t:
                    # el flag `required` suele estar en x3 justo antes
                    req = False
                    for back in range(pc - 8, pc, 4):
                        b = struct.unpack_from('<I', buf, back)[0]
                        if (b & 0xFFE0001F) == 0x52800003 and ((b >> 5) & 0xFFFF) == 1:
                            req = True
                    out.append((pending_key[1], t, req))
                pending_key = None
    return out


def main():
    so = sys.argv[1]
    a = A64(so)
    for pat in sys.argv[2:]:
        print('=' * 70)
        print('## %s' % pat)
        shown = set()
        for addr, name in a.named:
            if not re.search(pat, name) or 'deserialize' not in name or addr in shown:
                continue
            r = a.func_range_of(addr)
            if not r:
                continue
            shown.add(addr)
            fields = fields_for(a, r[0], r[1])
            if not fields:
                continue
            print('### %s' % name)
            for k, t, req in fields:
                print('    %-26s %-14s %s' % (k, t, 'OBLIGATORIO' if req else ''))


if __name__ == '__main__':
    main()
