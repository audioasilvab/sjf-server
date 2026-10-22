"""Referencias cruzadas sobre libsonicjumpfever.so sin desensamblador.

Como funciona
-------------
El compilador agrupa las cadenas y las referencia con una BASE alineada a
pagina de 256 bytes mas un desplazamiento pequeno. Es decir, en los "literal
pools" de .text aparece la direccion de la pagina (p.ej. 0x2a7400) y el codigo
suma/resta unos pocos bytes para llegar a la cadena concreta.

Por eso:
  1. se recogen todos los valores de 4 bytes que apuntan a .rodata desde
     .text / .data.rel.ro -> esos son los "anclajes";
  2. para una cadena dada se buscan los anclajes dentro de +-0x1000 bytes;
  3. la funcion que usa la cadena es la que contiene (o precede a) la
     posicion del literal pool.

Uso:
    python _tools/xref.py <so> <cadena>
    python _tools/xref.py <so> <cadena> --limit 20
    python _tools/xref.py <so> --grep sj
    python _tools/xref.py <so> --func DebugSettings
"""
import argparse
import collections
import re
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from elf import Elf  # noqa: E402


class Xref(object):
    def __init__(self, path):
        self.el = Elf(path)
        self.funcs = self._funcs()
        self.anchors = self._anchors()

    def _funcs(self):
        out = []
        for s in self.el.functions():
            v = s['value'] & ~1
            out.append((v, v + max(s['size'], 2), s['name']))
        out.sort()
        return out

    def owner(self, va):
        prev = None
        for lo, hi, name in self.funcs:
            if lo <= va < hi:
                return name, 0
            if lo > va:
                break
            prev = (name, hi)
        if prev:
            return prev[0], va - prev[1]
        return None, None

    def section_of_file(self, off):
        for s in self.el.sections:
            if s['size'] and s['offset'] <= off < s['offset'] + s['size']:
                return s['name']
        return None

    def _anchors(self):
        ro = self.el.section('.rodata')
        lo, hi = ro['addr'], ro['addr'] + ro['size']
        text = self.el.section('.text')
        tlo, thi = text['addr'], text['addr'] + text['size']
        anchors = collections.defaultdict(list)
        buf = self.el.buf
        for i in range(0, len(buf) - 4, 2):
            v = struct.unpack_from('<I', buf, i)[0]
            if not (lo <= v < hi):
                continue
            va = self.el.vaddr_of_file(i)
            if va is None:
                continue
            # solo nos interesan anclajes dentro de codigo o de .data.rel.ro
            if tlo <= va < thi or '.data.rel.ro' in (self.section_of_file(i) or ''):
                anchors[v].append(i)
        return anchors

    def string_at(self, foff):
        s = foff
        while s > 0 and 0x20 <= self.el.buf[s - 1] < 0x7f:
            s -= 1
        e = foff
        while e < len(self.el.buf) and 0x20 <= self.el.buf[e] < 0x7f:
            e += 1
        return self.el.buf[s:e].decode('latin1')

    def find_strings(self, needle):
        out = []
        i = self.el.buf.find(needle.encode())
        while i >= 0:
            out.append(i)
            i = self.el.buf.find(needle.encode(), i + 1)
        return out

    def xref(self, foff, window=0x1000):
        va = self.el.vaddr_of_file(foff)
        res = []
        for a, positions in self.anchors.items():
            d = a - va
            if abs(d) > window:
                continue
            for p in positions:
                pva = self.el.vaddr_of_file(p)
                name, slack = self.owner(pva)
                res.append({
                    'anchor': a, 'delta': d, 'pos': p, 'sec': self.section_of_file(p),
                    'func': name, 'slack': slack,
                })
        res.sort(key=lambda r: (abs(r['delta']), r['pos']))
        return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('needle', nargs='?')
    ap.add_argument('--grep')
    ap.add_argument('--func')
    ap.add_argument('--limit', type=int, default=15)
    ap.add_argument('--window', type=lambda x: int(x, 0), default=0x1000)
    args = ap.parse_args()

    x = Xref(args.so)

    if args.func:
        rx = re.compile(args.func, re.I)
        for lo, hi, name in x.funcs:
            if rx.search(name):
                print('  0x%08x-0x%08x  %s' % (lo, hi, name))
        return

    if args.grep:
        for m in re.finditer(rb'[\x20-\x7e]{4,}', x.el.buf):
            t = m.group().decode('latin1')
            if args.grep.lower() in t.lower():
                print('  0x%08x  %s' % (m.start(), t[:110]))
        return

    if not args.needle:
        ap.error('falta la cadena')

    offs = x.find_strings(args.needle)
    if not offs:
        print('no encontrado:', args.needle)
        return
    for foff in offs[:8]:
        print('=== "%s"  (fichero 0x%08x)' % (x.string_at(foff)[:90], foff))
        refs = x.xref(foff, args.window)
        if not refs:
            print('    sin anclajes en +-0x%x' % args.window)
        for r in refs[:args.limit]:
            print('    pool 0x%08x (%s)  ancla 0x%08x (%+d)  func %s%s' % (
                r['pos'], r['sec'], r['anchor'], r['delta'], r['func'] or '???',
                ('  +0x%x tras ella' % r['slack']) if r['slack'] else ''))


if __name__ == '__main__':
    main()
