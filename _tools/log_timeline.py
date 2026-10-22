"""Analiza sjf-server/logs/requests.log: linea temporal por cliente.

Uso:
    python _tools/log_timeline.py [log] [ip]
Si se indica una IP, solo se muestran sus bloques.
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'sjf-server/logs/requests.log'
only_ip = sys.argv[2] if len(sys.argv) > 2 else None
t = open(path, encoding='utf-8', errors='replace').read()
blocks = re.split(r'(?=\[\d{4}-\d\d-\d\dT)', t)

print('%-14s %-17s %-16s %s' % ('hora', 'cliente', 'evento', 'detalle'))
print('-' * 82)
for b in blocks:
    m = re.match(r'\[(\S+?)Z\]', b)
    if not m:
        continue
    ts = m.group(1)[11:]
    c = re.search(r'cliente: ([\d.]+)', b)
    ip = c.group(1) if c else '?'
    if only_ip and ip != only_ip:
        continue
    if 'POST /SJF23/' in b:
        ruta = re.search(r'POST /SJF23/(\w+)\.json', b)
        if ruta and ruta.group(1) in ('Handshake', 'Connect', 'GetSettings', 'GetProfile'):
            print('%-14s %-17s %-16s' % (ts, ip, '-> ' + ruta.group(1)))
    r = re.search(r'-> respuesta Connect[^\n]*', b)
    if r:
        m2 = re.search(r'"cohortId":("?[^,"}]*"?)', r.group(0))
        print('%-14s %-17s %-16s cohortId=%s' % (ts, ip, 'respuesta Connect',
                                                 m2.group(1) if m2 else '?'))
    g = re.search(r'-> respuesta GetSettings[^\n]*', b)
    if g:
        m3 = re.search(r'"currentZone":"([a-z_]+)"', g.group(0))
        m4 = re.search(r'"nextZone":"([a-z_]+)"', g.group(0))
        print('%-14s %-17s %-16s currentZone=%s nextZone=%s' %
              (ts, ip, 'respuesta GetSettings', m3.group(1) if m3 else '?',
               m4.group(1) if m4 else '?'))

