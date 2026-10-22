import re, sys

path = sys.argv[1]
needles = sys.argv[2:] or [b'<general', b'<settings', b'<?xml', b'sjunlockAll', b'{']
d = open(path, 'rb').read()
print('size', len(d))

LONG = re.compile(rb'[\x09\x0a\x0d\x20-\x7e]{200,}')

# print long printable blobs that look like markup or json
count = 0
for m in LONG.finditer(d):
    s = m.group()
    if b'<' in s[:50] or b'{' in s[:50] or b'[' in s[:50]:
        head = s[:120].decode('latin1')
        if re.search(r'<[a-zA-Z_/?!]|[\{\[]\s*["\}]', head):
            count += 1
            print('---', hex(m.start()), len(s))
            print(s[:3000].decode('latin1'))
            if count > 40:
                break
print('blobs', count)

for n in needles:
    idx = 0
    hits = 0
    while True:
        i = d.find(n, idx)
        if i < 0:
            break
        hits += 1
        lo = max(0, i - 80)
        hi = min(len(d), i + 400)
        print('=== needle', n, hex(i))
        print(repr(d[lo:hi])[:900])
        idx = i + 1
        if hits > 5:
            break
