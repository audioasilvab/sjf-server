import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from slatool import parse

TEXT_EXT = ('.json', '.xml', '.set', '.loc', '.ani', '.txt', '.csv', '.ini', '.bcd')
TEXT_MAGIC = (b'<', b'{', b'[', b'#', b';')

root = sys.argv[1] if len(sys.argv) > 1 else 'assets'
outroot = sys.argv[2] if len(sys.argv) > 2 else '_extracted'
os.makedirs(outroot, exist_ok=True)

for f in sorted(os.listdir(root)):
    if not f.endswith('.sla'):
        continue
    p = os.path.join(root, f)
    try:
        version, flags, entries, errors = parse(p)
    except Exception as e:
        print('FAIL', f, e)
        continue
    base = os.path.splitext(f)[0]
    summary = []
    for name, dlen, doff, data in entries:
        is_text = name.lower().endswith(TEXT_EXT) or (data[:1] in TEXT_MAGIC)
        if is_text:
            d = os.path.join(outroot, base)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, name.replace('/', '_')), 'wb') as fh:
                fh.write(data)
            summary.append('%s(%d)' % (name, dlen))
    print('%-28s v%d entries=%d text=%s %s' % (f, version, len(entries), len(summary), ' '.join(summary)))
