import re, sys, os

def dump(path, out, minlen=4):
    d = open(path, 'rb').read()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w', encoding='utf-8', errors='replace') as f:
        for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, d):
            f.write('%08x\t%s\n' % (m.start(), m.group().decode('latin1')))
    print('wrote', out, os.path.getsize(out))

if __name__ == '__main__':
    dump(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 4)
