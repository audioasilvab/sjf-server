import re, os, sys

URL_RE = re.compile(rb'(?:https?://|wss?://)[\x21-\x7e]{4,200}')
STR_RE = re.compile(rb'[\x20-\x7e]{5,}')

def clean(b):
    s = b.decode('latin1')
    return re.split(r'["\'<>,;)\\\s]', s)[0]

def urls(path):
    try:
        d = open(path, 'rb').read()
    except Exception:
        return []
    out = set()
    for m in URL_RE.finditer(d):
        out.add(clean(m.group()))
    return sorted(out)

def main(roots, pattern=None):
    rx = re.compile(pattern, re.I) if pattern else None
    for root in roots:
        if os.path.isfile(root):
            files = [root]
        else:
            files = []
            for dp, dn, fn in os.walk(root):
                for f in fn:
                    files.append(os.path.join(dp, f))
        for f in files:
            u = urls(f)
            if u:
                print('=' * 12, f, len(u))
                for s in u:
                    print('   ', s[:220])
            if rx:
                try:
                    d = open(f, 'rb').read()
                except Exception:
                    continue
                hits = set()
                for m in STR_RE.finditer(d):
                    s = m.group().decode('latin1')
                    if rx.search(s):
                        hits.add(s.strip()[:200])
                if hits:
                    print('---- pattern hits:', f, len(hits))
                    for s in sorted(hits)[:300]:
                        print('   ', s)

if __name__ == '__main__':
    roots = sys.argv[1:] or ['.']
    main(roots)
