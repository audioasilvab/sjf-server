"""Redirect libsonicjumpfever.so to your own server.

The production endpoint is stored as a plain NUL terminated string in .rodata:

    https://prod.server.sjf.hla.sega.co.uk:8443/SJF23        (49 chars)

This tool overwrites those bytes in place with your URL (padded with NUL).
The replacement must not be longer than the original, so the file size and
every ELF offset stay identical -> the patched .so can be dropped straight
back into the APK.

Usage
-----
    python _tools/patch_so.py check  lib/armeabi-v7a/libsonicjumpfever.so
    python _tools/patch_so.py patch  lib/armeabi-v7a/libsonicjumpfever.so  http://192.168.1.50:8080/SJF23
    
    python _tools/patch_so.py patch  lib/armeabi-v7a/libsonicjumpfever.so https://sjf-server.onrender.com/SJF23

`patch` writes <file>.patched unless you pass an explicit output path:

    python _tools/patch_so.py patch <so> <url> <out.so>
"""
import os
import shutil
import sys

ORIGINAL = b'https://prod.server.sjf.hla.sega.co.uk:8443/SJF23'

FALLBACKS = [
    b'https://prod.server.sjf.hla.sega.co.uk:8443/SJF23',
    b'https://prod.server.sjf.hla.sega.co.uk',
    b'prod.server.sjf.hla.sega.co.uk',
]


def find(haystack, needle):
    hits = []
    i = haystack.find(needle)
    while i >= 0:
        hits.append(i)
        i = haystack.find(needle, i + 1)
    return hits


def cmd_check(path):
    data = open(path, 'rb').read()
    for needle in FALLBACKS:
        hits = find(data, needle)
        if hits:
            print('%-6s %-52s %d hit(s) at %s' % (
                os.path.getsize(path), needle.decode(), len(hits),
                ', '.join(hex(h) for h in hits[:8])))
            return True
    print('%-6s no known server URL found' % os.path.getsize(path))
    return False


def cmd_patch(path, url, out=None):
    data = bytearray(open(path, 'rb').read())
    new = url.encode('ascii')
    if len(new) > len(ORIGINAL):
        sys.exit('URL too long: %d chars, max %d (%s)' %
                 (len(new), len(ORIGINAL), ORIGINAL.decode()))
    hits = find(bytes(data), ORIGINAL)
    if not hits:
        sys.exit('original URL not found in %s' % path)
    for h in hits:
        data[h:h + len(ORIGINAL)] = new + b'\x00' * (len(ORIGINAL) - len(new))
    out = out or (path + '.patched')
    with open(out, 'wb') as f:
        f.write(bytes(data))
    print('patched %d occurrence(s) -> %s' % (len(hits), out))
    print('  old: %s' % ORIGINAL.decode())
    print('  new: %s' % url)
    return out


def cmd_patch_all(root, url):
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            if f.endswith('.so'):
                p = os.path.join(dp, f)
                try:
                    cmd_patch(p, url)
                except SystemExit as e:
                    print('%s: %s' % (p, e))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    mode = sys.argv[1]
    if mode == 'check':
        for p in sys.argv[2:]:
            cmd_check(p)
    elif mode == 'patch':
        cmd_patch(sys.argv[2], sys.argv[3],
                  sys.argv[4] if len(sys.argv) > 4 else None)
    elif mode == 'patch-all':
        cmd_patch_all(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        sys.exit(1)
