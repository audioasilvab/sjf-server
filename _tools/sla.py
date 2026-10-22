"""Read / write Hardlight .sla archives.

Format (reverse engineered from Sonic Jump Fever 1.6.1 assets):

    u32  magic   "=O&D"             (0x3D4F2644)
    u8   version (4)
    u8   flags
    repeat until EOF:
        varint nameLen
        bytes  name
        varint dataLen
        bytes  data

varint = LEB128, 7 bits per byte, little endian.

CLI
---
    python _tools/sla.py list    <archive.sla>
    python _tools/sla.py extract <archive.sla> <outdir>
    python _tools/sla.py build   <outdir> <archive.sla> [version] [flags]
    python _tools/sla.py replace <archive.sla> <name> <file> [out.sla]
"""
import os
import sys


MAGIC = b'=O&D'


def read_varint(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 63:
            raise ValueError('varint too long at 0x%x' % off)


def write_varint(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def parse(path):
    buf = open(path, 'rb').read()
    return parse_bytes(buf, path)


def parse_bytes(buf, label='<bytes>'):
    if buf[:4] != MAGIC:
        raise ValueError('%s: bad magic %r' % (label, buf[:4]))
    version = buf[4]
    flags = buf[5]
    off = 6
    entries = []
    while off < len(buf):
        start = off
        nlen, off = read_varint(buf, off)
        if nlen == 0 or nlen > 512 or off + nlen > len(buf):
            raise ValueError('%s: bad name length %d at 0x%x' % (label, nlen, start))
        name = buf[off:off + nlen].decode('ascii')
        off += nlen
        dlen, off = read_varint(buf, off)
        if off + dlen > len(buf):
            raise ValueError('%s: truncated data for %s' % (label, name))
        entries.append((name, buf[off:off + dlen]))
        off += dlen
    return version, flags, entries


def build(entries, version=4, flags=0):
    out = bytearray(MAGIC)
    out.append(version)
    out.append(flags)
    for name, data in entries:
        nb = name.encode('ascii')
        out += write_varint(len(nb))
        out += nb
        out += write_varint(len(data))
        out += data
    return bytes(out)


def cmd_list(path):
    version, flags, entries = parse(path)
    print('%s: version=%d flags=0x%02x entries=%d' % (path, version, flags, len(entries)))
    for name, data in entries:
        print('   %-36s %9d' % (name, len(data)))


def cmd_extract(path, outdir):
    version, flags, entries = parse(path)
    os.makedirs(outdir, exist_ok=True)
    for name, data in entries:
        safe = name.replace('/', '_')
        with open(os.path.join(outdir, safe), 'wb') as f:
            f.write(data)
        print('   %-36s %9d' % (name, len(data)))
    print('-> %s (%d files)' % (outdir, len(entries)))


def cmd_build(indir, outpath, version=4, flags=0):
    entries = []
    for name in sorted(os.listdir(indir)):
        p = os.path.join(indir, name)
        if os.path.isfile(p):
            entries.append((name, open(p, 'rb').read()))
    data = build(entries, version, flags)
    with open(outpath, 'wb') as f:
        f.write(data)
    print('wrote %s (%d bytes, %d entries)' % (outpath, len(data), len(entries)))


def cmd_replace(path, name, src, outpath=None):
    version, flags, entries = parse(path)
    payload = open(src, 'rb').read()
    found = False
    new = []
    for n, d in entries:
        if n == name:
            new.append((n, payload))
            found = True
            print('replaced %s: %d -> %d bytes' % (n, len(d), len(payload)))
        else:
            new.append((n, d))
    if not found:
        new.append((name, payload))
        print('appended %s (%d bytes)' % (name, len(payload)))
    with open(outpath or path, 'wb') as f:
        f.write(build(new, version, flags))
    print('wrote', outpath or path)


USAGE = __doc__

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'list':
        cmd_list(sys.argv[2])
    elif cmd == 'extract':
        cmd_extract(sys.argv[2], sys.argv[3])
    elif cmd == 'build':
        cmd_build(sys.argv[2], sys.argv[3],
                  int(sys.argv[4]) if len(sys.argv) > 4 else 4,
                  int(sys.argv[5]) if len(sys.argv) > 5 else 0)
    elif cmd == 'replace':
        cmd_replace(sys.argv[2], sys.argv[3], sys.argv[4],
                    sys.argv[5] if len(sys.argv) > 5 else None)
    else:
        print(USAGE)
        sys.exit(1)
