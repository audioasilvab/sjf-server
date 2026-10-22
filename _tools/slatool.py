"""Parser for Hardlight .sla archives (magic '=O&D' / 0x3d4f2644).

Layout observed:
    u32  magic  "=O&D"
    u8   version
    u8   ??? (flags/entry count hint)
    repeat:
        varint  nameLen
        bytes   name
        varint  dataLen
        bytes   data
"""
import os
import sys


def read_varint(buf, off):
    """LEB128, 7 bits per byte, little endian."""
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
            raise ValueError('varint too long')


def parse(path):
    buf = open(path, 'rb').read()
    if buf[:4] != b'=O&D':
        raise ValueError('bad magic %r' % buf[:4])
    version = buf[4]
    flags = buf[5]
    off = 6
    entries = []
    errors = []
    while off < len(buf):
        start = off
        try:
            nlen, off = read_varint(buf, off)
        except Exception as e:
            errors.append((start, 'namelen: %s' % e))
            break
        if nlen == 0 or nlen > 512 or off + nlen > len(buf):
            errors.append((start, 'bad namelen %d' % nlen))
            break
        name = buf[off:off + nlen]
        off += nlen
        if not all(32 <= c < 127 for c in name):
            errors.append((start, 'bad name %r' % name))
            break
        try:
            dlen, off = read_varint(buf, off)
        except Exception as e:
            errors.append((start, 'datalen: %s' % e))
            break
        if off + dlen > len(buf):
            errors.append((start, 'truncated data for %s (%d)' % (name, dlen)))
            break
        data = buf[off:off + dlen]
        off += dlen
        entries.append((name.decode('ascii'), dlen, off - dlen, data))
    return version, flags, entries, errors


def main():
    path = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else None
    version, flags, entries, errors = parse(path)
    print('%s: version=%d flags=0x%02x entries=%d errors=%r' %
          (path, version, flags, len(entries), errors[:3]))
    total = 0
    for name, dlen, doff, data in entries:
        print('   %-32s %8d  @0x%06x' % (name, dlen, doff))
        total += dlen
    print('   accounted bytes:', total + sum(len(n) for n, _, _, _ in entries) + off_guess(entries, path))
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        for name, dlen, doff, data in entries:
            safe = name.replace('/', '_')
            with open(os.path.join(outdir, safe), 'wb') as f:
                f.write(data)
        print('extracted to', outdir)


def off_guess(entries, path):
    return 0


if __name__ == '__main__':
    main()
