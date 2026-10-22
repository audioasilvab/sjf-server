"""Inspecciona / reconstruye / firma el APK de Sonic Jump Fever.

Uso:
    python _tools/apk.py info  <app.apk>
"""
import os
import struct
import sys
import zipfile

APK_SIG_MAGIC = b'APK Sig Block 42'


def find_sig_block(data):
    """Devuelve (offset_inicio, tamano) del APK Signing Block o None."""
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0:
        return None
    cd_offset = struct.unpack_from('<I', data, eocd + 16)[0]
    magic_at = cd_offset - 16
    if magic_at < 0 or data[magic_at:magic_at + 16] != APK_SIG_MAGIC:
        return None
    size_at_end = struct.unpack_from('<Q', data, magic_at - 8)[0]
    start = cd_offset - size_at_end - 8
    return start, cd_offset - start


def info(path):
    data = open(path, 'rb').read()
    print('fichero : %s (%d bytes)' % (path, len(data)))
    zf = zipfile.ZipFile(path)
    infos = zf.infolist()

    sig = find_sig_block(data)
    print('firma   : APK Signing Block (v2/v3): %s' %
          ('SI, %d bytes en 0x%x' % (sig[1], sig[0]) if sig else 'NO'))
    names = [i.filename for i in infos]
    v1 = sorted(n for n in names if n.upper().startswith('META-INF/') and
                n.upper().endswith(('.RSA', '.DSA', '.EC', '.SF')))
    print('firma   : v1 (JAR): %s' % (', '.join(v1) if v1 else 'NO'))
    print('entradas: %d' % len(infos))
    print()
    print('%-58s %10s %9s %8s %9s' % ('nombre', 'tam', 'comprim', 'metodo', 'offset'))
    print('-' * 100)

    # offset real de los datos de cada entrada (leyendo la cabecera local)
    order = sorted(infos, key=lambda i: i.header_offset)
    problems = []
    for i in order:
        off = i.header_offset
        if data[off:off + 4] != b'PK\x03\x04':
            problems.append('%s: cabecera local invalida' % i.filename)
            continue
        nlen, elen = struct.unpack_from('<HH', data, off + 26)
        data_off = off + 30 + nlen + elen
        method = 'store' if i.compress_type == 0 else 'deflate'
        if i.filename.startswith('lib/') or i.filename == 'resources.arsc':
            align = data_off % 4096
            flag = '' if align == 0 else '  <-- NO alineado a 4096 (%d)' % align
            print('%-58s %10d %9d %8s %9d%s' %
                  (i.filename, i.file_size, i.compress_size, method, data_off, flag))
        else:
            print('%-58s %10d %9d %8s %9d' %
                  (i.filename, i.file_size, i.compress_size, method, data_off))
        if i.compress_type == 0 and i.compress_size != i.file_size:
            problems.append('%s: store con tamanos distintos' % i.filename)

    print()
    if problems:
        print('AVISOS:')
        for p in problems:
            print('  -', p)

    # comprobacion del .dex y del .so objetivo
    so = [i for i in infos if i.filename.endswith('libsonicjumpfever.so')]
    print()
    print('libsonicjumpfever.so: %d variantes' % len(so))
    for i in so:
        print('   %-42s %9d comprimido=%s' %
              (i.filename, i.file_size, 'store' if i.compress_type == 0 else 'deflate'))


if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] != 'info':
        print(__doc__)
        sys.exit(1)
    info(sys.argv[2])
