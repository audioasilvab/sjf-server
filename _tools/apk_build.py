"""Parchea y firma el APK de Sonic Jump Fever 1.6.1.

Que hace
--------
1. Sustituye la URL del servidor dentro de lib/*/libsonicjumpfever.so
   (misma longitud -> el .so conserva todos sus offsets).
2. Opcionalmente sube targetSdkVersion (Android 15+ no deja instalar
   apps con targetSdk < 24).
3. Reconstruye el APK sin la firma v1 antigua.
4. Crea un keystore (si no existe) y firma con jarsigner.

Uso
---
    python _tools/apk_build.py ips
    python _tools/apk_build.py patch --url http://192.168.1.50:8443/SJF23
    python _tools/apk_build.py patch --url http://192.168.1.50:8443/SJF23 --target-sdk 24

Por defecto lee  "sonic-jump-fever-1-6-1 (1).apk"  y escribe
"sonic-jump-fever-1-6-1-PARCHEADO.apk" en la raiz del proyecto.
"""
import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import axml  # noqa: E402

ORIGINAL_URL = b'https://prod.server.sjf.hla.sega.co.uk:8443/SJF23'
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_APK = os.path.join(ROOT, 'sonic-jump-fever-1-6-1 (1).apk')
SIGN_PREFIXES = ('META-INF/MANIFEST.MF',)
SIGN_SUFFIXES = ('.SF', '.RSA', '.DSA', '.EC')


def local_ips():
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.') and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def patch_so(data, url):
    new = url.encode('ascii')
    if len(new) > len(ORIGINAL_URL):
        raise SystemExit('URL demasiado larga: %d caracteres, maximo %d'
                         % (len(new), len(ORIGINAL_URL)))
    if data.find(ORIGINAL_URL) < 0:
        raise SystemExit('no encuentro la URL original en el .so')
    count = data.count(ORIGINAL_URL)
    return data.replace(ORIGINAL_URL, new + b'\x00' * (len(ORIGINAL_URL) - len(new))), count


def patch_manifest(data, target_sdk):
    buf = bytearray(data)
    off, old = axml.find_uses_sdk_target_offset(buf)
    if off is None:
        raise SystemExit('no encuentro targetSdkVersion en AndroidManifest.xml')
    buf[off:off + 4] = target_sdk.to_bytes(4, 'little')
    print('   targetSdkVersion: %d -> %d (offset 0x%x)' % (old, target_sdk, off))
    return bytes(buf)


def is_signature(name):
    if name in SIGN_PREFIXES:
        return True
    if name.startswith('META-INF/') and name.upper().endswith(SIGN_SUFFIXES):
        return True
    return False


def rebuild(apk_in, apk_out, url, target_sdk=None):
    print('leyendo %s' % apk_in)
    zin = zipfile.ZipFile(apk_in)
    so_patched = {}
    total = 0
    for info in zin.infolist():
        if info.filename.startswith('lib/') and info.filename.endswith('libsonicjumpfever.so'):
            raw = zin.read(info.filename)
            patched, n = patch_so(raw, url)
            assert len(patched) == len(raw), 'el parche cambio el tamano del .so'
            so_patched[info.filename] = patched
            print('   %-42s URL x%d -> %s' % (info.filename, n, url))
            total += 1
    if total == 0:
        raise SystemExit('no hay libsonicjumpfever.so en el APK')

    manifest = None
    if target_sdk:
        manifest = patch_manifest(zin.read('AndroidManifest.xml'), target_sdk)

    os.makedirs(os.path.dirname(os.path.abspath(apk_out)), exist_ok=True)
    with zipfile.ZipFile(apk_out, 'w') as zout:
        for info in zin.infolist():
            if is_signature(info.filename):
                continue
            if info.filename in so_patched:
                data = so_patched[info.filename]
            elif info.filename == 'AndroidManifest.xml' and manifest is not None:
                data = manifest
            else:
                data = zin.read(info.filename)
            new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            new_info.compress_type = info.compress_type
            new_info.external_attr = info.external_attr
            new_info.internal_attr = info.internal_attr
            new_info.create_system = info.create_system
            zout.writestr(new_info, data)
    zin.close()
    print('APK sin firmar -> %s (%d bytes)' % (apk_out, os.path.getsize(apk_out)))
    return apk_out


def ensure_keystore(path, alias='sjf'):
    if os.path.exists(path):
        return
    print('creando keystore %s' % path)
    cmd = ['keytool', '-genkeypair', '-v', '-keystore', path,
           '-alias', alias, '-keyalg', 'RSA', '-keysize', '2048',
           '-validity', '10000', '-storepass', 'android', '-keypass', 'android',
           '-dname', 'CN=Sonic Jump Fever, OU=Revival, O=Home, L=Local, ST=Local, C=ES']
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def sign(apk, keystore, alias='sjf'):
    print('firmando (v1) ...')
    cmd = ['jarsigner', '-keystore', keystore, '-storepass', 'android',
           '-keypass', 'android', '-sigalg', 'SHA256withRSA',
           '-digestalg', 'SHA-256', apk, alias]
    subprocess.run(cmd, check=True)
    subprocess.run(['jarsigner', '-verify', '-verbose', '-certs', apk],
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print('firma aplicada.')


def verify(apk, original=None):
    """Comprobacion exhaustiva del APK parcheado."""
    print('verificando %s' % apk)
    ok = True

    def check(cond, label, extra=''):
        nonlocal ok
        print('  %s %s%s' % ('OK  ' if cond else 'FALLA', label,
                             ('  ' + extra) if extra else ''))
        if not cond:
            ok = False

    z = zipfile.ZipFile(apk)
    bad = z.testzip()
    check(bad is None, 'integridad del ZIP', bad or '')

    names = z.namelist()
    sig = [n for n in names if n.startswith('META-INF/') and n.upper().endswith(('.SF', '.RSA', '.DSA', '.EC'))]
    check(len(sig) >= 2, 'firma v1 presente', ', '.join(sig))

    # manifest
    man = z.read('AndroidManifest.xml')
    off, target = axml.find_uses_sdk_target_offset(man)
    check(target is not None, 'targetSdkVersion legible', str(target))
    check(target >= 23, 'targetSdkVersion >= 23 (Android 14+)', str(target))

    # .so de cada ABI
    abis = [n for n in names if n.startswith('lib/') and n.endswith('libsonicjumpfever.so')]
    check(len(abis) == 3, 'las 3 ABIs presentes', str(len(abis)))
    for n in abis:
        data = z.read(n)
        check(data[:4] == b'\x7fELF', '%s es un ELF valido' % n)
        arch = {0x28: 'arm', 0xB7: 'aarch64'}.get(data[18], hex(data[18]))
        has_old = ORIGINAL_URL in data
        i = data.find(b'http://')
        # buscar la URL nueva: cualquier http:// seguido de host:puerto/SJF23
        m = re.search(rb'http://[0-9A-Za-z\.\-]+:\d+/SJF23', data)
        check(not has_old, '%s sin la URL original' % n)
        check(m is not None, '%s redirigido' % n, m.group().decode() if m else '')
        check(arch in ('arm', 'aarch64'), '%s arquitectura' % n, arch)

    # assets clave
    for a in ('assets/settings.sla', 'assets/hd-jungle_zone.sla', 'classes.dex',
              'resources.arsc'):
        check(a in names, 'contiene %s' % a)

    if original and os.path.exists(original):
        zo = zipfile.ZipFile(original)
        same = len(zo.namelist())
        check(len(names) >= same - 3, 'numero de entradas similar al original',
              '%d vs %d' % (len(names), same))
        for a in ('assets/settings.sla', 'classes.dex', 'resources.arsc'):
            check(z.read(a) == zo.read(a), '%s identico al original' % a)

    proc = subprocess.run(['jarsigner', '-verify', apk],
                          capture_output=True, text=True, errors='replace')
    out = (proc.stdout or '') + (proc.stderr or '')
    check('jar verified' in out.lower(), 'jarsigner -verify', out.strip().splitlines()[-1] if out.strip() else '')
    return ok


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('ips', help='muestra las IPs locales para usar en la URL')

    v = sub.add_parser('verify', help='comprueba un APK parcheado')
    v.add_argument('apk')
    v.add_argument('--original', default=DEFAULT_APK)

    p = sub.add_parser('patch', help='parchea y firma el APK')
    p.add_argument('--apk', default=DEFAULT_APK)
    p.add_argument('--out',
                   default=os.path.join(ROOT, 'sonic-jump-fever-1-6-1-PARCHEADO.apk'))
    p.add_argument('--url', required=True,
                   help='p.ej. http://192.168.1.50:8443/SJF23')
    p.add_argument('--target-sdk', type=int, default=None,
                   help='sube targetSdkVersion (usa 24 si tu movil es Android 15+)')
    p.add_argument('--keystore', default=os.path.join(HERE, 'sjf-debug.keystore'))
    p.add_argument('--alias', default='sjf')

    args = ap.parse_args()

    if args.cmd == 'ips':
        print('IPs locales (usa la de tu Wi-Fi):')
        for ip in local_ips():
            print('   http://%s:8443/SJF23' % ip)
        return

    if args.cmd == 'verify':
        sys.exit(0 if verify(args.apk, args.original) else 1)

    if not os.path.exists(args.apk):
        raise SystemExit('no existe el APK: %s\n(pasa --apk <ruta>)' % args.apk)

    rebuild(args.apk, args.out, args.url, args.target_sdk)
    ensure_keystore(args.keystore, args.alias)
    sign(args.out, args.keystore, args.alias)
    print()
    print('LISTO: %s' % args.out)
    print('Instala con:  adb install -r "%s"' % args.out)
    print('Si ya tenias el juego instalado, desinstalalo antes (firma distinta).')


if __name__ == '__main__':
    main()
