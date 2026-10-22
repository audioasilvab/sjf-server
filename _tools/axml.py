"""Parser de AndroidManifest.xml (AXML binario) con acceso a offsets.

Uso como libreria:
    buf = bytearray(open('AndroidManifest.xml','rb').read())
    for el in parse_elements(buf):
        print(el['name'], el['attrs'])
    off = find_int_attr(buf, 'uses-sdk', 'targetSdkVersion')  # offset del int32

Uso como CLI:
    python _tools/axml.py AndroidManifest.xml
"""
import struct
import sys

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

# android.R.attr.* ids que nos interesan
ATTR_IDS = {
    0x0101021B: 'versionCode',
    0x0101021C: 'versionName',
    0x0101020C: 'minSdkVersion',
    0x01010270: 'minSdkVersion',
    0x01010271: 'targetSdkVersion',
    0x01010003: 'name',
    0x01010000: 'theme',
    0x01010001: 'label',
    0x01010002: 'icon',
    0x01010010: 'screenOrientation',
    0x01010018: 'configChanges',
    0x0101001D: 'authorities',
    0x0101001E: 'grantUriPermissions',
    0x0101020E: 'hardwareAccelerated',
    0x010102B6: 'allowBackup',
    0x010102E0: 'extractNativeLibs',
    0x010104EB: 'usesCleartextTraffic',
    0x01010569: 'compileSdkVersion',
    0x01010572: 'compileSdkVersionCodename',
    0x01010573: 'appComponentFactory',
    0x0101056F: 'requestLegacyExternalStorage',
}

TYPE_NAMES = {
    0x00: 'null', 0x01: 'ref', 0x02: 'attr', 0x03: 'string',
    0x04: 'float', 0x05: 'dimension', 0x06: 'fraction',
    0x07: 'dynamic_ref', 0x08: 'int_dec', 0x10: 'int_hex',
    0x11: 'int_bool', 0x12: 'color',
}


def _parse_string_pool(buf, off):
    (_type, header_size, size) = struct.unpack_from('<HHI', buf, off)
    (string_count, style_count, flags, strings_start, styles_start) = \
        struct.unpack_from('<IIIII', buf, off + 8)
    utf8 = bool(flags & (1 << 8))
    offsets = struct.unpack_from('<%dI' % string_count, buf, off + 28)
    base = off + strings_start
    strings = []
    for o in offsets:
        p = base + o
        if utf8:
            n = buf[p]
            p += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | buf[p]
                p += 1
            m = buf[p]
            p += 1
            if m & 0x80:
                m = ((m & 0x7F) << 8) | buf[p]
                p += 1
            strings.append(buf[p:p + m].decode('utf-8', 'replace'))
        else:
            n = struct.unpack_from('<H', buf, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', buf, p)[0]
                p += 2
            strings.append(buf[p:p + n * 2].decode('utf-16-le', 'replace'))
    return strings, off + size


def parse_elements(buf):
    """Devuelve la lista de elementos (plana) con sus atributos y offsets."""
    magic, size = struct.unpack_from('<HI', buf, 0)
    assert magic == RES_XML, 'no es AXML: %r' % bytes(buf[:4])
    strings = []
    resmap = {}
    off = 8
    out = []
    while off < len(buf):
        _type, header_size, chunk_size = struct.unpack_from('<HHI', buf, off)
        if chunk_size == 0:
            break
        if _type == RES_STRING_POOL:
            strings, _ = _parse_string_pool(buf, off)
        elif _type == RES_XML_RESOURCE_MAP:
            n = (chunk_size - header_size) // 4
            ids = struct.unpack_from('<%dI' % n, buf, off + header_size)
            for i, rid in enumerate(ids):
                resmap[i] = rid
        elif _type == RES_XML_START_ELEMENT:
            ns_i, name_i = struct.unpack_from('<ii', buf, off + header_size)
            attr_start, attr_size, attr_count = struct.unpack_from(
                '<HHH', buf, off + header_size + 8)
            attrs = []
            ap = off + header_size + attr_start
            for _ in range(attr_count):
                a_ns, a_name, a_raw = struct.unpack_from('<iii', buf, ap)
                a_type = buf[ap + 15]
                a_data = struct.unpack_from('<I', buf, ap + 16)[0]
                rid = resmap.get(a_name)
                label = ATTR_IDS.get(rid)
                if label is None and 0 <= a_raw < len(strings) and strings[a_raw]:
                    label = strings[a_raw]
                attrs.append({
                    'ns': a_ns, 'name_idx': a_name, 'resource_id': rid,
                    'label': label, 'raw': a_raw, 'type': a_type,
                    'data': a_data, 'data_offset': ap + 16,
                    'value': _resolve(a_type, a_data, a_raw, strings),
                })
                ap += attr_size
            out.append({'name': strings[name_i], 'attrs': attrs,
                        'offset': off, 'header_size': header_size})
        off += chunk_size
    return out


def _resolve(a_type, a_data, a_raw, strings):
    if a_type == 0x03:
        return strings[a_raw] if 0 <= a_raw < len(strings) else None
    if a_type == 0x01:
        return 'ref(0x%08x)' % a_data
    if a_type == 0x02:
        return 'attr(0x%08x)' % a_data
    if a_type == 0x11:
        return bool(a_data)
    return a_data


def find_element(elements, name):
    for el in elements:
        if el['name'] == name:
            return el
    return None


INT_TYPES = (0x10, 0x11, 0x08)


def find_uses_sdk_target_offset(buf):
    """Devuelve (offset_int32, valor_actual) de targetSdkVersion.

    Los atributos numericos del manifiesto no guardan el nombre en el pool de
    cadenas (rawValue = -1), asi que dentro de <uses-sdk> se localizan por
    posicion: el ultimo atributo entero es targetSdkVersion.
    """
    for el in parse_elements(buf):
        if el['name'] != 'uses-sdk':
            continue
        ints = [a for a in el['attrs'] if a['type'] in INT_TYPES]
        if not ints:
            continue
        a = ints[-1]
        return a['data_offset'], a['data']
    return None, None


def find_attr_offset(buf, element, attr_label):
    for el in parse_elements(buf):
        if el['name'] != element:
            continue
        for a in el['attrs']:
            if a['label'] == attr_label or a['resource_id'] == attr_label:
                return a['data_offset']
    return None


def render(buf):
    lines = []
    depth = 0
    for el in parse_elements(buf):
        pass
    # render sencillo: reutilizamos parse_elements no da eventos de cierre,
    # asi que mostramos una lista plana con indentacion por profundidad real.
    return '\n'.join('%s<%s %s>' % (
        ' ' * (2 * i), el['name'],
        ' '.join('%s=%s' % (a['label'], a['value']) for a in el['attrs']))
        for i, el in enumerate(parse_elements(buf)))


if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    print(render(data))
