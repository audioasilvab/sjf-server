"""Lector ELF minimo (32/64 bits, little endian) en Python puro.

Objetivo: poder mapear offset de fichero <-> direccion virtual y leer la tabla
de simbolos, para localizar que funcion usa cada cadena del binario.
"""
import struct


class Elf(object):
    def __init__(self, path):
        self.path = path
        self.buf = open(path, 'rb').read()
        b = self.buf
        assert b[:4] == b'\x7fELF', 'no es un ELF'
        self.is64 = b[4] == 2
        self.endian = '<' if b[5] == 1 else '>'
        e = self.endian
        if self.is64:
            (self.e_type, self.e_machine, _v, self.e_entry, self.e_phoff,
             self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
             self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from(e + 'HHIQQQIHHHHHH', b, 16)
        else:
            (self.e_type, self.e_machine, _v, self.e_entry, self.e_phoff,
             self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
             self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from(e + 'HHIIIIIHHHHHH', b, 16)
        self._read_segments()
        self._read_sections()

    # ------------------------------------------------------------------ base
    def _read_segments(self):
        e = self.endian
        self.segments = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, \
                    p_memsz, p_align = struct.unpack_from(e + 'IIQQQQQQ', self.buf, off)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, \
                    p_flags, p_align = struct.unpack_from(e + 'IIIIIIII', self.buf, off)
            self.segments.append({
                'type': p_type, 'flags': p_flags, 'offset': p_offset,
                'vaddr': p_vaddr, 'filesz': p_filesz, 'memsz': p_memsz,
                'align': p_align,
            })

    def _read_sections(self):
        e = self.endian
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.is64:
                f = struct.unpack_from(e + 'IIQQQQIIQQ', self.buf, off)
            else:
                f = struct.unpack_from(e + 'IIIIIIIIII', self.buf, off)
            raw.append(f)
        self.sections = []
        for f in raw:
            if self.is64:
                name, typ, flags, addr, offset, size, link, info, align, entsize = f
            else:
                name, typ, flags, addr, offset, size, link, info, align, entsize = f
            self.sections.append({
                'name_idx': name, 'type': typ, 'flags': flags, 'addr': addr,
                'offset': offset, 'size': size, 'link': link, 'info': info,
                'align': align, 'entsize': entsize,
            })
        shstr = self.sections[self.e_shstrndx]
        base = shstr['offset']
        for s in self.sections:
            end = self.buf.index(b'\x00', base + s['name_idx'])
            s['name'] = self.buf[base + s['name_idx']:end].decode('latin1')

    # ---------------------------------------------------------------- helpers
    def seg_of_vaddr(self, va):
        for s in self.segments:
            if s['type'] == 1 and s['vaddr'] <= va < s['vaddr'] + s['filesz']:
                return s
        return None

    def file_of_vaddr(self, va):
        s = self.seg_of_vaddr(va)
        if s is None:
            return None
        return s['offset'] + (va - s['vaddr'])

    def vaddr_of_file(self, off):
        for s in self.segments:
            if s['type'] == 1 and s['offset'] <= off < s['offset'] + s['filesz']:
                return s['vaddr'] + (off - s['offset'])
        return None

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def symbols(self, table='.symtab'):
        sec = self.section(table)
        if sec is None:
            return []
        strtab = self.sections[sec['link']]
        out = []
        n = sec['size'] // sec['entsize']
        e = self.endian
        for i in range(n):
            off = sec['offset'] + i * sec['entsize']
            if self.is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(e + 'IBBHQQ', self.buf, off)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from(e + 'IIIBBH', self.buf, off)
            p = strtab['offset'] + st_name
            end = self.buf.index(b'\x00', p)
            name = self.buf[p:end].decode('latin1')
            out.append({'name': name, 'value': st_value, 'size': st_size,
                        'info': st_info, 'shndx': st_shndx})
        return out

    def functions(self):
        syms = self.symbols('.symtab') or self.symbols('.dynsym')
        out = []
        for s in syms:
            t = s['info'] & 0xF
            if t == 2 and s['value']:  # STT_FUNC
                out.append(s)
        out.sort(key=lambda s: s['value'])
        return out

    # ------------------------------------------------- .eh_frame_hdr parsing
    def _read_encoded(self, off, enc):
        fmt = enc & 0x0F
        if fmt == 0x01:
            v, off = self._uleb(off)
        elif fmt == 0x03:
            v = struct.unpack_from(self.endian + 'I', self.buf, off)[0]
            off += 4
        elif fmt == 0x04:
            v = struct.unpack_from(self.endian + 'Q', self.buf, off)[0]
            off += 8
        elif fmt == 0x0B:
            v = struct.unpack_from(self.endian + 'i', self.buf, off)[0]
            off += 4
        elif fmt == 0x0C:
            v = struct.unpack_from(self.endian + 'q', self.buf, off)[0]
            off += 8
        else:
            raise ValueError('encoding DW_EH_PE 0x%x no soportado' % enc)
        return v, off

    def _uleb(self, off):
        result = 0
        shift = 0
        while True:
            b = self.buf[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, off
            shift += 7

    def function_ranges(self):
        """Lista de (inicio, fin) de TODAS las funciones, via .eh_frame_hdr.

        Esto cubre tambien las funciones locales que no aparecen en .dynsym.
        """
        sec = self.section('.eh_frame_hdr')
        if sec is None:
            return []
        base = sec['offset']
        version = self.buf[base]
        if version != 1:
            return []
        eh_enc, cnt_enc, table_enc = self.buf[base + 1], self.buf[base + 2], self.buf[base + 3]
        off = base + 4
        try:
            eh_ptr, off = self._read_encoded(off, eh_enc)
            count, off = self._read_encoded(off, cnt_enc)
        except Exception:
            return []
        datarel_base = sec['addr'] if (table_enc & 0x70) == 0x30 else 0
        entries = []
        for _ in range(count):
            try:
                start, off = self._read_encoded(off, table_enc)
                length, off = self._read_encoded(off, table_enc)
            except Exception:
                break
            entries.append((start + datarel_base, length))
        entries.sort()
        out = []
        for i, (start, length) in enumerate(entries):
            end = entries[i + 1][0] if i + 1 < len(entries) else start + max(length, 4)
            out.append((start, end))
        return out



if __name__ == '__main__':
    import sys
    el = Elf(sys.argv[1])
    print('%s: %s %s' % (sys.argv[1], 'ELF64' if el.is64 else 'ELF32',
                         {40: 'ARM', 183: 'AArch64', 3: 'x86'}.get(el.e_machine, el.e_machine)))
    print('secciones:')
    for s in el.sections:
        if s['size']:
            print('   %-20s addr=0x%08x off=0x%08x size=%-9d entsize=%d' %
                  (s['name'], s['addr'], s['offset'], s['size'], s['entsize']))
    syms = el.symbols('.symtab')
    dyns = el.symbols('.dynsym')
    print('simbolos .symtab=%d  .dynsym=%d  funciones=%d' %
          (len(syms), len(dyns), len(el.functions())))
