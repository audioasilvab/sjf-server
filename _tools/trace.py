"""Traza legible de una funcion ARM64 sin desensamblador completo.

Imprime, en orden, los eventos que importan para entender la logica:
    - direcciones materializadas (ADRP+ADD)
    - cadenas cargadas
    - constantes MOVZ/MOVK/MOVN
    - llamadas (BL) con su destino resuelto a simbolo
    - saltos condicionales (CBZ/CBNZ/B.cond) como pistas de control de flujo

Uso:
    python _tools/trace.py <so> <nombre-funcion>
    python _tools/trace.py <so> --at 0x4b83d4 --len 644
"""
import argparse
import bisect
import re
import struct
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from a64func import A64, sx, dec_adrp, dec_add, dec_ldr, dec_bl  # noqa: E402


def dec_movwide(insn):
    m = insn & 0x7F800000
    if m not in (0x52800000, 0x72800000, 0x12800000):
        return None
    op = {0x52800000: 'movz', 0x72800000: 'movk', 0x12800000: 'movn'}[m]
    sf = (insn >> 31) & 1
    hw = (insn >> 21) & 3
    imm16 = (insn >> 5) & 0xFFFF
    rd = insn & 0x1F
    return op, rd, imm16, hw, sf


def dec_mov_reg(insn):
    # ORR Xd, XZR, Xm  ->  mov Xd, Xm
    if (insn & 0x7FE0FFE0) == 0x2A0003E0:
        return 'mov32', insn & 0x1F, (insn >> 16) & 0x1F
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        return 'mov64', insn & 0x1F, (insn >> 16) & 0x1F
    return None


def dec_cbz(insn, pc):
    if (insn & 0x7E000000) == 0x34000000:
        sf = (insn >> 31) & 1
        op = (insn >> 24) & 1
        imm = sx((insn >> 5) & 0x7FFFF, 19) << 2
        rt = insn & 0x1F
        return ('cbnz' if op else 'cbz'), rt, pc + imm
    if (insn & 0x7E000000) == 0x36000000:
        op = (insn >> 24) & 1
        b = (insn >> 19) & 0x1F
        imm = sx(((insn >> 31) << 13) | ((insn >> 5) & 0x3FFF), 14) << 2
        rt = insn & 0x1F
        return ('tbnz' if op else 'tbz'), rt, pc + imm
    return None


def dec_bcond(insn, pc):
    if (insn & 0xFF000010) == 0x54000000:
        imm = sx((insn >> 5) & 0x7FFFF, 19) << 2
        return 'b.%d' % (insn & 0xF), pc + imm
    return None


def dec_b(insn, pc):
    if (insn & 0xFC000000) == 0x14000000:
        return 'b', pc + (sx(insn & 0x3FFFFFF, 26) << 2)
    return None


def dec_ret(insn):
    return (insn & 0xFFFFFC1F) == 0xD65F0000


def dec_stp_ldp(insn):
    """STP/LDP con offset con signo (32/64 bits)."""
    if (insn & 0x3A000000) not in (0x28000000, 0x29000000, 0x2A000000, 0x2B000000):
        return None
    opc = (insn >> 30) & 3
    l = (insn >> 22) & 1
    imm7 = (insn >> 15) & 0x7F
    if imm7 & 0x40:
        imm7 -= 0x80
    rt2 = (insn >> 10) & 0x1F
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    scale = 8 if opc == 2 else 4
    return ('ldp' if l else 'stp'), rt, rt2, rn, imm7 * scale


def dec_ldst_uoff(insn):
    """LDR/STR (unsigned offset), 8/16/32/64 bits."""
    if (insn & 0x3B000000) != 0x39000000:
        return None
    size = (insn >> 30) & 3
    opc = (insn >> 22) & 3
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    mn = {(0, 0): 'strb', (0, 1): 'ldrb', (1, 0): 'strh', (1, 1): 'ldrh',
          (2, 0): 'str', (2, 1): 'ldr', (2, 2): 'ldrsw',
          (3, 0): 'str', (3, 1): 'ldr'}.get((size, opc))
    return mn, rt, rn, imm12 << size


def dec_addsub_reg(insn):
    """ADD/SUB (shifted register) y CMP."""
    if (insn & 0x1F200000) != 0x0B000000:
        return None
    sf = (insn >> 31) & 1
    op = (insn >> 30) & 1
    s = (insn >> 29) & 1
    shift = (insn >> 22) & 3
    rm = (insn >> 16) & 0x1F
    imm6 = (insn >> 10) & 0x3F
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    mn = 'sub' if op else 'add'
    if s and rd == 31:
        mn = 'cmp' if not op else 'cmn'
        return mn, rn, rm, imm6 << shift
    return mn, rd, rn, rm, imm6, shift


def dec_orr_reg(insn):
    if (insn & 0x7FE00000) != 0x2A000000:
        return None
    sf = (insn >> 31) & 1
    rm = (insn >> 16) & 0x1F
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return 'orr', rd, rn, rm



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('func', nargs='?')
    ap.add_argument('--at', type=lambda x: int(x, 0))
    ap.add_argument('--len', type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()

    a = A64(args.so)
    if args.at is not None:
        start = args.at
        end = start + (args.len or 512)
    else:
        hits = a.resolve(args.func, 5)
        if not hits:
            print('funcion no encontrada')
            return
        start, name = hits[0]
        r = a.func_range_of(start)
        end = r[1]
        print('### %s  0x%x-0x%x (%d bytes)' % (name, r[0], r[1], r[1] - r[0]))

    buf = a.el.buf
    page = {}
    for pc in range(start, end - 4, 4):
        insn = struct.unpack_from('<I', buf, pc)[0]
        notes = []

        d = dec_adrp(insn, pc)
        if d:
            page[d[0]] = (d[1], pc)
            notes.append('adrp x%d, 0x%x' % (d[0], d[1]))
        else:
            ad = dec_add(insn)
            if ad:
                rd, rn, imm = ad
                if rn in page and pc - page[rn][1] <= 48:
                    tgt = page[rn][0] + imm
                    s = a.read_string(tgt)
                    notes.append('add x%d, x%d, #0x%x -> 0x%x%s' %
                                 (rd, rn, imm, tgt, ('  "%s"' % s[:60]) if s else ''))
                else:
                    notes.append('add x%d, x%d, #0x%x' % (rd, rn, imm))
            l = dec_ldr(insn)
            if l:
                rt, rn, imm = l
                if rn in page and pc - page[rn][1] <= 48:
                    tgt = page[rn][0] + imm
                    s = a.read_string(tgt)
                    if s:
                        notes.append('ldr x%d, [x%d, #%d] -> "%s"' % (rt, rn, imm, s[:50]))
        mw = dec_movwide(insn)
        if mw:
            op, rd, imm16, hw, sf = mw
            notes.append('%s x%d, #0x%x, lsl #%d' % (op, rd, imm16, hw * 16))
        mr = dec_mov_reg(insn)
        if mr:
            notes.append('%s x%d, x%d' % mr)
        sp = dec_stp_ldp(insn)
        if sp:
            notes.append('%s x%d, x%d, [x%d, #%d]' % sp)
        lu = dec_ldst_uoff(insn)
        if lu:
            notes.append('%s x%d, [x%d, #0x%x]' % lu)
        ar = dec_addsub_reg(insn)
        if ar:
            notes.append(str(ar))
        orr = dec_orr_reg(insn)
        if orr:
            notes.append('orr x%d, x%d, x%d' % orr[1:])
        c = dec_bl(insn, pc)
        if c is not None:
            notes.append('bl %s' % a.label(c))
        else:
            cb = dec_cbz(insn, pc)
            if cb:
                notes.append('%s x%d -> 0x%x' % cb)
            else:
                bc = dec_bcond(insn, pc)
                if bc:
                    notes.append('%s -> 0x%x' % bc)
                else:
                    bb = dec_b(insn, pc)
                    if bb:
                        notes.append('b -> 0x%x' % bb[1])
                    elif dec_ret(insn):
                        notes.append('ret')
        print('  0x%06x  %08x  %s' % (pc, insn, ' | '.join(notes) if notes else '?'))


if __name__ == '__main__':
    main()
