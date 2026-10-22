"""Volcado masivo de esquemas: para cada funcion de red interesante, lista las
cadenas (nombres de campo JSON) que referencia.

    python _tools/dump_schemas.py lib/arm64-v8a/libsonicjumpfever.so > ESQUEMAS.txt
"""
import re
import sys

sys.path.insert(0, __file__.rsplit('\\', 1)[0])
from a64func import A64  # noqa: E402

PATTERNS = [
    r'network.*deserialize',
    r'network.*serialize',
    r'^_ZN7network(10NetConnect|13NetHandshake|14NetGetSettings|13NetGetProfile|14NetPushProfile|12NetGetScores|12NetPostScore|13NetGetFriends|14NetGetMessages|16NetDeleteMessage|15NetInviteFriend|11NetSendGift|16NetRequestEnergy|9NetLogIAP|19NetAwardRequestItem)',
    r'^_ZN7network(13LocalSettings|14ServerSettings|16LocalPlayerState|23SynchronizedPlayerState|11PlayerState|10ScoreEntry|11FriendEntry|12MessageEntry|9ChaoState)',
    r'SonicJumpConnectionManager',
    r'^_ZN13DebugSettings',
    r'^_ZN(21DebugZoneSelectScreen|16ZoneChangeScreen)',
    r'^_ZN14LevelResources',
    r'^_ZN13PlayerProfile',
    r'^(main)$',
]


def main():
    a = A64(sys.argv[1] if len(sys.argv) > 1 else 'lib/arm64-v8a/libsonicjumpfever.so')
    print('# %d funciones en .eh_frame, %d con nombre' % (len(a.ranges), len(a.named)))
    done = set()
    for pat in PATTERNS:
        rx = re.compile(pat)
        for addr, name in a.named:
            if not rx.search(name) or addr in done:
                continue
            r = a.func_range_of(addr)
            if not r:
                continue
            done.add(addr)
            strings, calls = a.scan_function(r[0], r[1])
            uniq = []
            for pc, tgt, s in strings:
                if s not in [u[1] for u in uniq]:
                    uniq.append((tgt, s))
            print()
            print('### %s' % name)
            print('    rango 0x%x-0x%x  (%d bytes)' % (r[0], r[1], r[1] - r[0]))
            for tgt, s in uniq:
                print('    %-14s %s' % ('0x%08x' % tgt, s))
            if calls:
                import collections
                cnt = collections.Counter(a.label(c) for _, c in calls)
                print('    -> llama: ' + ', '.join('%s' % k for k, _ in cnt.most_common(10)))


if __name__ == '__main__':
    main()
