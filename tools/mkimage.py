#!/usr/bin/env python3
"""Build a synthetic, structurally valid XCI and an SD-card image holding it.

The XCI is not a real cartridge: the CardHeader signature is zero, there is
no Nintendo-signed content, and no InitialData. It exercises the layout FS
parses: CardHeader at 0x1000, root HFS0 at 0x10000, child partitions.

The SD image is a FAT32 volume with one long-named file in the root
(`game.xci`), so the reader path is exercised end to end.
"""
import hashlib
import os
import struct
import sys

FILES = [
    ("0000000000000000.cnmt.nca", b"NCA0" + struct.pack("<I", 0x200) + bytes(0x1F8)),
    ("0100000000001000.nca", b"NCA0" + struct.pack("<I", 0x400) + bytes(0x1F8) + bytes(0x200)),
]


def hfs0(entries):
    count = len(entries)
    strtab = bytearray()
    name_offs = []
    for name, _ in entries:
        name_offs.append(len(strtab))
        strtab += name.encode() + b"\0"
    while (0x10 + 0x40 * count + len(strtab)) % 0x10:
        strtab += b"\0"

    ents = bytearray()
    data = bytearray()
    off = 0
    for (name, blob), no in zip(entries, name_offs):
        hashed = blob[: min(len(blob), 0x200)]
        ents += struct.pack("<QQII", off, len(blob), no, len(hashed))
        ents += b"\0" * 8 + hashlib.sha256(hashed).digest()
        data += blob
        off += len(blob)
    return bytes(b"HFS0" + struct.pack("<III", count, len(strtab), 0) + ents + strtab + data)


def build_xci():
    secure = hfs0(FILES)
    root = hfs0([("update", hfs0([])), ("normal", hfs0([])),
                 ("logo", hfs0([])), ("secure", secure)])
    pfs_off = 0x10000
    total = (pfs_off + len(root) + 0x1FF) & ~0x1FF
    img = bytearray(total)
    img[pfs_off:pfs_off + len(root)] = root

    hdr = bytearray(0x200)
    hdr[0x100:0x104] = b"HEAD"
    struct.pack_into("<I", hdr, 0x104, pfs_off // 0x200)
    struct.pack_into("<I", hdr, 0x108, 0xFFFFFFFF)
    hdr[0x10C] = 0x00
    hdr[0x10D] = 0xFA                       # RomSize: 1GB
    hdr[0x10E] = 0x00
    hdr[0x10F] = 0x00
    struct.pack_into("<Q", hdr, 0x110, 0x0100000000001000)
    struct.pack_into("<I", hdr, 0x118, total // 0x200)
    struct.pack_into("<Q", hdr, 0x130, pfs_off)
    struct.pack_into("<Q", hdr, 0x138, len(root))
    hdr[0x140:0x160] = hashlib.sha256(root).digest()
    # 0x160 InitialDataHash stays zero: the signed bytes are never edited,
    # and the emulator cannot produce a matching preimage. FS's check must
    # be patched out (0x187A1C -> MOV W0,#0 on FS 23.5.0).
    struct.pack_into("<I", hdr, 0x180, 1)
    struct.pack_into("<I", hdr, 0x184, 2)
    struct.pack_into("<I", hdr, 0x188, 0)
    struct.pack_into("<I", hdr, 0x18C, total // 0x200)
    img[0x1000:0x1200] = hdr
    return bytes(img)


def _short_checksum(name11):
    s = 0
    for b in name11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _lfn_entries(name, checksum):
    units = [ord(c) for c in name]
    units += [0x0000]
    while len(units) % 13:
        units.append(0xFFFF)
    out = bytearray()
    n_entries = len(units) // 13
    for idx in range(n_entries):
        chunk = units[idx * 13:(idx + 1) * 13]
        e = bytearray(32)
        seq = idx + 1
        e[0] = seq | (0x40 if idx == n_entries - 1 else 0)
        e[11] = 0x0F
        e[12] = 0
        e[13] = checksum
        for k in range(5):
            struct.pack_into("<H", e, 1 + 2 * k, chunk[k])
        for k in range(6):
            struct.pack_into("<H", e, 14 + 2 * k, chunk[5 + k])
        for k in range(2):
            struct.pack_into("<H", e, 28 + 2 * k, chunk[11 + k])
        out = e + out  # LFN entries precede the short entry in reverse order
    return bytes(out)


def build_fat32(files, total_sectors=70000):
    bps, spc, reserved, nfats = 512, 1, 32, 2
    fat_sectors = 1
    while True:
        data = total_sectors - reserved - nfats * fat_sectors
        clusters = data // spc
        need = ((clusters + 2) * 4 + bps - 1) // bps
        if need <= fat_sectors:
            break
        fat_sectors = need
    data_start = reserved + nfats * fat_sectors
    clusters = (total_sectors - data_start) // spc
    assert clusters >= 65525, "volume too small for FAT32"

    fat = [0] * (clusters + 2)
    fat[0], fat[1], fat[2] = 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF  # root = cluster 2
    img = bytearray(total_sectors * bps)
    root_dir = bytearray()

    next_cluster = 3
    for name, data in files:
        n = (len(data) + spc * bps - 1) // (spc * bps)
        start = next_cluster
        for i in range(n):
            fat[start + i] = start + i + 1 if i + 1 < n else 0x0FFFFFFF
        next_cluster += n
        # directory entry: LFN + 8.3
        base, _, ext = name.rpartition(".")
        short = (base.upper()[:8].ljust(8) + ext.upper()[:3].ljust(3)).encode()
        chk = _short_checksum(short)
        root_dir += _lfn_entries(name, chk)
        e = bytearray(32)
        e[0:11] = short
        e[11] = 0x20
        struct.pack_into("<H", e, 26, start & 0xFFFF)
        struct.pack_into("<H", e, 20, (start >> 16) & 0xFFFF)
        struct.pack_into("<I", e, 28, len(data))
        root_dir += e
        off = (data_start + (start - 2) * spc) * bps
        img[off:off + len(data)] = data

    boot = bytearray(bps)
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", boot, 11, bps)
    boot[13] = spc
    struct.pack_into("<H", boot, 14, reserved)
    boot[16] = nfats
    boot[19:21] = b"\0\0"
    struct.pack_into("<H", boot, 19, 0)
    boot[21] = 0xF8
    struct.pack_into("<H", boot, 24, 32)
    struct.pack_into("<H", boot, 26, 64)
    struct.pack_into("<I", boot, 32, total_sectors)
    struct.pack_into("<I", boot, 36, fat_sectors)
    struct.pack_into("<I", boot, 44, 2)
    struct.pack_into("<H", boot, 48, 1)
    struct.pack_into("<H", boot, 50, 6)
    boot[64] = 0x80
    boot[66] = 0x29
    struct.pack_into("<I", boot, 67, 0x1234ABCD)
    boot[71:82] = b"CARDLOADER "
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xAA"

    fsinfo = bytearray(bps)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<I", fsinfo, 484, 0x61417272)
    struct.pack_into("<I", fsinfo, 488, clusters)
    struct.pack_into("<I", fsinfo, 492, 0xFFFFFFFF)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)

    img[0:bps] = boot
    img[bps:2 * bps] = fsinfo
    img[6 * bps:7 * bps] = boot  # backup boot sector

    fat_bytes = bytearray(fat_sectors * bps)
    for i, v in enumerate(fat):
        struct.pack_into("<I", fat_bytes, 4 * i, v)
    for k in range(nfats):
        off = (reserved + k * fat_sectors) * bps
        img[off:off + len(fat_bytes)] = fat_bytes

    off = data_start * bps
    img[off:off + len(root_dir)] = root_dir
    return bytes(img)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "build/game.xci"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    xci = build_xci()
    with open(out, "wb") as f:
        f.write(xci)
    print(f"wrote {out}: {len(xci)} bytes")

    if "--sd" in sys.argv:
        sd = sys.argv[sys.argv.index("--sd") + 1]
        img = build_fat32([("game.xci", xci)])
        with open(sd, "wb") as f:
            f.write(img)
        print(f"wrote {sd}: {len(img)} bytes (FAT32, game.xci)")


if __name__ == "__main__":
    main()
