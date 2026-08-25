#!/usr/bin/env python3
"""Draw Cairn's application icon and the Windows .ico that the build needs.

## Why this exists rather than a checked-in binary from a design tool

Two reasons, one of them found by probing rather than by looking. `icons/icon.png` was a
placeholder: 512x512 pixels of a single colour, #6ea8fe. It looked like an icon in a file
listing and would have shipped as a flat blue square in the taskbar, the installer and the
release page. Reading the file did not show that; counting its distinct colours did.

The second is that `tauri-build` **hard-errors** on Windows without `icons/icon.ico` --
"required for generating a Windows Resource file" -- so the release build would have failed
on the runner. There is no Pillow and no ImageMagick in the development container, so the
rasteriser, the PNG encoder and the ICO writer are all here, on zlib and struct alone.

Run it after changing the mark:

    python3 scripts/make-icon.py

## The mark

A cairn: stones stacked by many hands to mark a trail for whoever comes next. Four stones,
widest at the base, in the accent gradient used throughout the client. It has to stay legible
at 16x16 in a taskbar, which is why the stones are few, well separated and high contrast
against the dark plate rather than being outlined.
"""

import math
import struct
import zlib
from pathlib import Path

SIZE = 512
ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "clients/desktop/src-tauri/icons"

PLATE_TOP = (0x1E, 0x25, 0x34)
PLATE_BOTTOM = (0x0C, 0x0E, 0x14)
STONE_TOP = (0x8B, 0x7D, 0xFB)      # --accent-2
STONE_BOTTOM = (0x5B, 0x93, 0xE8)   # the darker end of --accent

# centre x, centre y, half width, half height, corner radius. Fractions of SIZE so the
# proportions survive a change of resolution.
STONES = [
    (0.500, 0.250, 0.110, 0.058, 0.050),
    (0.500, 0.400, 0.180, 0.066, 0.058),
    (0.500, 0.565, 0.250, 0.072, 0.062),
    (0.500, 0.740, 0.320, 0.078, 0.066),
]


def rounded_rect_sdf(x, y, cx, cy, hw, hh, r):
    """Signed distance to a rounded rectangle: negative inside, zero on the edge."""
    dx = abs(x - cx) - (hw - r)
    dy = abs(y - cy) - (hh - r)
    outside = math.hypot(max(dx, 0.0), max(dy, 0.0))
    return outside + min(max(dx, dy), 0.0) - r


def coverage(d):
    """One pixel of antialiasing either side of the edge. Cheaper and sharper than
    supersampling, which at 512x512 in pure Python is measured in minutes."""
    return min(max(0.5 - d, 0.0), 1.0)


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def over(dst, src, alpha):
    """Source-over compositing, straight (not premultiplied) alpha."""
    return tuple(round(src[i] * alpha + dst[i] * (1 - alpha)) for i in range(3))


def draw():
    px = bytearray(SIZE * SIZE * 4)
    plate_r = SIZE * 0.215  # the squircle Windows 11 and macOS both expect

    for y in range(SIZE):
        t = y / (SIZE - 1)
        plate = lerp(PLATE_TOP, PLATE_BOTTOM, t)
        for x in range(SIZE):
            fx, fy = x + 0.5, y + 0.5
            a = coverage(rounded_rect_sdf(fx, fy, SIZE / 2, SIZE / 2, SIZE / 2, SIZE / 2, plate_r))
            if a <= 0.0:
                continue
            colour = plate

            for cx, cy, hw, hh, r in STONES:
                d = rounded_rect_sdf(
                    fx, fy, cx * SIZE, cy * SIZE, hw * SIZE, hh * SIZE, r * SIZE
                )
                sa = coverage(d)
                if sa <= 0.0:
                    continue
                # Vertical gradient across the whole stack rather than per stone, so the
                # four stones read as one object instead of four unrelated bars.
                stone = lerp(STONE_TOP, STONE_BOTTOM, (fy / SIZE - 0.2) / 0.62)
                colour = over(colour, stone, sa)

            i = (y * SIZE + x) * 4
            px[i], px[i + 1], px[i + 2] = colour
            px[i + 3] = round(a * 255)
    return bytes(px)


# ---- PNG -------------------------------------------------------------------


def to_png(size, px):
    def chunk(typ, body):
        crc = zlib.crc32(typ + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    rows = b"".join(b"\x00" + px[y * size * 4:(y + 1) * size * 4] for y in range(size))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def box_resize(px, src, dst):
    """Average the source block behind each destination pixel, premultiplied so a
    transparent edge does not drag colour in from nowhere."""
    out = bytearray(dst * dst * 4)
    for dy in range(dst):
        y0, y1 = dy * src // dst, max(dy * src // dst + 1, (dy + 1) * src // dst)
        for dx in range(dst):
            x0, x1 = dx * src // dst, max(dx * src // dst + 1, (dx + 1) * src // dst)
            r = g = b = a = n = 0
            for sy in range(y0, y1):
                base = sy * src * 4
                for sx in range(x0, x1):
                    i = base + sx * 4
                    al = px[i + 3]
                    r += px[i] * al
                    g += px[i + 1] * al
                    b += px[i + 2] * al
                    a += al
                    n += 1
            o = (dy * dst + dx) * 4
            if a:
                out[o] = min(255, r // a)
                out[o + 1] = min(255, g // a)
                out[o + 2] = min(255, b // a)
            out[o + 3] = a // n
    return bytes(out)


# ---- ICO -------------------------------------------------------------------


def to_dib(size, px):
    """A BMP icon entry: BITMAPINFOHEADER, bottom-up BGRA, then the AND mask.

    Everything at or below 128 uses this rather than PNG. Windows reads PNG entries at any
    size, but NSIS -- which builds the installer -- is fussier, and a rejected icon fails the
    installer build rather than merely looking wrong."""
    header = struct.pack(
        "<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, size * size * 4, 0, 0, 0, 0
    )
    xor = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            i = (y * size + x) * 4
            xor += bytes((px[i + 2], px[i + 1], px[i], px[i + 3]))
    mask_stride = ((size + 31) // 32) * 4
    return header + bytes(xor) + bytes(mask_stride * size)


def to_ico(px, sizes=(16, 24, 32, 48, 64, 128, 256)):
    entries = []
    for s in sizes:
        scaled = box_resize(px, SIZE, s)
        entries.append((s, to_png(s, scaled) if s > 128 else to_dib(s, scaled)))

    out = struct.pack("<HHH", 0, 1, len(entries))
    offset = 6 + 16 * len(entries)
    for s, blob in entries:
        # 0 means 256 in an icon directory; the field is a single byte.
        out += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    return out + b"".join(blob for _, blob in entries)


def main():
    px = draw()
    ICONS.mkdir(parents=True, exist_ok=True)

    (ICONS / "icon.png").write_bytes(to_png(SIZE, px))
    (ICONS / "icon.ico").write_bytes(to_ico(px))
    # The sizes a Linux desktop entry and an AppImage expect, named as Tauri names them.
    for s in (32, 128):
        (ICONS / f"{s}x{s}.png").write_bytes(to_png(s, box_resize(px, SIZE, s)))

    for f in sorted(ICONS.iterdir()):
        print(f"{f.relative_to(ROOT)}: {f.stat().st_size} bytes")


if __name__ == "__main__":
    main()
