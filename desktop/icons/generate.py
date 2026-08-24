#!/usr/bin/env python3
"""Generate the secretctl menu-bar and application icons.

Menu-bar icons are macOS *template* images: pure black coverage plus an alpha
channel, which the system re-tints for light mode, dark mode, and the
highlighted (menu-open) state. That is why nothing here sets a colour — the
shape carries all the meaning, which is also what keeps the states legible for
users who cannot rely on colour alone (spec §33).

Each state gets a structurally different glyph rather than a recoloured one:

    protected              closed padlock
    approval_required      padlock + exclamation badge
    sensitive_operation    padlock + bolt badge
    completed              padlock + check badge
    blocked                padlock + cross badge
    protection_interrupted padlock with a severed shackle + exclamation badge
    disconnected           open padlock + cross badge

Run: python3 desktop/icons/generate.py
"""

import math
import os
import struct
import zlib

SS = 4  # supersampling factor for anti-aliasing


class Canvas:
    """Minimal coverage canvas rendered at SS x resolution."""

    def __init__(self, size):
        self.size = size
        self.n = size * SS
        self.buf = bytearray(self.n * self.n)

    def _set(self, x, y):
        if 0 <= x < self.n and 0 <= y < self.n:
            self.buf[y * self.n + x] = 255

    def disc(self, cx, cy, r):
        cx, cy, r = cx * SS, cy * SS, r * SS
        for y in range(int(cy - r) - 1, int(cy + r) + 2):
            for x in range(int(cx - r) - 1, int(cx + r) + 2):
                if (x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2 <= r * r:
                    self._set(x, y)

    def ring(self, cx, cy, r, width, start_deg=0.0, end_deg=360.0):
        cx, cy, r, width = cx * SS, cy * SS, r * SS, width * SS
        outer, inner = r + width / 2.0, r - width / 2.0
        for y in range(int(cy - outer) - 1, int(cy + outer) + 2):
            for x in range(int(cx - outer) - 1, int(cx + outer) + 2):
                dx, dy = x + 0.5 - cx, y + 0.5 - cy
                dist = math.hypot(dx, dy)
                if not inner <= dist <= outer:
                    continue
                angle = math.degrees(math.atan2(-dy, dx)) % 360.0
                if start_deg <= angle <= end_deg:
                    self._set(x, y)

    def rrect(self, x0, y0, x1, y1, radius):
        x0, y0, x1, y1, radius = (v * SS for v in (x0, y0, x1, y1, radius))
        for y in range(int(y0) - 1, int(y1) + 2):
            for x in range(int(x0) - 1, int(x1) + 2):
                px, py = x + 0.5, y + 0.5
                if not (x0 <= px <= x1 and y0 <= py <= y1):
                    continue
                cx = min(max(px, x0 + radius), x1 - radius)
                cy = min(max(py, y0 + radius), y1 - radius)
                if math.hypot(px - cx, py - cy) <= radius:
                    self._set(x, y)

    def line(self, x0, y0, x1, y1, width):
        steps = int(math.hypot(x1 - x0, y1 - y0) * SS * 2) + 1
        for step in range(steps + 1):
            t = step / steps
            self.disc(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, width / 2.0)

    def erase_rect(self, x0, y0, x1, y1):
        x0, y0, x1, y1 = (v * SS for v in (x0, y0, x1, y1))
        for y in range(int(y0), int(y1) + 1):
            for x in range(int(x0), int(x1) + 1):
                if 0 <= x < self.n and 0 <= y < self.n:
                    self.buf[y * self.n + x] = 0

    def downsample(self):
        """Box-filter back to `size`, producing the alpha channel."""
        out = bytearray(self.size * self.size)
        area = SS * SS
        for y in range(self.size):
            for x in range(self.size):
                total = 0
                for sy in range(SS):
                    row = (y * SS + sy) * self.n + x * SS
                    total += sum(self.buf[row : row + SS])
                out[y * self.size + x] = total // area
        return out


def write_png(path, size, alpha, rgb=(0, 0, 0)):
    """Write an 8-bit RGBA PNG with a constant colour and the given alpha."""
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter type: none
        for x in range(size):
            raw.extend((rgb[0], rgb[1], rgb[2], alpha[y * size + x]))

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as handle:
        handle.write(png)


def padlock(canvas, unit, open_shackle=False, broken=False):
    """Draw the padlock every state shares, so the icon stays recognisable."""
    body_w, body_h = 9.5 * unit, 7.5 * unit
    cx = canvas.size / 2 - 2.6 * unit
    body_top = canvas.size / 2 + 0.4 * unit
    canvas.rrect(
        cx - body_w / 2, body_top, cx + body_w / 2, body_top + body_h, 1.6 * unit
    )
    canvas.erase_rect(
        cx - 0.8 * unit, body_top + 2.2 * unit, cx + 0.8 * unit, body_top + 5.0 * unit
    )

    shackle_r, shackle_w = 3.0 * unit, 1.4 * unit
    shackle_cx = cx + (2.4 * unit if open_shackle else 0)
    if broken:
        # A visibly severed shackle: protection could not be verified.
        canvas.ring(shackle_cx, body_top - 0.3 * unit, shackle_r, shackle_w, 25, 90)
    else:
        canvas.ring(shackle_cx, body_top - 0.4 * unit, shackle_r, shackle_w, 0, 180)
        if not open_shackle:
            for side in (-1, 1):
                canvas.line(
                    shackle_cx + side * shackle_r,
                    body_top - 0.4 * unit,
                    shackle_cx + side * shackle_r,
                    body_top + 0.4 * unit,
                    shackle_w,
                )


def badge_exclamation(canvas, bx, by, unit):
    canvas.line(bx, by - 2.4 * unit, bx, by + 0.4 * unit, 1.5 * unit)
    canvas.disc(bx, by + 2.3 * unit, 0.85 * unit)


def badge_check(canvas, bx, by, unit):
    canvas.line(bx - 2.3 * unit, by + 0.2 * unit, bx - 0.6 * unit, by + 2.0 * unit, 1.5 * unit)
    canvas.line(bx - 0.6 * unit, by + 2.0 * unit, bx + 2.6 * unit, by - 2.2 * unit, 1.5 * unit)


def badge_cross(canvas, bx, by, unit):
    canvas.line(bx - 2.0 * unit, by - 2.0 * unit, bx + 2.0 * unit, by + 2.0 * unit, 1.5 * unit)
    canvas.line(bx + 2.0 * unit, by - 2.0 * unit, bx - 2.0 * unit, by + 2.0 * unit, 1.5 * unit)


def badge_bolt(canvas, bx, by, unit):
    canvas.line(bx + 1.2 * unit, by - 2.6 * unit, bx - 1.4 * unit, by + 0.3 * unit, 1.4 * unit)
    canvas.line(bx - 1.4 * unit, by + 0.3 * unit, bx + 0.9 * unit, by + 0.1 * unit, 1.4 * unit)
    canvas.line(bx + 0.9 * unit, by + 0.1 * unit, bx - 1.0 * unit, by + 2.8 * unit, 1.4 * unit)


BADGES = {
    "protected": None,
    "approval_required": badge_exclamation,
    "sensitive_operation": badge_bolt,
    "completed": badge_check,
    "blocked": badge_cross,
    "protection_interrupted": badge_exclamation,
    "disconnected": badge_cross,
}


def render_state(state, size):
    canvas = Canvas(size)
    unit = size / 22.0
    padlock(
        canvas,
        unit,
        open_shackle=(state == "disconnected"),
        broken=(state == "protection_interrupted"),
    )
    badge = BADGES[state]
    if badge is not None:
        bx, by = canvas.size - 3.8 * unit, canvas.size - 3.8 * unit
        # Clear a gap so the badge reads separately from the lock body.
        canvas.erase_rect(bx - 3.6 * unit, by - 3.6 * unit, canvas.size, canvas.size)
        badge(canvas, bx, by, unit)
    return canvas.downsample()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    tray_dir = os.path.join(here, "tray")
    os.makedirs(tray_dir, exist_ok=True)

    for state in BADGES:
        for scale, suffix in ((22, ""), (44, "@2x")):
            write_png(
                os.path.join(tray_dir, f"{state}{suffix}.png"),
                scale,
                render_state(state, scale),
            )
        print(f"tray/{state}.png")

    app_dir = os.path.join(os.path.dirname(here), "src-tauri", "icons")
    os.makedirs(app_dir, exist_ok=True)
    for size in (32, 128, 256, 512):
        name = "128x128@2x.png" if size == 256 else f"{size}x{size}.png"
        write_png(os.path.join(app_dir, name), size, render_state("protected", size), rgb=(28, 28, 30))
        print(f"src-tauri/icons/{name}")
    write_png(
        os.path.join(app_dir, "icon.png"), 512, render_state("protected", 512), rgb=(28, 28, 30)
    )
    print("src-tauri/icons/icon.png")


if __name__ == "__main__":
    main()
