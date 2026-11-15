"""Genera el icono de JHTerminalx (icon.png, icon.ico, icon.icns).

Uso: python3 assets/make_icon.py   (requiere Pillow)
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent
S = 1024  # se dibuja grande y se reduce (antialiasing)


def rounded(draw, box, r, **kw):
    draw.rounded_rectangle(box, radius=r, **kw)


def make() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Fondo con degradado vertical
    bg = Image.new("RGBA", (S, S))
    bd = ImageDraw.Draw(bg)
    top, bot = (0x2b, 0x2f, 0x45), (0x12, 0x14, 0x1f)
    for y in range(S):
        t = y / (S - 1)
        bd.line([(0, y), (S, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bot)) + (255,))
    mask = Image.new("L", (S, S), 0)
    rounded(ImageDraw.Draw(mask), (40, 40, S - 40, S - 40), 200, fill=255)
    img.paste(bg, (0, 0), mask)

    # Ventana trasera (multisesión)
    rounded(d, (300, 170, 880, 600), 48, fill=(0x3a, 0x4a, 0x78, 255))
    rounded(d, (300, 170, 880, 250), 48, fill=(0x55, 0x6a, 0xa8, 255))
    d.rectangle((300, 210, 880, 250), fill=(0x55, 0x6a, 0xa8, 255))

    # Ventana delantera (terminal)
    rounded(d, (150, 330, 760, 850), 52, fill=(0x1e, 0x1f, 0x29, 255), outline=(0x61, 0xaf, 0xef, 255), width=14)
    rounded(d, (157, 337, 753, 420), 46, fill=(0x2c, 0x31, 0x48, 255))
    d.rectangle((157, 380, 753, 420), fill=(0x2c, 0x31, 0x48, 255))
    for i, c in enumerate([(0xe0, 0x5f, 0x65), (0xe5, 0xc0, 0x7b), (0x7c, 0xc4, 0x7a)]):
        cx = 215 + i * 55
        d.ellipse((cx - 17, 361, cx + 17, 395), fill=c + (255,))

    # Prompt ">_"
    green = (0x7c, 0xe0, 0x7a, 255)
    d.line([(250, 520), (380, 610), (250, 700)], fill=green, width=56, joint="curve")
    for x, y in [(250, 520), (380, 610), (250, 700)]:
        d.ellipse((x - 28, y - 28, x + 28, y + 28), fill=green)
    rounded(d, (430, 680, 640, 732), 26, fill=green)
    return img


def main() -> None:
    big = make()
    png = big.resize((256, 256), Image.LANCZOS)
    png.save(OUT / "icon.png")
    big.save(OUT / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    big.save(OUT / "icon.icns")
    print("Iconos generados en", OUT)


if __name__ == "__main__":
    main()
