"""Generate high-resolution PNG QR code for direct APK download."""

import base64
from pathlib import Path
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.colormasks import RadialGradiantColorMask

DOWNLOAD_URL = "https://github.com/jaiganesh0502/vulnlens/releases/latest/download/VulnLens-Demo.apk"


def generate_qr():
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(DOWNLOAD_URL)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#030E33", back_color="#FFFFFF")

    assets_dir = Path("assets/images")
    assets_dir.mkdir(parents=True, exist_ok=True)
    out_path = assets_dir / "qr_download.png"
    img.save(out_path)
    print(f"Generated QR Code at: {out_path}")

    # Also save in mobile assets
    mobile_assets_dir = Path("vulnlens_mobile/assets/images")
    mobile_assets_dir.mkdir(parents=True, exist_ok=True)
    img.save(mobile_assets_dir / "qr_download.png")
    print(f"Saved to mobile assets: {mobile_assets_dir / 'qr_download.png'}")


if __name__ == "__main__":
    generate_qr()
