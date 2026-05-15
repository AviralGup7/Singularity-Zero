"""Screenshot diffing utility for visual regression detection.

Computes pixel-level diffs and structural similarity (SSIM) between
two screenshots. Accepts file paths or base64-encoded image data.
Returns diff metrics and an annotated diff image.
"""

import base64
import io
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont
from pydantic import BaseModel, Field

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

ImageInput = str | Path | bytes


class DiffMetrics(BaseModel):
    pixel_diff_count: int = Field(description="Number of differing pixels")
    pixel_diff_percentage: float = Field(description="Percentage of differing pixels")
    ssim: float = Field(description="Structural similarity index (0.0 to 1.0)")
    mse: float = Field(description="Mean squared error between images")
    width: int = Field(description="Image width used for comparison")
    height: int = Field(description="Image height used for comparison")
    identical: bool = Field(description="True if images are pixel-identical")


class DiffResult(BaseModel):
    metrics: DiffMetrics
    diff_image_base64: str = Field(description="Base64-encoded diff image (PNG)")
    diff_image_path: str | None = Field(
        default=None, description="Path where diff image was saved, if any"
    )


def _load_image(source: ImageInput) -> Image.Image:
    if isinstance(source, bytes):
        return Image.open(io.BytesIO(source)).convert("RGB")
    if isinstance(source, Path) or (isinstance(source, str) and Path(source).exists()):
        return Image.open(source).convert("RGB")
    if isinstance(source, str):
        raw = base64.b64decode(source)
        return Image.open(io.BytesIO(raw)).convert("RGB")
    raise ValueError(f"Unsupported image input type: {type(source)}")


def _normalize_images(img_a: Image.Image, img_b: Image.Image) -> tuple[Image.Image, Image.Image]:
    if img_a.size != img_b.size:
        max_w = max(img_a.width, img_b.width)
        max_h = max(img_a.height, img_b.height)
        resized_a = Image.new("RGB", (max_w, max_h), (0, 0, 0))
        resized_a.paste(img_a, (0, 0))
        resized_b = Image.new("RGB", (max_w, max_h), (0, 0, 0))
        resized_b.paste(img_b, (0, 0))
        return resized_a, resized_b
    return img_a, img_b


def _compute_pixel_diff(img_a: Image.Image, img_b: Image.Image) -> Image.Image:
    diff = ImageChops.difference(img_a, img_b)
    return diff


def _compute_mse(img_a: Image.Image, img_b: Image.Image) -> float:
    pixels_a = list(img_a.getdata())
    pixels_b = list(img_b.getdata())
    total = 0.0
    count = len(pixels_a)
    if count == 0:
        return 0.0
    for (r1, g1, b1), (r2, g2, b2) in zip(pixels_a, pixels_b):
        total += (r1 - r2) ** 2 + (g1 - g2) ** 2 + (b1 - b2) ** 2
    return total / (count * 3)


def _compute_ssim(img_a: Image.Image, img_b: Image.Image, window_size: int = 11) -> float:
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    pixels_a = [list(img_a.getdata())]
    pixels_b = [list(img_b.getdata())]
    width, height = img_a.size
    channels = 3
    total_pixels = width * height

    means_a: list[float] = []
    means_b: list[float] = []
    for ch in range(channels):
        vals_a = [p[ch] for p in pixels_a[0]]
        vals_b = [p[ch] for p in pixels_b[0]]
        means_a.append(sum(vals_a) / total_pixels)
        means_b.append(sum(vals_b) / total_pixels)

    var_a = 0.0
    var_b = 0.0
    cov_ab = 0.0
    for i in range(total_pixels):
        for ch in range(channels):
            diff_a = pixels_a[0][i][ch] - means_a[ch]
            diff_b = pixels_b[0][i][ch] - means_b[ch]
            var_a += diff_a * diff_a
            var_b += diff_b * diff_b
            cov_ab += diff_a * diff_b

    var_a /= total_pixels
    var_b /= total_pixels
    cov_ab /= total_pixels

    numerator = (2 * means_a[0] * means_b[0] + c1) * (2 * cov_ab + c2)
    denominator = (means_a[0] ** 2 + means_b[0] ** 2 + c1) * (var_a + var_b + c2)
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _count_diff_pixels(diff: Image.Image, threshold: int = 0) -> int:
    count = 0
    for pixel in diff.getdata():
        if isinstance(pixel, int):
            if pixel > threshold:
                count += 1
        elif any(c > threshold for c in pixel):
            count += 1
    return count


def _create_annotated_diff(
    img_a: Image.Image,
    img_b: Image.Image,
    diff: Image.Image,
    metrics: DiffMetrics,
) -> Image.Image:
    w, h = img_a.size
    panel_w = w
    total_w = panel_w * 3
    total_h = h + 40
    composite = Image.new("RGB", (total_w, total_h), (255, 255, 255))
    composite.paste(img_a, (0, 40))
    composite.paste(img_b, (panel_w, 40))
    composite.paste(diff, (panel_w * 2, 40))
    draw = ImageDraw.Draw(composite)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = ImageFont.load_default()
    labels = [
        f"Base ({img_a.width}x{img_a.height})",
        f"Current ({img_b.width}x{img_b.height})",
        f"Diff (SSIM: {metrics.ssim:.4f})",
    ]
    for idx, label in enumerate(labels):
        x = idx * panel_w + 10
        draw.text((x, 10), label, fill=(0, 0, 0), font=font)
    summary = (
        f"Diff: {metrics.pixel_diff_count} px ({metrics.pixel_diff_percentage:.2f}%)  "
        f"MSE: {metrics.mse:.2f}  Identical: {metrics.identical}"
    )
    draw.text((10, total_h - 25), summary, fill=(0, 0, 0), font=font)
    return composite


def compute_screenshot_diff(
    base: ImageInput,
    current: ImageInput,
    save_path: str | Path | None = None,
    threshold: int = 0,
) -> DiffResult:
    logger.info("Computing screenshot diff")
    img_base = _load_image(base)
    img_current = _load_image(current)
    img_base, img_current = _normalize_images(img_base, img_current)
    diff_image = _compute_pixel_diff(img_base, img_current)
    diff_pixel_count = _count_diff_pixels(diff_image, threshold)
    total_pixels = img_base.width * img_base.height
    pixel_diff_pct = (diff_pixel_count / total_pixels * 100) if total_pixels > 0 else 0.0
    mse = _compute_mse(img_base, img_current)
    ssim = _compute_ssim(img_base, img_current)
    metrics = DiffMetrics(
        pixel_diff_count=diff_pixel_count,
        pixel_diff_percentage=round(pixel_diff_pct, 4),
        ssim=round(ssim, 6),
        mse=round(mse, 4),
        width=img_base.width,
        height=img_base.height,
        identical=diff_pixel_count == 0,
    )
    annotated = _create_annotated_diff(img_base, img_current, diff_image, metrics)
    buf = io.BytesIO()
    annotated.save(buf, format="PNG")
    diff_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    result = DiffResult(metrics=metrics, diff_image_base64=diff_b64)
    if save_path is not None:
        out = Path(save_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        annotated.save(out, format="PNG")
        result.diff_image_path = str(out)
        logger.info("Diff image saved to %s", out)
    logger.info(
        "Diff complete: SSIM=%.4f MSE=%.2f diff_pct=%.2f%% identical=%s",
        metrics.ssim,
        metrics.mse,
        metrics.pixel_diff_percentage,
        metrics.identical,
    )
    return result
