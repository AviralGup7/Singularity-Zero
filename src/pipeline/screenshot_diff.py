"""Screenshot diffing utility for visual regression detection.

Computes pixel-level diffs and structural similarity (SSIM) between
two screenshots. Accepts file paths or base64-encoded image data.
Returns diff metrics and an annotated diff image.
"""

import base64
import io
from pathlib import Path

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFont
from pydantic import BaseModel, Field
from scipy.signal import convolve2d

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


def _gaussian_kernel(size: int = 11, sigma: float = 1.5) -> np.ndarray:
    x = np.arange(-(size // 2), size // 2 + 1)
    kernel = np.exp(-0.5 * (x**2) / sigma**2)
    kernel2d = np.outer(kernel, kernel)
    result: np.ndarray = kernel2d / kernel2d.sum()
    return result


def _compute_ssim(img_a: Image.Image, img_b: Image.Image, win_size: int = 11, sigma: float = 1.5) -> float:
    """Compute structural similarity (SSIM) using a 2D Gaussian window."""
    # Convert to grayscale float array
    arr_a = np.array(img_a.convert("L"), dtype=float)
    arr_b = np.array(img_b.convert("L"), dtype=float)

    window = _gaussian_kernel(win_size, sigma)

    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2

    # Local means
    mu1 = convolve2d(arr_a, window, mode='valid')
    mu2 = convolve2d(arr_b, window, mode='valid')

    mu1_sq = mu1 ** 2
    mu2_sq = mu2 ** 2
    mu1_mu2 = mu1 * mu2

    # Local variances and covariances
    sigma1_sq = convolve2d(arr_a ** 2, window, mode='valid') - mu1_sq
    sigma2_sq = convolve2d(arr_b ** 2, window, mode='valid') - mu2_sq
    sigma12 = convolve2d(arr_a * arr_b, window, mode='valid') - mu1_mu2

    # SSIM map calculation
    ssim_map = ((2 * mu1_mu2 + c1) * (2 * sigma12 + c2)) / (
        (mu1_sq + mu2_sq + c1) * (sigma1_sq + sigma2_sq + c2)
    )
    return float(np.mean(ssim_map))


def _highlight_changes(
    img_a: Image.Image,
    img_b: Image.Image,
    diff: Image.Image,
    grid_cols: int = 8,
    grid_rows: int = 8,
    threshold: float = 0.98,
) -> Image.Image:
    """Split the images into a grid, run SSIM per tile, and draw bounding boxes around changed tiles."""
    w, h = img_a.size
    tile_w = w / grid_cols
    tile_h = h / grid_rows

    highlighted = diff.convert("RGBA")
    overlay = Image.new("RGBA", highlighted.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    for row in range(grid_rows):
        for col in range(grid_cols):
            x0 = int(col * tile_w)
            y0 = int(row * tile_h)
            x1 = int((col + 1) * tile_w)
            y1 = int((row + 1) * tile_h)

            if x1 <= x0 or y1 <= y0:
                continue

            crop_a = img_a.crop((x0, y0, x1, y1))
            crop_b = img_b.crop((x0, y0, x1, y1))

            tile_ssim = _compute_ssim(crop_a, crop_b)
            if tile_ssim < threshold:
                # Highlight changed region in semi-transparent red
                draw.rectangle([x0, y0, x1 - 1, y1 - 1], outline=(255, 0, 0, 180), width=2)
                draw.rectangle([x0 + 1, y0 + 1, x1 - 2, y1 - 2], fill=(255, 0, 0, 30))

    return Image.alpha_composite(highlighted, overlay).convert("RGB")


def _count_diff_pixels(diff: Image.Image, threshold: int = 0) -> int:
    count = 0
    for pixel in list(diff.getdata()):
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

    # Highlight changed regions in diff panel using tiled SSIM
    diff_image = _highlight_changes(img_base, img_current, diff_image)

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

