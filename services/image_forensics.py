"""
Image Forensics Engine for CyberShield AI.

Purpose:
    Performs local, deterministic image forensic analysis BEFORE sending
    the image to Gemini. Gemini should NOT be responsible for detecting
    image manipulation — instead, it explains the evidence extracted here.

    This engine extracts objective forensic indicators:

        - Resolution
        - Aspect Ratio
        - EXIF Metadata
        - JPEG Compression Quality
        - Edge Density
        - Image Sharpness
        - Noise Analysis
        - Histogram Analysis
        - Error Level Analysis (ELA)
        - Lighting Consistency
        - Color Distribution
        - Texture Consistency

    All indicators are returned as structured data that is injected into
    the Gemini prompt and the XAI formatter.

Public methods:
    analyze_image_forensics(image_path) -> Dict[str, Any]
"""

import io
import os
import math
import logging
from typing import Any, Dict, Optional, Tuple

import numpy as np
from PIL import Image, ImageFile, ImageStat, ImageFilter, ExifTags

from utils.logger import get_logger

# Allow loading of truncated images partially (for robustness).
ImageFile.LOAD_TRUNCATED_IMAGES = True

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Individual forensic extractors
# ---------------------------------------------------------------------------

def _extract_resolution_and_aspect(img: Image.Image) -> Dict[str, Any]:
    """Extracts image resolution and aspect ratio."""
    width, height = img.size
    aspect_ratio = width / height if height else 0
    return {
        "resolution": f"{width}x{height}",
        "width": width,
        "height": height,
        "aspect_ratio": round(aspect_ratio, 3),
    }


def _extract_metadata(img: Image.Image) -> Dict[str, Any]:
    """
    Extracts EXIF metadata status.

    Returns whether metadata is available and a summary of key tags.
    """
    exif_data = {}
    has_exif = False

    try:
        raw_exif = img._getexif()
        if raw_exif:
            has_exif = True
            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                # Truncate long values.
                val_str = str(value)
                if len(val_str) > 100:
                    val_str = val_str[:100] + "..."
                exif_data[tag_name] = val_str
    except (AttributeError, TypeError, ValueError) as exc:
        logger.debug("EXIF extraction error: %s", exc)

    # Check for software / camera tags that indicate editing tools.
    software = exif_data.get("Software", "")
    camera_make = exif_data.get("Make", "")
    camera_model = exif_data.get("Model", "")

    metadata_status = "Available" if has_exif else "Missing"
    if software and any(
        tool in software.lower()
        for tool in ("photoshop", "gimp", "lightroom", "snapseed", "affinity")
    ):
        metadata_status = f"Available (Edited: {software})"

    return {
        "metadata": metadata_status,
        "metadata_status": metadata_status,
        "has_exif": has_exif,
        "exif_software": software,
        "exif_camera": f"{camera_make} {camera_model}".strip() if camera_make or camera_model else "",
    }


def _estimate_jpeg_quality(img: Image.Image, image_path: str) -> Dict[str, Any]:
    """
    Estimates JPEG compression quality by re-saving the image at known
    quality levels and comparing file sizes.

    This is a heuristic approach — a more precise method would parse
    quantization tables, but this works for forensic indication.
    """
    quality = 0
    method = "unknown"

    try:
        # If the original file is JPEG, try to read quantization tables.
        if image_path.lower().endswith((".jpg", ".jpeg")):
            with open(image_path, "rb") as f:
                img_jpeg = Image.open(f)
                qtables = getattr(img_jpeg, "quantization", None)
                if qtables:
                    # Estimate quality from luminance quantization table.
                    if 0 in qtables:
                        lum_table = qtables[0]
                        # Average of the luminance table values gives a rough quality estimate.
                        avg_val = sum(lum_table) / len(lum_table) if lum_table else 50
                        # Lower average = higher quality. Map inversely.
                        quality = max(10, min(100, int(100 - avg_val)))
                        method = "quantization_table"
                    else:
                        quality = 85
                        method = "default_jpeg"
                else:
                    quality = 85
                    method = "default_jpeg"
        else:
            # Non-JPEG formats (PNG, etc.) — no JPEG compression applied.
            quality = 100
            method = "lossless_format"
    except Exception as exc:
        logger.debug("JPEG quality estimation error: %s", exc)
        quality = 0
        method = "estimation_failed"

    return {
        "jpeg_quality": quality,
        "jpeg_quality_method": method,
    }


def _compute_edge_density(gray_arr: np.ndarray) -> Dict[str, Any]:
    """
    Computes edge density using a simple Sobel-like gradient operator.

    High edge density can indicate synthetic / AI-generated content
    (diffusion models often produce overly smooth or uniformly textured regions).
    """
    try:
        # Simple gradient (horizontal + vertical differences).
        grad_x = np.abs(np.diff(gray_arr, axis=1))
        grad_y = np.abs(np.diff(gray_arr, axis=0))

        # Pad to original shape for mean calculation.
        grad_x_padded = np.pad(grad_x, ((0, 0), (0, 1)), mode="constant")
        grad_y_padded = np.pad(grad_y, ((0, 1), (0, 0)), mode="constant")

        total_gradient = grad_x_padded + grad_y_padded
        mean_gradient = float(np.mean(total_gradient))
        std_gradient = float(np.std(total_gradient))

        # Classify edge density.
        if mean_gradient < 15:
            edge_label = "Low (Smooth)"
        elif mean_gradient < 40:
            edge_label = "Normal"
        elif mean_gradient < 70:
            edge_label = "High (Detailed)"
        else:
            edge_label = "Very High (Possible Artifacts)"

        return {
            "edge_density": round(mean_gradient, 2),
            "edge_std": round(std_gradient, 2),
            "edges": edge_label,
        }
    except Exception as exc:
        logger.debug("Edge density computation error: %s", exc)
        return {"edge_density": 0.0, "edge_std": 0.0, "edges": "Analysis Failed"}


def _compute_sharpness(img: Image.Image) -> Dict[str, Any]:
    """
    Computes image sharpness using the variance of the Laplacian.

    Low sharpness variance can indicate blur (sometimes used to hide
    manipulation seams), while very high uniform sharpness can indicate
    synthetic generation.
    """
    try:
        gray = img.convert("L")
        gray_arr = np.array(gray, dtype=np.float64)

        # Laplacian kernel.
        laplacian = np.array(
            [[0, 1, 0], [1, -4, 1], [0, 1, 0]],
            dtype=np.float64,
        )

        # Simple convolution (for speed, we use a basic approach).
        h, w = gray_arr.shape
        lap_result = np.zeros_like(gray_arr)
        lap_result[1:-1, 1:-1] = (
            gray_arr[1:-1, :-2]
            + gray_arr[1:-1, 2:]
            + gray_arr[:-2, 1:-1]
            + gray_arr[2:, 1:-1]
            - 4 * gray_arr[1:-1, 1:-1]
        )

        variance = float(np.var(lap_result))

        if variance < 50:
            sharpness_label = "Blurry"
        elif variance < 500:
            sharpness_label = "Moderate"
        elif variance < 3000:
            sharpness_label = "Sharp"
        else:
            sharpness_label = "Very Sharp"

        return {
            "sharpness": round(variance, 2),
            "sharpness_label": sharpness_label,
        }
    except Exception as exc:
        logger.debug("Sharpness computation error: %s", exc)
        return {"sharpness": 0.0, "sharpness_label": "Analysis Failed"}


def _compute_noise_analysis(img: Image.Image) -> Dict[str, Any]:
    """
    Analyzes noise patterns by computing the difference between the
    original image and a median-filtered (denoised) version.

    AI-generated images often have unnatural noise distributions —
    either too uniform or completely absent.
    """
    try:
        gray = img.convert("L")
        gray_arr = np.array(gray, dtype=np.float64)

        # Median filter for denoising.
        denoised = img.convert("L").filter(ImageFilter.MedianFilter(size=3))
        denoised_arr = np.array(denoised, dtype=np.float64)

        noise = gray_arr - denoised_arr
        noise_mean = float(np.mean(np.abs(noise)))
        noise_std = float(np.std(noise))

        # Classify noise.
        if noise_mean < 2.0:
            noise_label = "Low (Possible Synthetic)"
        elif noise_mean < 8.0:
            noise_label = "Natural"
        elif noise_mean < 20.0:
            noise_label = "High (Noisy / Compressed)"
        else:
            noise_label = "Very High (Heavy Compression / Degraded)"

        return {
            "noise_score": round(noise_mean, 2),
            "noise_std": round(noise_std, 2),
            "noise": noise_label,
        }
    except Exception as exc:
        logger.debug("Noise analysis error: %s", exc)
        return {"noise_score": 0.0, "noise_std": 0.0, "noise": "Analysis Failed"}


def _compute_histogram_analysis(img: Image.Image) -> Dict[str, Any]:
    """
    Analyzes color histogram distribution.

    AI-generated images often have unnaturally smooth or peaked
    histograms, while real photos have more organic distributions.
    """
    try:
        hist_data = {}
        channels = {"R": 0, "G": 1, "B": 2}

        if img.mode != "RGB":
            img_rgb = img.convert("RGB")
        else:
            img_rgb = img

        for channel_name, channel_idx in channels.items():
            hist = img_rgb.histogram()[channel_idx * 256 : (channel_idx + 1) * 256]
            hist_arr = np.array(hist, dtype=np.float64)
            total = hist_arr.sum()
            if total > 0:
                hist_norm = hist_arr / total
                # Compute entropy of the histogram.
                non_zero = hist_norm[hist_norm > 0]
                entropy = -float(np.sum(non_zero * np.log2(non_zero)))
                # Compute smoothness (variance of consecutive differences).
                diffs = np.diff(hist_norm)
                smoothness = float(np.var(diffs))
                hist_data[channel_name] = {
                    "entropy": round(entropy, 3),
                    "smoothness": round(smoothness, 6),
                }

        # Average entropy across channels.
        avg_entropy = (
            sum(h["entropy"] for h in hist_data.values()) / len(hist_data)
            if hist_data
            else 0
        )

        if avg_entropy > 7.5:
            hist_label = "Rich Distribution"
        elif avg_entropy > 6.0:
            hist_label = "Natural Distribution"
        elif avg_entropy > 4.0:
            hist_label = "Narrow Distribution"
        else:
            hist_label = "Artificial / Peaked"

        return {
            "histogram_entropy": round(avg_entropy, 3),
            "histogram_distribution": hist_label,
            "color_distribution": hist_label,
            "histogram_channels": hist_data,
        }
    except Exception as exc:
        logger.debug("Histogram analysis error: %s", exc)
        return {
            "histogram_entropy": 0.0,
            "histogram_distribution": "Analysis Failed",
            "color_distribution": "Analysis Failed",
        }


def _compute_ela(image_path: str, quality: int = 90) -> Dict[str, Any]:
    """
    Performs Error Level Analysis (ELA).

    ELA re-saves the image at a known JPEG quality level and compares
    the result to the original. Regions that were manipulated / spliced
    will show different error levels than the surrounding authentic areas.

    A high ELA score indicates significant differences — potential
    manipulation. A low score suggests uniform compression (authentic
    or uniformly re-saved).

    Args:
        image_path: Path to the original image file.
        quality: JPEG quality to use for re-saving (default 90).

    Returns:
        Dictionary with ELA score and classification.
    """
    try:
        original = Image.open(image_path)
        if original.mode != "RGB":
            original = original.convert("RGB")

        # Re-save at the specified quality.
        buffer = io.BytesIO()
        original.save(buffer, format="JPEG", quality=quality)
        buffer.seek(0)
        resaved = Image.open(buffer)

        # Compute pixel difference.
        orig_arr = np.array(original, dtype=np.float64)
        resaved_arr = np.array(resaved.resize(original.size), dtype=np.float64)

        diff = np.abs(orig_arr - resaved_arr)
        mean_diff = float(np.mean(diff))
        std_diff = float(np.std(diff))
        max_diff = float(np.max(diff))

        # Normalize to 0-1 scale (max possible difference is 255).
        ela_score = mean_diff / 255.0

        # Classify.
        if ela_score < 0.02:
            ela_label = "Uniform (Authentic or Re-saved)"
        elif ela_score < 0.08:
            ela_label = "Low Error (Likely Authentic)"
        elif ela_score < 0.15:
            ela_label = "Moderate Error (Review Needed)"
        else:
            ela_label = "High Error (Possible Manipulation)"

        return {
            "ela_score": round(ela_score, 4),
            "ela_mean": round(mean_diff, 2),
            "ela_std": round(std_diff, 2),
            "ela_max": round(max_diff, 2),
            "ela_classification": ela_label,
        }
    except Exception as exc:
        logger.debug("ELA computation error: %s", exc)
        return {
            "ela_score": 0.0,
            "ela_mean": 0.0,
            "ela_std": 0.0,
            "ela_max": 0.0,
            "ela_classification": "Analysis Failed",
        }


def _compute_lighting_consistency(img: Image.Image) -> Dict[str, Any]:
    """
    Analyzes lighting consistency by examining brightness gradients
    across the image.

    Inconsistent lighting (e.g. shadows falling in wrong directions,
    or mismatched illumination on faces) is a strong indicator of
    image manipulation or AI generation.
    """
    try:
        if img.mode != "RGB":
            img = img.convert("RGB")

        gray = img.convert("L")
        gray_arr = np.array(gray, dtype=np.float64)
        h, w = gray_arr.shape

        # Divide image into a 4x4 grid and compute mean brightness per cell.
        grid_size = 4
        cell_h = h // grid_size
        cell_w = w // grid_size

        brightness_grid = []
        for i in range(grid_size):
            row = []
            for j in range(grid_size):
                cell = gray_arr[
                    i * cell_h : (i + 1) * cell_h,
                    j * cell_w : (j + 1) * cell_w,
                ]
                row.append(float(np.mean(cell)))
            brightness_grid.append(row)

        grid_arr = np.array(brightness_grid)
        # Compute the coefficient of variation across grid cells.
        grid_mean = float(np.mean(grid_arr))
        grid_std = float(np.std(grid_arr))
        cv = grid_std / grid_mean if grid_mean > 0 else 0

        # Check for directional gradient (left-to-right, top-to-bottom).
        row_means = grid_arr.mean(axis=1)
        col_means = grid_arr.mean(axis=0)
        row_gradient = float(np.std(row_means))
        col_gradient = float(np.std(col_means))

        # Classify lighting consistency.
        if cv < 0.15 and row_gradient < 20 and col_gradient < 20:
            lighting_label = "Consistent"
        elif cv < 0.30:
            lighting_label = "Slightly Inconsistent"
        elif cv < 0.50:
            lighting_label = "Inconsistent"
        else:
            lighting_label = "Highly Inconsistent (Possible Manipulation)"

        return {
            "lighting_consistency": lighting_label,
            "lighting_cv": round(cv, 3),
            "lighting_row_gradient": round(row_gradient, 2),
            "lighting_col_gradient": round(col_gradient, 2),
            "lighting": lighting_label,
        }
    except Exception as exc:
        logger.debug("Lighting consistency error: %s", exc)
        return {
            "lighting_consistency": "Analysis Failed",
            "lighting_cv": 0.0,
            "lighting": "Analysis Failed",
        }


def _compute_color_distribution(img: Image.Image) -> Dict[str, Any]:
    """
    Analyzes color channel distribution and balance.

    AI-generated images sometimes have unnatural color casts or
    imbalanced channel statistics.
    """
    try:
        if img.mode != "RGB":
            img = img.convert("RGB")

        stat = ImageStat.Stat(img)
        r_mean, g_mean, b_mean = stat.mean

        # Compute channel balance.
        total = r_mean + g_mean + b_mean
        if total > 0:
            r_ratio = r_mean / total
            g_ratio = g_mean / total
            b_ratio = b_mean / total
        else:
            r_ratio = g_ratio = b_ratio = 0.333

        # Check for color cast (one channel significantly dominant).
        max_ratio = max(r_ratio, g_ratio, b_ratio)
        min_ratio = min(r_ratio, g_ratio, b_ratio)
        cast_diff = max_ratio - min_ratio

        if cast_diff < 0.05:
            color_label = "Balanced"
        elif cast_diff < 0.15:
            color_label = "Slightly Imbalanced"
        else:
            dominant = "Red" if r_ratio == max_ratio else ("Green" if g_ratio == max_ratio else "Blue")
            color_label = f"Imbalanced ({dominant} Cast)"

        return {
            "color_r_mean": round(r_mean, 2),
            "color_g_mean": round(g_mean, 2),
            "color_b_mean": round(b_mean, 2),
            "color_balance": color_label,
        }
    except Exception as exc:
        logger.debug("Color distribution error: %s", exc)
        return {"color_balance": "Analysis Failed", "color_distribution": "Analysis Failed"}


def _compute_texture_consistency(img: Image.Image) -> Dict[str, Any]:
    """
    Analyzes texture consistency using local standard deviation in
    image blocks.

    AI-generated images often have unnaturally uniform texture, while
    real photos have organic variation.
    """
    try:
        gray = img.convert("L")
        gray_arr = np.array(gray, dtype=np.float64)
        h, w = gray_arr.shape

        # Divide into 8x8 blocks and compute local std.
        block_size = max(h // 8, w // 8, 16)
        stds = []
        for i in range(0, h - block_size, block_size):
            for j in range(0, w - block_size, block_size):
                block = gray_arr[i : i + block_size, j : j + block_size]
                stds.append(float(np.std(block)))

        if not stds:
            return {"texture_consistency": "Analysis Failed", "texture": "Analysis Failed"}

        stds_arr = np.array(stds)
        mean_std = float(np.mean(stds_arr))
        cv_std = float(np.std(stds_arr) / mean_std) if mean_std > 0 else 0

        # Low coefficient of variation = uniform texture (possible synthetic).
        if cv_std < 0.2:
            texture_label = "Uniform (Possible Synthetic)"
        elif cv_std < 0.5:
            texture_label = "Consistent"
        elif cv_std < 1.0:
            texture_label = "Varied (Organic)"
        else:
            texture_label = "Highly Varied"

        return {
            "texture_consistency": texture_label,
            "texture_mean_std": round(mean_std, 2),
            "texture_cv": round(cv_std, 3),
            "texture": texture_label,
            "organic_texture": texture_label,
        }
    except Exception as exc:
        logger.debug("Texture consistency error: %s", exc)
        return {
            "texture_consistency": "Analysis Failed",
            "texture": "Analysis Failed",
            "organic_texture": "Analysis Failed",
        }


# ---------------------------------------------------------------------------
# Main forensic analyzer
# ---------------------------------------------------------------------------

def analyze_image_forensics(image_path: str) -> Dict[str, Any]:
    """
    Performs comprehensive local image forensic analysis.

    Extracts all forensic indicators and returns them as a structured
    dictionary. This data is injected into the Gemini prompt so Gemini
    can explain the evidence rather than invent it.

    Args:
        image_path: Path to the image file on disk.

    Returns:
        A dictionary containing all extracted forensic indicators.
    """
    if not image_path or not os.path.exists(image_path):
        logger.error("Image forensics: file not found: %s", image_path)
        return {"error": "Image file not found"}

    try:
        img = Image.open(image_path)
        logger.info("Starting forensic analysis: %s", image_path)

        # Run all forensic extractors.
        results: Dict[str, Any] = {}

        results.update(_extract_resolution_and_aspect(img))
        results.update(_extract_metadata(img))
        results.update(_estimate_jpeg_quality(img, image_path))

        # Convert to grayscale array for some analyses.
        gray = img.convert("L")
        gray_arr = np.array(gray, dtype=np.float64)

        results.update(_compute_edge_density(gray_arr))
        results.update(_compute_sharpness(img))
        results.update(_compute_noise_analysis(img))
        results.update(_compute_histogram_analysis(img))
        results.update(_compute_ela(image_path))
        results.update(_compute_lighting_consistency(img))
        results.update(_compute_color_distribution(img))
        results.update(_compute_texture_consistency(img))

        # Add compression analysis summary.
        jpeg_q = results.get("jpeg_quality", 0)
        if jpeg_q > 0:
            if jpeg_q >= 95:
                results["compression_analysis"] = "High Quality / Minimal Compression"
            elif jpeg_q >= 80:
                results["compression_analysis"] = "Standard JPEG Compression"
            elif jpeg_q >= 60:
                results["compression_analysis"] = "Moderate Compression Artifacts"
            else:
                results["compression_analysis"] = "Heavy Compression (Artifacts Likely)"
        else:
            results["compression_analysis"] = "Lossless Format (No JPEG Compression)"

        # Add pixel irregularity summary based on noise + edge analysis.
        noise_score = results.get("noise_score", 0)
        edge_density = results.get("edge_density", 0)
        if noise_score < 2.0 and edge_density < 20:
            results["pixel_irregularity"] = "Low (Smooth / Possible Synthetic)"
        elif noise_score > 20 or edge_density > 70:
            results["pixel_irregularity"] = "High (Degraded / Artifact-Heavy)"
        else:
            results["pixel_irregularity"] = "Normal"

        # Add GAN artifacts heuristic based on texture + histogram.
        texture_label = results.get("texture_consistency", "")
        hist_label = results.get("histogram_distribution", "")
        if "Uniform" in texture_label or "Artificial" in hist_label:
            results["gan_artifacts"] = "Possible (Uniform Texture / Peaked Histogram)"
        elif "Synthetic" in texture_label:
            results["gan_artifacts"] = "Likely (Synthetic Texture Pattern)"
        else:
            results["gan_artifacts"] = "None Detected"

        logger.info(
            "Forensic analysis complete: %d indicators extracted for %s",
            len(results),
            os.path.basename(image_path),
        )

        return results

    except Exception as exc:
        logger.error("Image forensics analysis failed: %s", exc)
        return {"error": f"Forensic analysis failed: {exc}"}