import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from ml.config import DATASET_DIR
from ml.features.url_features import extract_base_domain

logger = logging.getLogger(__name__)


class DatasetInspector:
    """
    Inspects, validates, and profiles the CompPhish Version 4 dataset directory.
    Operates without hardcoded assumptions on filenames or column names.
    """

    def __init__(self, dataset_dir: Path = DATASET_DIR):
        self.dataset_dir = Path(dataset_dir)

    def find_dataset_files(self) -> List[Path]:
        """Discovers all tabular and data files in the dataset directory."""
        if not self.dataset_dir.exists():
            return []
        
        valid_exts = {".csv", ".parquet", ".json", ".tsv", ".txt", ".pkl", ".joblib", ".zip", ".tar", ".gz"}
        files = []
        for p in self.dataset_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in valid_exts and p.name != "README.md":
                files.append(p)
        return files

    def inspect(self) -> Dict[str, Any]:
        """
        Runs comprehensive inspection of the CompPhish V4 directory.
        """
        files = self.find_dataset_files()
        if not files:
            print("============================================================")
            print("CompPhish V4 dataset not found in data/compPhish_v4/.")
            print("Training is intentionally skipped.")
            print("============================================================")
            return {"status": "NOT_FOUND", "files": []}

        print("============================================================")
        print("CompPhish V4 Dataset Inspection Report")
        print("============================================================")
        print(f"Directory: {self.dataset_dir}")
        print(f"Discovered Files ({len(files)}):")
        
        for f in files:
            size_mb = f.stat().st_size / (1024 * 1024)
            print(f"  - {f.name} ({size_mb:.2f} MB)")

        # Inspect the primary tabular file (CSV or Parquet)
        tabular_files = [f for f in files if f.suffix.lower() in (".csv", ".parquet", ".tsv")]
        if not tabular_files:
            print("\nNo CSV or Parquet files detected.")
            return {"status": "NO_TABULAR_DATA", "files": [str(f) for f in files]}

        target_file = tabular_files[0]
        print(f"\nAnalyzing primary tabular dataset: {target_file.name}")

        try:
            if target_file.suffix.lower() == ".parquet":
                df = pd.read_parquet(target_file)
            else:
                df = pd.read_csv(target_file, low_memory=False)
        except Exception as e:
            print(f"Error reading dataset file: {e}")
            return {"status": "READ_ERROR", "error": str(e)}

        print(f"Dataset Shape: {df.shape[0]} rows x {df.shape[1]} columns")

        # Column discovery
        cols = list(df.columns)
        print(f"\nDiscovered Columns ({len(cols)}):")
        for i, col in enumerate(cols[:30]):
            print(f"  [{i+1}] {col} ({df[col].dtype})")
        if len(cols) > 30:
            print(f"  ... and {len(cols) - 30} more columns")

        # Target label candidate detection
        label_candidates = [c for c in cols if c.lower() in ("label", "target", "class", "result", "is_phishing", "phishing", "status", "type")]
        detected_label = label_candidates[0] if label_candidates else None
        print(f"\nDetected Target Label Column: {detected_label}")
        if detected_label:
            dist = df[detected_label].value_counts().to_dict()
            print(f"Class Distribution: {dist}")

        # URL column candidate detection
        url_candidates = [c for c in cols if c.lower() in ("url", "urls", "domain", "link", "website", "address")]
        detected_url = url_candidates[0] if url_candidates else None
        print(f"Detected URL Column: {detected_url}")

        # HTML column candidate detection
        html_candidates = [c for c in cols if c.lower() in ("html", "source", "body", "page_source", "dom", "raw_html")]
        detected_html = html_candidates[0] if html_candidates else None
        print(f"Detected HTML Column: {detected_html}")

        # Missing values check
        missing = df.isnull().sum()
        missing_cols = missing[missing > 0]
        print(f"\nColumns with Missing Values: {len(missing_cols)}")
        if len(missing_cols) > 0:
            for c, cnt in missing_cols.head(10).items():
                print(f"  - {c}: {cnt} missing ({cnt / len(df) * 100:.1f}%)")

        # Duplicate URLs and Domains check
        if detected_url:
            num_dup_urls = df[detected_url].duplicated().sum()
            print(f"\nDuplicate URLs in Dataset: {num_dup_urls}")

            # Extract base domains for leakage check
            sample_domains = df[detected_url].dropna().astype(str).apply(lambda u: extract_base_domain(u.split("/")[2] if "//" in u else u))
            num_unique_domains = sample_domains.nunique()
            print(f"Unique Base Domains: {num_unique_domains}")

        print("============================================================")
        return {
            "status": "INSPECTED",
            "file": str(target_file),
            "shape": df.shape,
            "columns": cols,
            "detected_label": detected_label,
            "detected_url": detected_url,
            "detected_html": detected_html
        }


if __name__ == "__main__":
    inspector = DatasetInspector()
    inspector.inspect()
