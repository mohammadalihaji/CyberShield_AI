import logging
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from ml.config import DATASET_DIR, RANDOM_STATE
from ml.dataset_inspector import DatasetInspector
from ml.features.url_features import extract_base_domain

logger = logging.getLogger(__name__)


class DatasetLoader:
    """
    Loads CompPhish V4 data and prepares domain-aware group splits to prevent data leakage.
    """

    def __init__(self, dataset_dir: Path = DATASET_DIR):
        self.dataset_dir = Path(dataset_dir)
        self.inspector = DatasetInspector(self.dataset_dir)

    def load_raw_dataset(self) -> Optional[pd.DataFrame]:
        """Loads raw dataset dataframe from discovered files."""
        files = self.inspector.find_dataset_files()
        tabular = [f for f in files if f.suffix.lower() in (".csv", ".parquet", ".tsv")]
        if not tabular:
            return None

        target = tabular[0]
        if target.suffix.lower() == ".parquet":
            return pd.read_parquet(target)
        else:
            return pd.read_csv(target, low_memory=False)

    def split_domain_aware(
        self,
        df: pd.DataFrame,
        url_col: str,
        test_size: float = 0.20,
        val_size: float = 0.10,
        random_state: int = RANDOM_STATE
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Splits dataset into Train, Validation, and Test partitions ensuring NO DOMAIN OVERLAP.
        """
        # Extract base domains for grouping
        domains = df[url_col].astype(str).apply(lambda u: extract_base_domain(u.split("/")[2] if "//" in u else u))
        df["_extracted_domain"] = domains

        # 1. Train+Val vs Test split by domain
        gss_test = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        train_val_idx, test_idx = next(gss_test.split(df, groups=df["_extracted_domain"]))

        df_train_val = df.iloc[train_val_idx].copy()
        df_test = df.iloc[test_idx].copy()

        # 2. Train vs Val split by domain
        adjusted_val_size = val_size / (1.0 - test_size)
        gss_val = GroupShuffleSplit(n_splits=1, test_size=adjusted_val_size, random_state=random_state)
        train_idx, val_idx = next(gss_val.split(df_train_val, groups=df_train_val["_extracted_domain"]))

        df_train = df_train_val.iloc[train_idx].copy()
        df_val = df_train_val.iloc[val_idx].copy()

        # Verify domain overlap is strictly zero
        train_domains = set(df_train["_extracted_domain"])
        val_domains = set(df_val["_extracted_domain"])
        test_domains = set(df_test["_extracted_domain"])

        overlap_tv = len(train_domains & val_domains)
        overlap_tt = len(train_domains & test_domains)
        overlap_vt = len(val_domains & test_domains)

        logger.info(f"Domain-aware Split: Train={len(df_train)}, Val={len(df_val)}, Test={len(df_test)}")
        logger.info(f"Domain Overlap Check: Train-Val={overlap_tv}, Train-Test={overlap_tt}, Val-Test={overlap_vt}")

        # Drop temporary helper column
        df_train = df_train.drop(columns=["_extracted_domain"])
        df_val = df_val.drop(columns=["_extracted_domain"])
        df_test = df_test.drop(columns=["_extracted_domain"])

        return df_train, df_val, df_test
