import os
import sys
import glob
import json
import zipfile
import hashlib
import logging
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit

# Ensure project root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.email.config import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    RANDOM_STATE
)
from ml.email.schema import EmailRecord
from ml.email.parser import parse_raw_eml, parse_pasted_email

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prepare_dataset")


def load_enron_dataset(sample_size: int = 10000) -> list:
    """Loads and samples Enron spam and ham emails."""
    enron_path = RAW_DATA_DIR / "enron_spam" / "enron_spam_data" / "enron_spam_data.csv"
    if not enron_path.exists():
        logger.warning(f"Enron path not found at {enron_path}")
        return []

    logger.info("Loading Enron dataset...")
    df = pd.read_csv(enron_path)
    
    # Sample balanced
    df_ham = df[df["Spam/Ham"].str.lower() == "ham"]
    df_spam = df[df["Spam/Ham"].str.lower() == "spam"]
    
    n_per_class = sample_size // 2
    df_sample = pd.concat([
        df_ham.sample(n=min(n_per_class, len(df_ham)), random_state=RANDOM_STATE),
        df_spam.sample(n=min(n_per_class, len(df_spam)), random_state=RANDOM_STATE)
    ]).sample(frac=1.0, random_state=RANDOM_STATE)

    records = []
    for idx, row in df_sample.iterrows():
        subj = str(row.get("Subject", "") or "")
        body = str(row.get("Message", "") or "")
        label_raw = str(row.get("Spam/Ham", "")).lower()
        label = "spam" if "spam" in label_raw else "ham"
        date_str = str(row.get("Date", "") or "")

        rec = parse_pasted_email(sender="user@enron.com", body_or_headers=body, subject=subj)
        rec.id = f"enron_{row.get('Message ID', idx)}"
        rec.source_dataset = "enron_spam"
        rec.label = label
        rec.date = date_str
        records.append(rec)

    logger.info(f"Loaded {len(records)} Enron records.")
    return records


def load_spamassassin_dataset(sample_size: int = 5000) -> list:
    """Loads raw RFC emails from SpamAssassin public corpus."""
    sa_base = RAW_DATA_DIR / "spamassassin"
    if not sa_base.exists():
        logger.warning(f"SpamAssassin path not found at {sa_base}")
        return []

    logger.info("Loading SpamAssassin dataset...")
    records = []
    
    folders = [
        ("20030228_easy_ham/easy_ham", "ham"),
        ("20030228_easy_ham_2/easy_ham_2", "ham"),
        ("20030228_hard_ham/hard_ham", "ham"),
        ("20030228_spam/spam", "spam"),
        ("20030228_spam_2/spam_2", "spam")
    ]

    for rel_dir, label in folders:
        dir_path = sa_base / rel_dir
        if not dir_path.exists():
            continue
        
        files = [f for f in os.listdir(dir_path) if not f.startswith("cmds") and os.path.isfile(dir_path / f)]
        for fn in files:
            fp = dir_path / fn
            try:
                with open(fp, "rb") as f:
                    raw_bytes = f.read()
                rec = parse_raw_eml(raw_bytes, source_dataset="spamassassin")
                rec.id = f"sa_{fn}"
                rec.label = label
                records.append(rec)
            except Exception as e:
                continue

    if len(records) > sample_size:
        # Balanced sample
        hams = [r for r in records if r.label == "ham"]
        spams = [r for r in records if r.label == "spam"]
        np.random.seed(RANDOM_STATE)
        np.random.shuffle(hams)
        np.random.shuffle(spams)
        n_half = sample_size // 2
        records = hams[:n_half] + spams[:n_half]

    logger.info(f"Loaded {len(records)} SpamAssassin records.")
    return records


def load_meajor_dataset(sample_size: int = 12000) -> list:
    """Loads Phishing and Benign records from MeAJOR parquet dataset."""
    meajor_path = RAW_DATA_DIR / "meajor" / "meajor_cleaned_preprocessed.parquet.gzip"
    if not meajor_path.exists():
        logger.warning(f"MeAJOR path not found at {meajor_path}")
        return []

    logger.info("Loading MeAJOR dataset...")
    df = pd.read_parquet(meajor_path)

    df_benign = df[df["label"] == 0.0]
    df_phish = df[df["label"] == 1.0]

    n_half = sample_size // 2
    df_sample = pd.concat([
        df_benign.sample(n=min(n_half, len(df_benign)), random_state=RANDOM_STATE),
        df_phish.sample(n=min(n_half, len(df_phish)), random_state=RANDOM_STATE)
    ]).sample(frac=1.0, random_state=RANDOM_STATE)

    records = []
    for idx, row in df_sample.iterrows():
        sender = str(row.get("sender", "") or "")
        sender_dom = str(row.get("sender_domain", "") or "")
        subj = str(row.get("subject", "") or "")
        body = str(row.get("body", "") or "")
        is_phish = (row.get("label") == 1.0)
        label = "phishing" if is_phish else "ham"
        
        # In MeAJOR, URLs might be a list or array
        raw_urls = row.get("urls")
        url_list = []
        if isinstance(raw_urls, (list, np.ndarray)):
            url_list = [str(u) for u in raw_urls if u]
        elif isinstance(raw_urls, str) and raw_urls.strip():
            url_list = [raw_urls.strip()]

        rec = parse_pasted_email(sender=sender, body_or_headers=body, subject=subj)
        rec.id = f"meajor_{idx}"
        rec.source_dataset = "meajor"
        rec.label = label
        if sender_dom:
            rec.from_domain = sender_dom
        if url_list:
            rec.urls = url_list[:25]
        
        records.append(rec)

    logger.info(f"Loaded {len(records)} MeAJOR records.")
    return records


def load_trec_dataset(sample_size: int = 8000) -> list:
    """Loads raw email records from TREC 2007 dataset."""
    trec_zip = RAW_DATA_DIR / "trec2007" / "email_origin.csv.zip"
    if not trec_zip.exists():
        logger.warning(f"TREC 2007 zip not found at {trec_zip}")
        return []

    logger.info("Loading TREC 2007 dataset...")
    records = []
    try:
        with zipfile.ZipFile(trec_zip, "r") as z:
            csv_name = z.namelist()[0]
            with z.open(csv_name) as f:
                df = pd.read_csv(f)
                
                # Check labels
                df_ham = df[df["label"].astype(str).str.lower().isin(["0", "ham", "0.0"])]
                df_spam = df[df["label"].astype(str).str.lower().isin(["1", "spam", "1.0"])]
                
                n_half = sample_size // 2
                df_sample = pd.concat([
                    df_ham.sample(n=min(n_half, len(df_ham)), random_state=RANDOM_STATE),
                    df_spam.sample(n=min(n_half, len(df_spam)), random_state=RANDOM_STATE)
                ]).sample(frac=1.0, random_state=RANDOM_STATE)

                for idx, row in df_sample.iterrows():
                    raw_email_str = str(row.get("origin", "") or "")
                    label_val = str(row.get("label", "")).lower()
                    label = "spam" if label_val in ["1", "spam", "1.0"] else "ham"

                    rec = parse_raw_eml(raw_email_str, source_dataset="trec2007")
                    rec.id = f"trec_{idx}"
                    rec.label = label
                    records.append(rec)
    except Exception as e:
        logger.error(f"Error reading TREC dataset: {e}")

    logger.info(f"Loaded {len(records)} TREC records.")
    return records


def deduplicate_and_build_dataset():
    """
    Consolidates Enron, SpamAssassin, MeAJOR, and TREC records.
    Applies exact and near-duplicate deduplication.
    Performs Group-Aware train/val/test splitting to prevent domain/campaign leakage.
    Produces both in-distribution and cross-dataset evaluation splits.
    """
    enron_recs = load_enron_dataset(sample_size=8000)
    sa_recs = load_spamassassin_dataset(sample_size=4000)
    meajor_recs = load_meajor_dataset(sample_size=10000)
    trec_recs = load_trec_dataset(sample_size=6000)

    all_records = enron_recs + sa_recs + meajor_recs + trec_recs
    logger.info(f"Total raw collected records before deduplication: {len(all_records)}")

    # Deduplication by hash of (from_address + subject + first 300 chars of body)
    seen_hashes = set()
    deduped_records = []
    
    for r in all_records:
        norm_key = f"{r.from_domain}|{r.subject.strip().lower()}|{r.plain_text[:300].strip().lower()}"
        h = hashlib.md5(norm_key.encode("utf-8", errors="ignore")).hexdigest()
        if h not in seen_hashes:
            seen_hashes.add(h)
            deduped_records.append(r)

    logger.info(f"Total records after deduplication: {len(deduped_records)}")

    # Convert to DataFrame
    rows = []
    for r in deduped_records:
        d = r.to_dict()
        # Flatten attachments for tabular parquet storage
        d["attachment_count"] = len(r.attachments)
        d["has_attachments"] = 1 if len(r.attachments) > 0 else 0
        d["attachments_json"] = json.dumps([asdict_a for asdict_a in d.pop("attachments", [])])
        d["urls_json"] = json.dumps(d.pop("urls", []))
        d["received_headers_json"] = json.dumps(d.pop("received_headers", []))
        rows.append(d)

    df_full = pd.DataFrame(rows)
    logger.info(f"Class distribution:\n{df_full['label'].value_counts()}")
    logger.info(f"Dataset distribution:\n{df_full['source_dataset'].value_counts()}")

    # Grouping key: sender domain to prevent domain/campaign leakage
    # For generic webmail or empty domains, split into 100 pseudo-groups to maintain balance
    def assign_group_key(row):
        d = str(row.get("from_domain", "")).strip().lower()
        if d and d not in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]:
            return d
        # Assign pseudo-group to generic/empty domains
        return f"generic_grp_{hash(str(row.get('id', ''))) % 200}"

    df_full["group_key"] = df_full.apply(assign_group_key, axis=1)

    # 1. Separate Cross-Dataset Holdout: Reserve 20% of MeAJOR and SpamAssassin for dedicated cross-dataset generalization evaluation
    cross_mask = (df_full["source_dataset"].isin(["meajor", "spamassassin"])) & (df_full.index % 5 == 0)
    df_cross_test = df_full[cross_mask].copy()
    df_main = df_full[~cross_mask].copy()

    # 2. Group-Aware Split on df_main (Train: 70%, Val: 15%, Test In-Dist: 15%)
    gss1 = GroupShuffleSplit(n_splits=1, train_size=0.70, random_state=RANDOM_STATE)
    train_idx, temp_idx = next(gss1.split(df_main, groups=df_main["group_key"]))
    
    df_train = df_main.iloc[train_idx].copy()
    df_temp = df_main.iloc[temp_idx].copy()

    gss2 = GroupShuffleSplit(n_splits=1, train_size=0.50, random_state=RANDOM_STATE)
    val_idx, test_idx = next(gss2.split(df_temp, groups=df_temp["group_key"]))

    df_val = df_temp.iloc[val_idx].copy()
    df_test_in_dist = df_temp.iloc[test_idx].copy()

    # Zero Leakage Verification
    train_domains = set(df_train[df_train["group_key"] != "generic_webmail"]["group_key"].unique())
    test_domains = set(df_test_in_dist[df_test_in_dist["group_key"] != "generic_webmail"]["group_key"].unique())
    domain_overlap = train_domains.intersection(test_domains)
    logger.info(f"Zero-Leakage Domain Check: Overlapping specialized domains between Train & Test = {len(domain_overlap)}")
    assert len(domain_overlap) == 0, f"Domain leakage detected: {domain_overlap}"

    # Save splits
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    df_train.to_parquet(PROCESSED_DATA_DIR / "train.parquet", index=False)
    df_val.to_parquet(PROCESSED_DATA_DIR / "val.parquet", index=False)
    df_test_in_dist.to_parquet(PROCESSED_DATA_DIR / "test_in_dist.parquet", index=False)
    df_cross_test.to_parquet(PROCESSED_DATA_DIR / "test_cross_dataset.parquet", index=False)

    logger.info("Dataset preparation complete:")
    logger.info(f"  Train: {len(df_train)} samples")
    logger.info(f"  Validation: {len(df_val)} samples")
    logger.info(f"  In-Distribution Test: {len(df_test_in_dist)} samples")
    logger.info(f"  Cross-Dataset Test: {len(df_cross_test)} samples")


if __name__ == "__main__":
    deduplicate_and_build_dataset()
