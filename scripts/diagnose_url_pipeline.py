"""
Diagnostic: Per-URL classification forensics for a Creatify-style marketing email.
Prints detailed evidence for every URL classified as MALICIOUS (contextual_risk >= 0.70).

Usage:
    python scripts/diagnose_url_pipeline.py [path-to-message.eml]

Run from CyberShield_AI root.
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.email.schema import EmailRecord, AttachmentMetadata
from ml.email.parser import parse_raw_eml
from ml.email.url_aggregator import EmailURLAggregator
from ml.email.url_classifier import (
    URLCategory, normalize_url, classify_single_url, detect_brand_impersonation,
    compute_contextual_url_risk,
)
from ml.features.url_features import extract_url_features
from ml.models.model_registry import ModelRegistry

# ─────────────────────────────────────────────────────────────────────────────
# Creatify-style marketing email — representative of what users paste/upload
# Contains: sender-domain links, ESP tracking links, Luma redirect, social links,
#           unsubscribe, preferences, Unsplash CDN image, UTM-tagged links, JWT token
# ─────────────────────────────────────────────────────────────────────────────
RAW_EML = """\
From: hello@mails.creatify.ai
To: subscriber@example.com
Reply-To: support@creatify.ai
Return-Path: <bounce@envelope.mails.creatify.ai>
Subject: Creatify AI — Your Weekly Product Digest
Date: Thu, 26 Sep 2026 10:00:00 +0000
Authentication-Results: spf=pass dkim=pass dmarc=pass
Content-Type: text/html; charset=utf-8

<html><head>
<style>.preheader{display:none !important;visibility:hidden;opacity:0;color:transparent;height:0;width:0;}</style>
</head><body>
<span class="preheader" style="display:none;font-size:0;">Your weekly AI video digest is here.</span>

<img src="https://mails.creatify.ai/open?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzNDU2IiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&recipient_id=abc123" width="1" height="1" />

<h1>Creatify AI Weekly Digest</h1>
<p>Hello Creator,</p>

<p><a href="https://creatify.ai">Visit Creatify</a></p>
<p><a href="https://creatify.ai/blog/ai-video-2026?utm_source=email&utm_medium=newsletter&utm_campaign=weekly_digest">Read the AI Video Blog</a></p>
<p><a href="https://creatify.ai/features/avatar?utm_source=email&utm_medium=newsletter">Explore AI Avatars</a></p>
<p><a href="https://creatify.ai/pricing?utm_source=email">View Pricing</a></p>

<p><a href="https://links.creatify.ai/c/abc123?destination=https%3A%2F%2Fcreatify.ai%2Fdemo&utm_source=email">Book a Demo</a></p>
<p><a href="https://links.creatify.ai/c/def456?destination=https%3A%2F%2Fcreatify.ai%2Fcase-studies&utm_source=email">View Case Studies</a></p>

<p><a href="https://link.luma-mail.com/click?url=https%3A%2F%2Flu.ma%2Fcreatify-webinar-2026&mc_cid=abc123">Register for Webinar</a></p>
<p><a href="https://link.luma-mail.com/click?url=https%3A%2F%2Flu.ma%2Fai-summit-2026">AI Summit Event</a></p>

<p><a href="https://twitter.com/creatifyai">Follow us on Twitter/X</a></p>
<p><a href="https://linkedin.com/company/creatify-ai">LinkedIn</a></p>
<p><a href="https://youtube.com/@creatifyai">YouTube Channel</a></p>
<p><a href="https://instagram.com/creatifyai">Instagram</a></p>

<img src="https://images.unsplash.com/photo-1729458223043-4b38eb63a4fe?w=600&q=80&fit=crop&auto=format&ixlib=rb-4.0.3" />
<img src="https://images.unsplash.com/photo-1659617754783-f8e6a4f3e2e2?w=400&q=80" />

<p><a href="https://mails.creatify.ai/unsubscribe?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJsaXN0X2lkIjoiY3JlYXRpZnkifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c">Unsubscribe</a></p>
<p><a href="https://mails.creatify.ai/preferences?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c">Manage Preferences</a></p>

<p><a href="https://creatify.ai/terms">Terms of Service</a></p>
<p><a href="https://creatify.ai/privacy">Privacy Policy</a></p>

</body></html>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Load model
# ─────────────────────────────────────────────────────────────────────────────
print("Loading CompPhish V4 URL model...")
registry = ModelRegistry()
models = registry.load_models()
url_model = models.get("url_model") if models.get("is_ready") else None
if url_model:
    print("  ✓ URL model loaded")
else:
    print("  ✗ URL model NOT available — heuristic fallback will be used")

# ─────────────────────────────────────────────────────────────────────────────
# Parse email
# ─────────────────────────────────────────────────────────────────────────────
if len(sys.argv) > 1:
    with open(sys.argv[1], "rb") as eml_file:
        record = parse_raw_eml(eml_file.read())
else:
    record = parse_raw_eml(RAW_EML)
sender_domain = record.from_domain.lower()
from ml.email.domain_analyzer import get_organizational_domain
sender_org = get_organizational_domain(sender_domain)

print(f"\nFrom: {record.from_address}")
print(f"From domain: {sender_domain} | Sender org: {sender_org}")
print(f"URLs extracted: {len(record.urls)}")
print("=" * 100)

# ─────────────────────────────────────────────────────────────────────────────
# Per-URL analysis
# ─────────────────────────────────────────────────────────────────────────────
malicious_rows = []
all_rows = []

seen = set()
unique_urls = []
for u in record.urls:
    norm = normalize_url(u)
    if norm and norm not in seen:
        seen.add(norm)
        unique_urls.append((u, norm))

print(f"Unique normalized URLs: {len(unique_urls)}\n")

for idx, (raw_url, norm_url) in enumerate(unique_urls, 1):
    classification = classify_single_url(norm_url, sender_domain=sender_domain)
    dest_url = classification.get("destination_url", norm_url)
    dest_domain = classification.get("destination_domain", "")
    org_domain = classification.get("org_domain", "")
    cat = classification.get("category", "DIRECT")

    brand_check = detect_brand_impersonation(dest_url, sender_domain=sender_domain)
    feat = extract_url_features(dest_url)

    raw_risk = 0.0
    if url_model and hasattr(url_model, "predict_single"):
        try:
            raw_risk = float(url_model.predict_single(feat))
        except Exception as e:
            raw_risk = 0.1
            print(f"  [WARN] model error for {norm_url}: {e}")

    contextual_risk, contextual_reason = compute_contextual_url_risk(
        classification=classification,
        brand_check=brand_check,
        url_features=feat,
        raw_model_risk=raw_risk,
        sender_org=sender_org
    )

    is_malicious = contextual_risk >= 0.70
    is_suspicious = 0.40 <= contextual_risk < 0.70

    verdict = "🔴 MALICIOUS" if is_malicious else ("🟡 SUSPICIOUS" if is_suspicious else "🟢 SAFE")

    row = {
        "idx": idx,
        "raw_url": raw_url,
        "norm_url": norm_url,
        "dest_url": dest_url,
        "org_domain": org_domain,
        "dest_domain": dest_domain,
        "category": cat,
        "is_tracking": classification.get("is_tracking", False),
        "is_social": cat == URLCategory.SOCIAL,
        "is_unsubscribe": cat == URLCategory.UNSUBSCRIBE,
        "is_cdn_asset": cat == URLCategory.IMAGE_CDN,
        "brand_detected": brand_check.get("brand", "") or "None",
        "brand_impersonation": brand_check.get("is_impersonation", False),
        "brand_severity": brand_check.get("severity", "SAFE"),
        "brand_domain_relationship": (
            "IMPERSONATION" if brand_check.get("is_impersonation", False)
            else "NO_BRAND_IMPERSONATION"
        ),
        "url_contains_ip": feat.get("url_contains_ip", 0),
        "has_punycode": feat.get("has_punycode", 0),
        "fake_tld": feat.get("fake_tld", 0),
        "suspicious_tld": feat.get("suspicious_tld_indicator", 0),
        "url_length": feat.get("url_length", 0),
        "suspicious_kw": feat.get("suspicious_keywords_count", 0),
        "special_chars": feat.get("number_of_special_characters", 0),
        "has_token_param": "token" in norm_url.lower() or "eyJ" in norm_url,
        "nonzero_model_features": {
            key: value for key, value in feat.items()
            if isinstance(value, (int, float)) and value != 0
        },
        "raw_compphish": round(raw_risk, 4),
        "contextual_risk": round(contextual_risk, 4),
        "contextual_reason": contextual_reason,
        "verdict": verdict,
    }
    all_rows.append(row)

    if is_malicious:
        malicious_rows.append(row)

# ─────────────────────────────────────────────────────────────────────────────
# Print Summary Table
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'IDX':>3}  {'VERDICT':<14}  {'CAT':<18}  {'RAW':>6}  {'CTX':>6}  {'DEST_DOMAIN':<30}  URL (truncated)")
print("-" * 140)
for r in all_rows:
    print(f"{r['idx']:>3}  {r['verdict']:<14}  {r['category']:<18}  {r['raw_compphish']:>6.4f}  {r['contextual_risk']:>6.4f}  {r['dest_domain']:<30}  {r['norm_url'][:60]}")

# ─────────────────────────────────────────────────────────────────────────────
# Print Full Forensics for MALICIOUS URLs only
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n\n{'='*100}")
print(f"MALICIOUS URL FORENSICS ({len(malicious_rows)} URLs)")
print(f"{'='*100}")

if not malicious_rows:
    print("✅ No malicious URLs detected.")
else:
    for r in malicious_rows:
        print(f"""
[URL #{r['idx']}] {r['verdict']}
  Raw URL         : {r['raw_url']}
  Normalized URL  : {r['norm_url']}
  Destination URL : {r['dest_url']}
  Org Domain      : {r['org_domain']}
  Dest Domain     : {r['dest_domain']}
  Category        : {r['category']}
  Is Tracking     : {r['is_tracking']}
  Is Social       : {r['is_social']}
  Is Unsubscribe  : {r['is_unsubscribe']}
  Is CDN Asset    : {r['is_cdn_asset']}
  Brand Detected  : {r['brand_detected']}
  Impersonation   : {r['brand_impersonation']} (severity={r['brand_severity']})
  Brand Relation  : {r['brand_domain_relationship']}
  ── CompPhish Features ──
  url_contains_ip : {r['url_contains_ip']}
  has_punycode    : {r['has_punycode']}
  fake_tld        : {r['fake_tld']}
  suspicious_tld  : {r['suspicious_tld']}
  url_length      : {r['url_length']}
  suspicious_kw   : {r['suspicious_kw']}
  special_chars   : {r['special_chars']}
  has_token/JWT   : {r['has_token_param']}
  Non-zero model features: {json.dumps(r['nonzero_model_features'], sort_keys=True)}
  ── Scores ──
  CompPhish Raw   : {r['raw_compphish']:.4f} ({r['raw_compphish']*100:.1f}%)
  Contextual Risk : {r['contextual_risk']:.4f} ({r['contextual_risk']*100:.1f}%)
  Final Class.    : {r['verdict']}
  Exact Evidence  : {r['contextual_reason']}
""")

# ─────────────────────────────────────────────────────────────────────────────
# Aggregates
# ─────────────────────────────────────────────────────────────────────────────
from ml.email.url_classifier import URLCategory
cat_counts = {}
for r in all_rows:
    cat_counts[r["category"]] = cat_counts.get(r["category"], 0) + 1

raw_risks = [r["raw_compphish"] for r in all_rows]
ctx_risks = [r["contextual_risk"] for r in all_rows]

print(f"\n{'='*100}")
print("AGGREGATE SUMMARY")
print(f"{'='*100}")
print(f"Total unique URLs     : {len(all_rows)}")
print(f"Category breakdown    : {json.dumps(cat_counts, indent=2)}")
print(f"Max CompPhish raw     : {max(raw_risks):.4f} ({max(raw_risks)*100:.1f}%) — this is email_max_url_risk fed to ensemble")
print(f"Avg CompPhish raw     : {sum(raw_risks)/len(raw_risks):.4f} ({sum(raw_risks)/len(raw_risks)*100:.1f}%)")
print(f"Max contextual risk   : {max(ctx_risks):.4f} ({max(ctx_risks)*100:.1f}%) — user-facing")
print(f"Malicious (ctx>=0.70) : {len([r for r in all_rows if r['contextual_risk'] >= 0.70])}")
print(f"Suspicious (ctx>=0.40): {len([r for r in all_rows if 0.40 <= r['contextual_risk'] < 0.70])}")
print(f"Safe (ctx<0.40)       : {len([r for r in all_rows if r['contextual_risk'] < 0.40])}")
