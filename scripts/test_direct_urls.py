"""Test DIRECT URL capping + phishing passthrough"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.email.url_classifier import classify_single_url, detect_brand_impersonation, compute_contextual_url_risk
from ml.features.url_features import extract_url_features
from ml.email.domain_analyzer import get_organizational_domain
from ml.models.model_registry import ModelRegistry

registry = ModelRegistry()
models = registry.load_models()
url_model = models.get('url_model') if models.get('is_ready') else None

sender_domain = 'mails.creatify.ai'
sender_org = get_organizational_domain(sender_domain)

direct_urls = [
    ('https://app.veed.io/edit/a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'Veed.io video editor'),
    ('https://notion.so/Creatify-AI-Roadmap-abc123def456', 'Notion doc'),
    ('https://loom.com/share/abc123def456789', 'Loom video'),
    ('https://share.hsforms.com/1ABCDEFGHIJKLMNOP', 'HubSpot form'),
    ('https://cdn.creatify.ai/assets/email-header-v2.png', 'CDN static asset'),
    # Phishing URLs (should remain high)
    ('https://paypal.security-portal.xyz/login/verify', 'Phishing: brand+path'),
    ('http://192.168.1.100/paypal/signin', 'Phishing: IP+brand+path'),
]

print(f"sender_org: {sender_org}")
fmt = "{:<32} {:<18} raw={:<8} ctx={:<8} [{:>4}]  {}"
print(fmt.format("LABEL", "CATEGORY", "SCORE", "SCORE", "VERD", "REASON"))
print("-" * 130)

for url, label in direct_urls:
    classification = classify_single_url(url, sender_domain=sender_domain)
    dest_url = classification.get("destination_url", url)
    brand_check = detect_brand_impersonation(dest_url, sender_domain=sender_domain)
    feat = extract_url_features(dest_url)
    raw_risk = float(url_model.predict_single(feat)) if url_model else 0.5
    ctx_risk, reason = compute_contextual_url_risk(classification, brand_check, feat, raw_risk, sender_org)
    cat = classification.get("category", "DIRECT")
    verdict = "MAL" if ctx_risk >= 0.70 else ("SUS" if ctx_risk >= 0.40 else "SAFE")
    print(fmt.format(label, cat, f"{raw_risk:.4f}", f"{ctx_risk:.4f}", verdict, reason[:65]))
