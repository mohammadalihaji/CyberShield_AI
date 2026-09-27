import re
import html
import logging
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, List, Optional, Set, Tuple

from ml.email.domain_analyzer import (
    get_organizational_domain,
    extract_clean_hostname,
    classify_domain_relation,
    KNOWN_ESP_DOMAINS
)

logger = logging.getLogger(__name__)

# Known social media platforms
SOCIAL_DOMAINS: Set[str] = {
    'twitter.com', 'x.com', 'linkedin.com', 'facebook.com', 'instagram.com',
    'youtube.com', 'github.com', 'discord.gg', 'discord.com', 'slack.com',
    'reddit.com', 'medium.com', 'tiktok.com', 'pinterest.com', 'threads.net'
}

# Trusted CDN / image hosting services (used for email assets, not phishing targets)
IMAGE_CDN_DOMAINS: Set[str] = {
    'unsplash.com', 'images.unsplash.com',
    'cloudinary.com', 'res.cloudinary.com',
    'imgix.net', 'fastly.net',
    'cdn.jsdelivr.net', 'jsdelivr.net',
    'gravatar.com',
    'googleusercontent.com', 'ggpht.com',
    'twimg.com', 'fbcdn.net',
    'amazonwebservices.com', 'cloudfront.net', 's3.amazonaws.com',
    'akamaized.net', 'akamai.net', 'akamaihd.net',
    'imgur.com', 'giphy.com',
    'pexels.com', 'pixabay.com',
}

# These hosts are image delivery endpoints, rather than their entire parent
# domains: c.vialoops.com is a click-tracking endpoint and must not be treated
# as an image CDN merely because images.vialoops.com is legitimate.
IMAGE_CDN_HOSTS: Set[str] = {
    'images.vialoops.com',
}

# CDN subdomain prefixes — if the leftmost subdomain is one of these,
# classify as IMAGE_CDN regardless of the parent domain
CDN_SUBDOMAIN_PREFIXES: Set[str] = {
    'cdn', 'static', 'assets', 'img', 'images', 'media', 'files',
    'content', 'res', 'resources', 'dl', 'download', 'dist',
}

# High-target brand dictionary: brand_id -> (official_domains, lookalikes)
HIGH_TARGET_BRANDS: Dict[str, Set[str]] = {
    'paypal': {'paypal.com', 'paypal.me', 'paypal-corp.com'},
    'apple': {'apple.com', 'icloud.com', 'appleid.apple.com'},
    'google': {'google.com', 'gmail.com', 'google.co.uk', 'google.ca', 'youtube.com', 'workspace.google.com'},
    'microsoft': {'microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'microsoftonline.com'},
    'netflix': {'netflix.com'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'},
    'facebook': {'facebook.com', 'meta.com', 'fb.com'},
    'instagram': {'instagram.com'},
    'chase': {'chase.com', 'jpmorganchase.com'},
    'wellsfargo': {'wellsfargo.com'},
    'bankofamerica': {'bankofamerica.com', 'bofa.com'},
    'binance': {'binance.com'},
    'coinbase': {'coinbase.com'},
    'dhl': {'dhl.com', 'dhl.de'},
    'fedex': {'fedex.com'},
    'ups': {'ups.com'},
    'steam': {'steampowered.com', 'steamcommunity.com'}
}

# Typosquatting patterns
TYPOSQUAT_PATTERNS = [
    (r'paypa[l1i]\.com', 'paypal.com'),
    (r'micros[0o]ft\.com', 'microsoft.com'),
    (r'app[l1i]e\.com', 'apple.com'),
    (r'g[0o]{2}g[l1i]e\.com', 'google.com'),
    (r'arnazon\.com', 'amazon.com'),
    (r'netf[l1i]x\.com', 'netflix.com'),
    (r'c[o0]inbase\.com', 'coinbase.com'),
    (r'b[i1]nance\.com', 'binance.com')
]

# Tracking redirect query parameters
REDIRECT_PARAMS = [
    'url', 'redirect', 'dest', 'destination', 'target', 'u', 'next', 'r',
    'goto', 'link', 'q', 'href', 'uri', 'target_url', 'to', 'endpoint',
    'location', 'out', 'ref'
]

# Subdomain prefixes commonly used by ESPs for click-tracking / link-wrapping
TRACKING_SUBDOMAINS: Set[str] = {
    'link', 'links', 'click', 'clicks', 'track', 'tracking', 'trk',
    'email', 'mail', 'em', 'url', 'go', 't', 'ct', 'm', 'c', 'e', 's',
    'r', 'q', 'clk', 'stat', 'open', 'beacon', 'redirect', 'out',
    'news', 'info', 'promo', 'notification', 'notify', 'send', 'delivery',
    'bounce', 'reply', 'noreply', 'no-reply', 'mailer', 'mails', 'newsletter',
    'updates', 'update', 'alert', 'alerts', 'campaign', 'campaigns',
    'message', 'messages', 'inbox', 'outbox', 'list', 'bulk'
}

# Known tracking/analytics path segments
TRACKING_PATHS: Set[str] = {
    '/click', '/track', '/c/', '/wf/click', '/e/c/', '/link/',
    '/open', '/beacon', '/pixel', '/t/', '/r/', '/go/', '/lt.php',
    '/trk/', '/click/', '/lm/', '/x/', '/redirect'
}

# Suspicious / abused TLD list
HIGH_RISK_TLDS: Set[str] = {
    '.xyz', '.top', '.tk', '.ml', '.cf', '.ga', '.gq', '.pw', '.cc',
    '.click', '.download', '.zip', '.review', '.country', '.kim', '.science',
    '.work', '.party', '.gdn', '.win', '.loan', '.date', '.faith', '.racing',
    '.bid', '.stream', '.trade', '.accountant', '.webcam', '.cricket', '.space',
    '.men', '.ninja', '.life'
}

# Phishing credential-harvest path keywords
PHISHING_PATH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'account', 'auth', 'update',
    'confirm', 'secure', 'password', 'credential', 'suspend', 'wallet',
    'recover', 'unlock', 'validate', 'restore', 'reset'
]


class URLCategory:
    DIRECT = 'DIRECT'
    TRACKING = 'TRACKING'
    REDIRECT = 'REDIRECT'
    UNSUBSCRIBE = 'UNSUBSCRIBE'
    SOCIAL = 'SOCIAL'
    IMAGE_CDN = 'IMAGE_CDN'
    SENDER_DOMAIN = 'SENDER_DOMAIN'
    IMAGE_TRACKING_PIXEL = 'IMAGE_TRACKING_PIXEL'
    SUSPICIOUS = 'SUSPICIOUS'
    MALICIOUS = 'MALICIOUS'


def normalize_url(raw_url: str) -> str:
    """
    Robustly normalizes raw URL strings:
    - Decodes HTML entities (&amp; -> &)
    - Performs double percent decoding (%2520 -> %20 -> ' ')
    - Normalizes schemes and hostnames to lowercase
    - Safely strips trailing punctuation
    """
    if not raw_url:
        return ''

    u = html.unescape(raw_url.strip())
    u = u.strip().rstrip(".,;)>\"'").lstrip("<>\"'")

    try:
        decoded_once = unquote(u)
        if '%' in decoded_once:
            u = unquote(decoded_once)
        else:
            u = decoded_once
    except Exception:
        pass

    if not u.startswith(('http://', 'https://')):
        u = 'https://' + u

    try:
        parsed = urlparse(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path and path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        query = parsed.query
        fragment = parsed.fragment
        rebuilt = f'{scheme}://{netloc}{path}'
        if query:
            rebuilt += f'?{query}'
        if fragment:
            rebuilt += f'#{fragment}'
        return rebuilt
    except Exception:
        return u


def extract_destination_from_tracking(url: str) -> Optional[str]:
    """
    Extracts underlying destination URL from a tracking wrapper or redirect parameter.
    Handles query-parameter redirects, percent-encoded destinations, and path-embedded URLs.
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=False)
        for p in REDIRECT_PARAMS:
            if p in params and params[p]:
                val = params[p][0]
                try:
                    val_decoded = unquote(val)
                except Exception:
                    val_decoded = val
                if val_decoded.startswith(('http://', 'https://')):
                    return normalize_url(val_decoded)
                elif 'http' in val_decoded:
                    sub_match = re.search(r'https?://[^\s&]+', val_decoded)
                    if sub_match:
                        return normalize_url(sub_match.group(0))

        # Path-based redirect: check if path segment decodes to a URL
        path = parsed.path
        try:
            path_decoded = unquote(path)
        except Exception:
            path_decoded = path
        url_in_path = re.search(r'https?://[^\s<>"]+', path_decoded)
        if url_in_path:
            return normalize_url(url_in_path.group(0))

    except Exception:
        pass
    return None


def is_tracking_subdomain(hostname: str) -> bool:
    """
    Returns True if the leftmost subdomain token of the hostname is a known
    marketing/tracking prefix (e.g. links.creatify.ai, click.brand.com).
    """
    if not hostname:
        return False
    parts = hostname.lower().split('.')
    if len(parts) >= 3:
        return parts[0] in TRACKING_SUBDOMAINS
    return False


def has_tracking_query_params(url: str) -> bool:
    """Returns True if the URL contains known marketing/analytics tracking parameters."""
    try:
        params = parse_qs(urlparse(url).query, keep_blank_values=False)
        TRACKING_PARAM_KEYS = {
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
            'mc_cid', 'mc_eid', '_hsenc', '_hsmi', 'hs_email', 'hs_src',
            'mkt_tok', 'elqTrackId', 'elqaid', 'elqat',
            'sb_referer_host', 'campaign_id', 'recipient_id', 'subscriber_id',
            'email_id', 'list_id', 'linkId', 'mid', 'rid',
            'cid', 'cmpid', 'cm_mmc', 'vgo_ee', 'fbclid', 'gclid'
        }
        return bool(TRACKING_PARAM_KEYS.intersection(params.keys()))
    except Exception:
        return False


def detect_brand_impersonation(url: str, sender_domain: str = '') -> Dict[str, Any]:
    """
    Multi-Factor Brand Impersonation Engine.
    Evaluates typosquatting, brand keywords in subdomains, and credential-harvest paths.
    """
    clean_url = normalize_url(url)
    parsed = urlparse(clean_url)
    hostname = parsed.hostname or ''
    org_domain = get_organizational_domain(hostname)
    sender_org = get_organizational_domain(sender_domain)

    # Typosquatting check
    for pattern, target in TYPOSQUAT_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE) and org_domain != target:
            return {
                'is_impersonation': True,
                'brand': target.split('.')[0],
                'severity': 'HIGH',
                'reason': f'Lookalike typosquatting domain impersonating {target} (actual domain: {org_domain}).'
            }

    # Sender brand alignment check FIRST — own org domain is never impersonation
    if sender_org and org_domain and sender_org == org_domain:
        return {
            'is_impersonation': False,
            'brand': '',
            'severity': 'SAFE',
            'reason': f'URL is owned by verified sender domain "{sender_org}".'
        }

    host_parts = hostname.lower().split('.')
    subdomain_tokens = host_parts[:-2] if len(host_parts) > 2 else []

    for brand, official_domains in HIGH_TARGET_BRANDS.items():
        if org_domain in official_domains:
            continue

        brand_regex = re.compile(rf'(^|[-_.@]){brand}([-_.@]|$)', re.IGNORECASE)
        subdomain_str = '.'.join(subdomain_tokens)
        if brand_regex.search(subdomain_str):
            return {
                'is_impersonation': True,
                'brand': brand,
                'severity': 'CRITICAL',
                'reason': f'Target brand "{brand}" embedded in third-party subdomain structure of "{org_domain}".'
            }

        path_lower = parsed.path.lower()
        if brand_regex.search(path_lower) and any(kw in path_lower for kw in PHISHING_PATH_KEYWORDS):
            return {
                'is_impersonation': True,
                'brand': brand,
                'severity': 'HIGH',
                'reason': f'Brand "{brand}" credential harvest path on unverified domain "{org_domain}".'
            }

    return {
        'is_impersonation': False,
        'brand': '',
        'severity': 'SAFE',
        'reason': 'No brand impersonation detected.'
    }


def classify_single_url(url: str, sender_domain: str = '', is_image_src: bool = False) -> Dict[str, Any]:
    """
    Classifies a single URL into its functional category and extracts full forensics.
    """
    clean_url = normalize_url(url)
    parsed = urlparse(clean_url)
    hostname = parsed.hostname or ''
    org_domain = get_organizational_domain(hostname)
    sender_org = get_organizational_domain(sender_domain)
    url_lower = clean_url.lower()

    # 1. Image Tracking Pixel
    if is_image_src:
        if any(h in url_lower for h in ['pixel', 'track', 'open', 'beacon', 'wf/open', 'e/o/']):
            return {
                'url': clean_url,
                'category': URLCategory.IMAGE_TRACKING_PIXEL,
                'hostname': hostname,
                'org_domain': org_domain,
                'destination_url': clean_url,
                'destination_domain': org_domain,
                'is_tracking': True,
                'is_suspicious': False,
                'description': 'Email open tracking pixel / web beacon.'
            }

    # Functional classifications deliberately precede sender-domain alignment:
    # sender-hosted click wrappers and preference endpoints need unwrapping.

    # 2. Social Links
    if org_domain in SOCIAL_DOMAINS:
        return {
            'url': clean_url,
            'category': URLCategory.SOCIAL,
            'hostname': hostname,
            'org_domain': org_domain,
            'destination_url': clean_url,
            'destination_domain': org_domain,
            'is_tracking': False,
            'is_suspicious': False,
            'description': f'Official social media channel ({org_domain}).'
        }

    # 4. Trusted Image CDN (explicit allowlist OR CDN subdomain prefix heuristic)
    is_known_cdn = (
        org_domain in IMAGE_CDN_DOMAINS or hostname in IMAGE_CDN_DOMAINS
        or hostname in IMAGE_CDN_HOSTS
    )
    # CDN subdomain heuristic: cdn.brand.com, static.brand.com, assets.brand.com, etc.
    host_parts = hostname.split('.')
    is_cdn_subdomain = len(host_parts) >= 3 and host_parts[0] in CDN_SUBDOMAIN_PREFIXES
    # Also check if the URL path looks like a static asset
    is_asset_path = bool(re.search(r'\.(png|jpg|jpeg|gif|svg|webp|ico|bmp|woff2?|ttf|eot|css|js|mp4|webm|pdf)(\?|$)', url_lower))

    if is_known_cdn or (is_cdn_subdomain and is_asset_path):
        return {
            'url': clean_url,
            'category': URLCategory.IMAGE_CDN,
            'hostname': hostname,
            'org_domain': org_domain,
            'destination_url': clean_url,
            'destination_domain': org_domain,
            'is_tracking': False,
            'is_suspicious': False,
            'description': f'Trusted image/asset CDN ({org_domain}).'
        }

    # 5. Unsubscribe / Preferences
    if any(kw in url_lower for kw in [
        'unsubscribe', 'optout', 'opt-out', 'preferences', 'list-manage',
        'email-settings', 'manage-subscriptions', 'email_preferences', 'emailpref'
    ]):
        return {
            'url': clean_url,
            'category': URLCategory.UNSUBSCRIBE,
            'hostname': hostname,
            'org_domain': org_domain,
            'destination_url': clean_url,
            'destination_domain': org_domain,
            'is_tracking': True,
            'is_suspicious': False,
            'description': 'Marketing subscription preference / unsubscribe link.'
        }

    # 6. Tracking / Redirect detection (multi-signal)
    destination = extract_destination_from_tracking(clean_url)
    is_esp = (org_domain in KNOWN_ESP_DOMAINS) or any(hostname.endswith('.' + esp) for esp in KNOWN_ESP_DOMAINS)
    is_tracking_path = any(
        parsed.path.lower().startswith(p) or ('/' + p.strip('/') + '/') in parsed.path.lower()
        for p in TRACKING_PATHS
    )
    is_tracking_sub = is_tracking_subdomain(hostname)
    has_tracking_params = has_tracking_query_params(clean_url)

    query_keys = set(parse_qs(parsed.query, keep_blank_values=False).keys())
    is_open_tracking_endpoint = (
        parsed.path.lower().rstrip('/') in {'/open', '/pixel', '/beacon'}
        and bool({'token', 'recipient_id', 'email_id', 'rid'}.intersection(query_keys))
    )
    # An ESP domain alone is not proof that a direct destination is a tracking
    # wrapper. Require a redirect/tracking form as well.
    is_tracking_wrapper = (
        destination or is_tracking_path or is_tracking_sub
        or has_tracking_params or is_open_tracking_endpoint
    )

    if is_tracking_wrapper:
        dest_url = destination or clean_url
        dest_host = urlparse(dest_url).hostname or ''
        dest_org = get_organizational_domain(dest_host)

        reason_parts = []
        if is_esp:
            reason_parts.append('known ESP infrastructure')
        if is_tracking_sub:
            reason_parts.append(f'tracking subdomain "{hostname.split(".")[0]}"')
        if is_tracking_path:
            reason_parts.append('tracking path segment')
        if has_tracking_params:
            reason_parts.append('marketing tracking parameters (UTM/token)')
        if destination:
            reason_parts.append(f'redirect -> "{dest_org or dest_host}"')
        reason_str = '; '.join(reason_parts) if reason_parts else 'click-tracking wrapper'

        logger.debug(
            f'URL: {clean_url} | classification: TRACKING_REDIRECT | '
            f'sender_org_match: {dest_org == sender_org} | '
            f'destination_domain: {dest_org} | tracking_detected: True | reason: {reason_str}'
        )

        return {
            'url': clean_url,
            'category': URLCategory.TRACKING if not destination else URLCategory.REDIRECT,
            'hostname': hostname,
            'org_domain': org_domain,
            'destination_url': dest_url,
            'destination_domain': dest_org,
            'is_tracking': True,
            'is_suspicious': False,
            'description': f'Marketing click-tracking redirect ({reason_str}).'
        }

    # 7. Direct Link (fallback — model will score this)
    if sender_org and org_domain and sender_org == org_domain:
        return {
            'url': clean_url,
            'category': URLCategory.SENDER_DOMAIN,
            'hostname': hostname,
            'org_domain': org_domain,
            'destination_url': clean_url,
            'destination_domain': org_domain,
            'is_tracking': False,
            'is_suspicious': False,
            'description': f'Direct link on verified sender domain "{sender_org}".'
        }

    return {
        'url': clean_url,
        'category': URLCategory.DIRECT,
        'hostname': hostname,
        'org_domain': org_domain,
        'destination_url': clean_url,
        'destination_domain': org_domain,
        'is_tracking': False,
        'is_suspicious': False,
        'description': f'Direct destination link to "{org_domain or hostname}".'
    }


def compute_contextual_url_risk(
    classification: Dict[str, Any],
    brand_check: Dict[str, Any],
    url_features: Dict[str, Any],
    raw_model_risk: float,
    sender_org: str = ''
) -> Tuple[float, str]:
    """
    Applies email-context intelligence on top of the raw CompPhish V4 ML score.

    The raw_model_risk is kept UNCHANGED for the ensemble meta-vector input.
    contextual_risk is the user-facing per-URL verdict ONLY.

    Rules:
    - Confirmed threats (impersonation, IP URL, punycode, high-risk TLD) -> amplify
    - Benign email-context categories (sender domain, social, CDN, tracking, unsubscribe) -> cap at 0.05
    - DIRECT links with no red flags -> pass through raw model score

    Returns: (contextual_risk: float, reason: str)
    """
    cat = classification.get('category', URLCategory.DIRECT)
    org_domain = classification.get('org_domain', '')
    has_ip = url_features.get('url_contains_ip', 0)
    has_punycode = url_features.get('has_punycode', 0)
    has_suspicious_tld = url_features.get('fake_tld', 0) or url_features.get('suspicious_tld_indicator', 0)
    is_impersonation = brand_check.get('is_impersonation', False)
    brand_severity = brand_check.get('severity', 'SAFE')

    # ── AMPLIFY: confirmed threats ────────────────────────────────────────────
    if is_impersonation and brand_severity in ('CRITICAL', 'HIGH'):
        score = max(raw_model_risk, 0.90)
        return round(score, 4), f'Brand impersonation detected: {brand_check.get("reason", "")}'

    if has_ip:
        score = max(raw_model_risk, 0.80)
        return round(score, 4), 'URL uses raw IP address instead of domain (strong phishing signal)'

    if has_punycode:
        score = max(raw_model_risk, 0.75)
        return round(score, 4), 'Punycode/IDN homoglyph domain (potential visual spoofing)'

    if has_suspicious_tld:
        score = max(raw_model_risk, 0.65)
        return round(score, 4), 'High-risk or abused TLD detected'

    # ── REDUCE: unambiguously benign email-context categories ─────────────────
    SAFE_CATEGORIES = {
        URLCategory.SENDER_DOMAIN,
        URLCategory.SOCIAL,
        URLCategory.IMAGE_CDN,
        URLCategory.UNSUBSCRIBE,
        URLCategory.IMAGE_TRACKING_PIXEL,
        URLCategory.TRACKING,
        URLCategory.REDIRECT,
    }

    if cat in SAFE_CATEGORIES:
        reason_map = {
            URLCategory.SENDER_DOMAIN: f'Verified sender domain link ({org_domain})',
            URLCategory.SOCIAL: f'Official social media platform ({org_domain})',
            URLCategory.IMAGE_CDN: f'Trusted asset CDN ({org_domain})',
            URLCategory.UNSUBSCRIBE: 'Marketing unsubscribe/preference link',
            URLCategory.IMAGE_TRACKING_PIXEL: 'Email open tracking pixel',
            URLCategory.TRACKING: 'Marketing click-tracking wrapper',
            URLCategory.REDIRECT: 'Click-tracking redirect to safe destination',
        }
        return 0.05, reason_map.get(cat, 'Benign email infrastructure link')

    # ── DIRECT: apply contextual interpretation of raw lexical score ─────────
    # CompPhish V4 is a lexical random forest. It assigns high scores to URLs
    # with high entropy, long paths, UUIDs, JWT tokens, and many special chars
    # — even on completely legitimate SaaS tool links (e.g. app.veed.io/edit/UUID).
    #
    # Without CONFIRMED semantic threat signals, a purely lexical high score
    # should NOT produce a MALICIOUS contextual verdict.
    #
    # Confirmed threat signals: brand impersonation, IP address, punycode,
    # suspicious/abused TLD, phishing path keywords.
    # These are already handled in the AMPLIFY section above.
    #
    # If we reach here with raw_model_risk >= 0.70, NO threat signals fired,
    # so we cap at SUSPICIOUS (0.55) to prevent false positives.

    url_str = classification.get('url', '')
    parsed_url = urlparse(url_str) if url_str else None
    path_lower = (parsed_url.path.lower() if parsed_url else '')

    has_phishing_keywords = any(kw in path_lower for kw in [
        'login', 'signin', 'sign-in', 'verify', 'account', 'auth', 'update',
        'confirm', 'secure', 'password', 'credential', 'suspend', 'wallet',
        'recover', 'unlock', 'validate', 'restore', 'reset'
    ])

    if has_phishing_keywords:
        # Phishing keywords in path on a 3rd party domain — trust the raw model
        return round(raw_model_risk, 4), f'Phishing keyword in URL path on external domain ({org_domain})'

    if raw_model_risk >= 0.70:
        # High lexical score but NO semantic threat signals — cap at SUSPICIOUS
        return 0.55, (
            f'CompPhish lexical score {raw_model_risk*100:.0f}% — capped at SUSPICIOUS '
            f'(no confirmed threat signals on {org_domain})'
        )

    # Low/medium raw score, no threats — pass through
    return round(raw_model_risk, 4), f'CompPhish V4 lexical score ({org_domain})'
