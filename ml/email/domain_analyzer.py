import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, Tuple, Optional, Set

# Standard multi-part TLDs across global registries
MULTI_PART_TLDS: Set[str] = {
    # UK
    "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "edu.nz", "geek.nz", "gen.nz",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ed.jp", "go.jp", "gr.jp", "ad.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "adm.br",
    # Canada
    "gc.ca", "ab.ca", "bc.ca", "mb.ca", "nb.ca", "nl.ca", "ns.ca", "nt.ca", "nu.ca", "on.ca", "pe.ca", "qc.ca", "sk.ca", "yk.ca",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "ac.za", "edu.za",
    # Mexico
    "com.mx", "org.mx", "edu.mx", "gob.mx", "net.mx",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg",
    # Other common ccTLD 2nd level domains
    "com.tr", "org.tr", "edu.tr", "gov.tr", "com.ar", "net.ar", "org.ar", "com.co", "net.co",
    "com.tw", "org.tw", "net.tw", "com.hk", "org.hk", "net.hk", "com.my", "org.my", "net.my",
    "com.ph", "org.ph", "net.ph", "com.pk", "org.pk", "net.pk", "com.ng", "org.ng", "net.ng"
}

# Known ESP and bulk mail delivery infrastructure providers
KNOWN_ESP_DOMAINS: Set[str] = {
    "sendgrid.net", "sendgrid.com", "mailgun.org", "mailgun.net", "mailgun.com",
    "mailchimp.com", "mcsv.net", "mandrillapp.com", "mandrill.com",
    "amazonses.com", "amazonaws.com", "sparkpostmail.com", "sparkpost.com",
    "hubspotemail.net", "hubspot.com", "hubspotstarter.net",
    "createsend.com", "cmail1.com", "cmail2.com", "cmail19.com", "cmail20.com",
    "klaviyomail.com", "klaviyo.com", "customeriomail.com", "customer.io",
    "intercom-mail.com", "intercom.io", "postmarkapp.com", "wildbit.com",
    "salesforce.com", "exacttarget.com", "marketo.org", "mktomail.com",
    "constantcontact.com", "rsys5.com", "responsys.net", "sailthru.com",
    "activehosted.com", "sendinblue.com", "brevo.com", "brevomail.com",
    "infusionsoft.com", "dripemail2.com", "campaign-archive.com", "createsend1.com",
    # Event & transactional email platforms
    "luma-mail.com", "lu.ma", "luma.co",
    "luma.com", "vialoops.com", "loops.so",
    "beehiiv.com", "convertkit.com", "ck.page",
    "substack.com", "substackcdn.com",
    "mailerlite.com", "mailersend.com",
    "getresponse.com", "moosend.com", "omnisend.com",
    "iterable.com", "sendloop.com", "benchmark.email",
    "hsforms.com", "hs-analytics.net", "hubspotlinks.com",
    "vero.co", "drip.com", "autopilotmail.com",
}



def extract_clean_hostname(url_or_domain: str) -> str:
    """Extracts lowercase stripped hostname without port, scheme, or trailing punctuation."""
    if not url_or_domain:
        return ""
    
    text = url_or_domain.strip().lower()
    
    if "@" in text and not text.startswith(("http://", "https://")):
        text = text.split("@")[-1]
        
    if "://" in text:
        try:
            parsed = urlparse(text)
            text = parsed.hostname or text
        except Exception:
            pass
            
    if ":" in text:
        text = text.split(":")[0]
        
    return text.strip().rstrip(".,;)>\"'").lstrip("<>")


def get_organizational_domain(hostname_or_url: str) -> str:
    """
    Extracts the registered organizational/base domain from a hostname or URL.
    Correctly recognizes multi-part TLDs (e.g. .co.uk, .com.au, .co.in).
    
    Examples:
      - 'hello@mails.creatify.ai' -> 'creatify.ai'
      - 'envelope.mails.creatify.ai' -> 'creatify.ai'
      - 'sub.example.co.uk' -> 'example.co.uk'
      - 'paypal-login.security-portal.xyz' -> 'security-portal.xyz'
      - '192.168.1.1' -> '192.168.1.1'
    """
    host = extract_clean_hostname(hostname_or_url)
    if not host:
        return ""

    # Check if raw IP
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


class DomainRelation:
    EXACT_MATCH = "EXACT_MATCH"
    SUBDOMAIN_MATCH = "SUBDOMAIN_MATCH"
    SAME_ORGANIZATIONAL_DOMAIN = "SAME_ORGANIZATIONAL_DOMAIN"
    ESP_INFRASTRUCTURE = "ESP_INFRASTRUCTURE"
    DIFFERENT_ORGANIZATIONAL_DOMAIN = "DIFFERENT_ORGANIZATIONAL_DOMAIN"
    INVALID_OR_MISSING = "INVALID_OR_MISSING"


def classify_domain_relation(domain_a: str, domain_b: str) -> Dict[str, Any]:
    """
    Evaluates the relationship between two domains (e.g., From domain vs Return-Path,
    From domain vs Reply-To, or Sender domain vs URL host).
    
    Returns structured relationship telemetry and alignment verdict.
    """
    host_a = extract_clean_hostname(domain_a)
    host_b = extract_clean_hostname(domain_b)

    if not host_a or not host_b:
        return {
            "relation": DomainRelation.INVALID_OR_MISSING,
            "is_aligned": False,
            "org_domain_a": "",
            "org_domain_b": "",
            "description": "One or both domains are missing or invalid."
        }

    # 1. Exact Match
    if host_a == host_b:
        org_a = get_organizational_domain(host_a)
        return {
            "relation": DomainRelation.EXACT_MATCH,
            "is_aligned": True,
            "org_domain_a": org_a,
            "org_domain_b": org_a,
            "description": f"Exact domain match ('{host_a}')."
        }

    org_a = get_organizational_domain(host_a)
    org_b = get_organizational_domain(host_b)

    # 2. Subdomain Match
    if host_a.endswith("." + host_b) or host_b.endswith("." + host_a):
        return {
            "relation": DomainRelation.SUBDOMAIN_MATCH,
            "is_aligned": True,
            "org_domain_a": org_a,
            "org_domain_b": org_b,
            "description": f"Hierarchical subdomain relationship ('{host_a}' and '{host_b}')."
        }

    # 3. Same Organizational Domain
    if org_a and org_b and org_a == org_b:
        return {
            "relation": DomainRelation.SAME_ORGANIZATIONAL_DOMAIN,
            "is_aligned": True,
            "org_domain_a": org_a,
            "org_domain_b": org_b,
            "description": f"Shared organizational root domain ('{org_a}')."
        }

    # 4. Known ESP / Mail Delivery Infrastructure
    if org_b in KNOWN_ESP_DOMAINS or any(host_b.endswith("." + esp) for esp in KNOWN_ESP_DOMAINS):
        return {
            "relation": DomainRelation.ESP_INFRASTRUCTURE,
            "is_aligned": True,
            "org_domain_a": org_a,
            "org_domain_b": org_b,
            "description": f"Authorized email service provider infrastructure ('{host_b}')."
        }

    # 5. Different Organizational Domain (Real Mismatch)
    return {
        "relation": DomainRelation.DIFFERENT_ORGANIZATIONAL_DOMAIN,
        "is_aligned": False,
        "org_domain_a": org_a,
        "org_domain_b": org_b,
        "description": f"Unrelated organizational domains ('{org_a}' vs '{org_b}')."
    }
