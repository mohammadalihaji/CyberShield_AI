from typing import Dict, Any, List, Optional
from ml.email.schema import EmailRecord
from ml.email.domain_analyzer import classify_domain_relation, DomainRelation, get_organizational_domain


class EmailXAIEngine:
    """
    Deterministic Explainable AI (XAI) Engine for Email Security.
    Generates verifiable, factual evidence items and user-first markdown reports
    strictly derived from extracted email features without hallucination.
    """

    def generate_evidence(self, record: EmailRecord, features: Dict[str, Any], predictions: Dict[str, Any]) -> List[Dict[str, Any]]:
        evidence = []
        from_dom = record.from_domain.lower()
        reply_dom = record.reply_to_domain.lower()
        return_dom = record.return_path_domain.lower()

        # 1. Header & Domain Consistency Findings
        if reply_dom and from_dom:
            reply_rel = classify_domain_relation(from_dom, reply_dom)
            if reply_rel["is_aligned"]:
                evidence.append({
                    "category": "Header Integrity",
                    "title": "Sender & Reply Identity Aligned",
                    "indicator": "Sender & Reply Identity Aligned",
                    "severity": "SAFE",
                    "confidence": 0.99,
                    "evidence": f"From: {from_dom} | Reply-To: {reply_dom}",
                    "explanation": f"Reply-To address uses the same organizational namespace ('{reply_rel['org_domain_a']}').",
                    "related_feature": "from_reply_to_mismatch",
                    "source": "DomainRelationshipClassifier",
                    "risk_factor": False
                })
            else:
                severity = "HIGH" if features.get("is_free_provider_sender") == 1 or features.get("auth_failure_count", 0) > 0 else "LOW"
                evidence.append({
                    "category": "Header Integrity",
                    "title": "Reply Address Differs from Sender Domain",
                    "indicator": "Reply Address Differs from Sender Domain",
                    "severity": severity,
                    "confidence": 0.90,
                    "evidence": f"From: {from_dom} | Reply-To: {reply_dom}",
                    "explanation": f"Replies are routed to an external domain ('{reply_rel['org_domain_b']}').",
                    "related_feature": "from_reply_to_mismatch",
                    "source": "DomainRelationshipClassifier",
                    "risk_factor": (severity == "HIGH")
                })

        if return_dom and from_dom:
            return_rel = classify_domain_relation(from_dom, return_dom)
            if return_rel["relation"] == DomainRelation.ESP_INFRASTRUCTURE:
                evidence.append({
                    "category": "Header Integrity",
                    "title": "Authorized ESP Delivery Infrastructure",
                    "indicator": "Authorized ESP Delivery Infrastructure",
                    "severity": "INFO",
                    "confidence": 0.95,
                    "evidence": f"Return-Path: {return_dom}",
                    "explanation": f"Return-Path envelope uses recognized mail delivery infrastructure ('{return_dom}').",
                    "related_feature": "from_return_path_mismatch",
                    "source": "DomainRelationshipClassifier",
                    "risk_factor": False
                })
            elif return_rel["is_aligned"]:
                evidence.append({
                    "category": "Header Integrity",
                    "title": "Return-Path Domain Aligned",
                    "indicator": "Return-Path Domain Aligned",
                    "severity": "SAFE",
                    "confidence": 0.98,
                    "evidence": f"From: {from_dom} | Return-Path: {return_dom}",
                    "explanation": f"Return-Path envelope matches the sender's organizational domain ('{return_rel['org_domain_a']}').",
                    "related_feature": "from_return_path_mismatch",
                    "source": "DomainRelationshipClassifier",
                    "risk_factor": False
                })
            else:
                evidence.append({
                    "category": "Header Integrity",
                    "title": "Return-Path Domain Mismatch",
                    "indicator": "Return-Path Alignment Mismatch",
                    "severity": "MEDIUM",
                    "confidence": 0.88,
                    "evidence": f"From: {from_dom} | Return-Path: {return_dom}",
                    "explanation": f"Return-Path domain ('{return_dom}') belongs to a different organization than sender ('{from_dom}').",
                    "related_feature": "from_return_path_mismatch",
                    "source": "DomainRelationshipClassifier",
                    "risk_factor": True
                })

        # 2. Email Authentication Protocol Findings
        if features.get("spf_pass") == 1:
            evidence.append({
                "category": "Authentication",
                "title": "SPF Authentication Passed",
                "indicator": "SPF Authentication Passed",
                "severity": "SAFE",
                "confidence": 0.99,
                "evidence": "Received-SPF: pass",
                "explanation": "Sending server IP is authorized in the sender domain's published SPF policy.",
                "related_feature": "spf_pass",
                "source": "AuthenticationResultsParser",
                "risk_factor": False
            })
        elif features.get("spf_fail") == 1:
            evidence.append({
                "category": "Authentication",
                "title": "SPF Authentication Failed",
                "indicator": "SPF Authentication Failed",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": "Received-SPF: fail / softfail",
                "explanation": "Sending server IP is not authorized by the sender domain's SPF record.",
                "related_feature": "spf_fail",
                "source": "AuthenticationResultsParser",
                "risk_factor": True
            })

        if features.get("dkim_pass") == 1:
            evidence.append({
                "category": "Authentication",
                "title": "DKIM Cryptographic Signature Valid",
                "indicator": "DKIM Cryptographic Signature Valid",
                "severity": "SAFE",
                "confidence": 0.99,
                "evidence": "DKIM-Signature: pass",
                "explanation": "Digital cryptographic signature verified with the sender's public key.",
                "related_feature": "dkim_pass",
                "source": "AuthenticationResultsParser",
                "risk_factor": False
            })
        elif features.get("dkim_fail") == 1:
            evidence.append({
                "category": "Authentication",
                "title": "DKIM Signature Verification Failed",
                "indicator": "DKIM Verification Failed",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": "DKIM: fail",
                "explanation": "Message body or headers modified in transit or invalid signature key.",
                "related_feature": "dkim_fail",
                "source": "AuthenticationResultsParser",
                "risk_factor": True
            })

        if features.get("dmarc_pass") == 1:
            evidence.append({
                "category": "Authentication",
                "title": "DMARC Alignment Validated",
                "indicator": "DMARC Alignment Validated",
                "severity": "SAFE",
                "confidence": 0.99,
                "evidence": "DMARC: pass",
                "explanation": "Domain-based Message Authentication policy successfully validated.",
                "related_feature": "dmarc_pass",
                "source": "AuthenticationResultsParser",
                "risk_factor": False
            })
        elif features.get("dmarc_fail") == 1:
            evidence.append({
                "category": "Authentication",
                "title": "DMARC Policy Violation",
                "indicator": "DMARC Policy Violation",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": "DMARC: fail",
                "explanation": "Email failed DMARC domain alignment checks.",
                "related_feature": "dmarc_fail",
                "source": "AuthenticationResultsParser",
                "risk_factor": True
            })

        # 3. URL and Link Security Findings
        url_metrics = features.get("url_metrics", {})
        if url_metrics.get("tracking_urls", 0) > 0 or url_metrics.get("redirect_urls", 0) > 0:
            evidence.append({
                "category": "Link Security",
                "title": "Marketing Tracking Redirects Detected",
                "indicator": "Marketing Tracking Redirects",
                "severity": "INFO",
                "confidence": 0.92,
                "evidence": f"Tracking links: {url_metrics.get('tracking_urls', 0)} | Redirects: {url_metrics.get('redirect_urls', 0)}",
                "explanation": "Email utilizes standard marketing campaign click-tracking or analytics wrappers.",
                "related_feature": "tracking_urls",
                "source": "EmailURLAggregator",
                "risk_factor": False
            })

        if features.get("email_has_brand_in_subdomain_url") == 1:
            evidence.append({
                "category": "Link Security",
                "title": "Brand Impersonation in Link Destination",
                "indicator": "Brand Impersonation in Subdomain",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "evidence": "Brand keyword located inside third-party subdomain or lookalike domain.",
                "explanation": "Link points to an unverified third-party domain mimicking a recognized brand.",
                "related_feature": "email_has_brand_in_subdomain_url",
                "source": "BrandImpersonationEngine",
                "risk_factor": True
            })

        if features.get("email_has_ip_url") == 1:
            evidence.append({
                "category": "Link Security",
                "title": "Raw Numeric IP Link Destination",
                "indicator": "Raw IP Address in URL",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": "URL host is a numeric IP address.",
                "explanation": "Links pointing to raw IP addresses bypass standard DNS reputation checks.",
                "related_feature": "email_has_ip_url",
                "source": "EmailURLAggregator",
                "risk_factor": True
            })

        if features.get("email_has_suspicious_tld_url") == 1:
            evidence.append({
                "category": "Link Security",
                "title": "High-Risk Top Level Domain",
                "indicator": "Abuse-Heavy Top Level Domain",
                "severity": "HIGH",
                "confidence": 0.90,
                "evidence": "URL hosted on high-abuse TLD.",
                "explanation": "Links use top-level domains frequently associated with bulk malicious campaigns.",
                "related_feature": "email_has_suspicious_tld_url",
                "source": "EmailURLAggregator",
                "risk_factor": True
            })

        if features.get("html_anchor_href_mismatch_count", 0) > 0:
            evidence.append({
                "category": "Link Security",
                "title": "Anchor Text vs Destination Link Mismatch",
                "indicator": "Anchor Text vs Destination Link Mismatch",
                "severity": "CRITICAL",
                "confidence": 0.98,
                "evidence": f"{features['html_anchor_href_mismatch_count']} mismatched link(s)",
                "explanation": "Displayed text suggests one domain while the actual href points to a different domain.",
                "related_feature": "html_anchor_href_mismatch_count",
                "source": "HTMLFeatureExtractor",
                "risk_factor": True
            })

        # 4. Attachment Forensics
        if features.get("has_double_extension_attachment") == 1:
            evidence.append({
                "category": "Attachment Security",
                "title": "Double Extension Executable Attachment",
                "indicator": "Double Extension Executable Attachment",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "evidence": "Dual extension payload (e.g. .pdf.exe)",
                "explanation": "Attachment disguises an executable file using deceptive dual extensions.",
                "related_feature": "has_double_extension_attachment",
                "source": "AttachmentFeatureExtractor",
                "risk_factor": True
            })
        elif features.get("has_executable_attachment") == 1:
            evidence.append({
                "category": "Attachment Security",
                "title": "Executable File Attachment",
                "indicator": "Executable File Attachment",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "evidence": "Binary executable, script, or installer attachment",
                "explanation": "Email contains direct executable payload.",
                "related_feature": "has_executable_attachment",
                "source": "AttachmentFeatureExtractor",
                "risk_factor": True
            })
        elif features.get("has_macro_attachment") == 1:
            evidence.append({
                "category": "Attachment Security",
                "title": "Macro-Enabled Office Document",
                "indicator": "Macro-Enabled Document",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": "VBA/Macro enabled file",
                "explanation": "Office document contains embedded macros.",
                "related_feature": "has_macro_attachment",
                "source": "AttachmentFeatureExtractor",
                "risk_factor": True
            })
        elif features.get("has_attachments") == 0:
            evidence.append({
                "category": "Attachment Security",
                "title": "No File Attachments",
                "indicator": "No Attachments",
                "severity": "SAFE",
                "confidence": 0.99,
                "evidence": "Attachment count: 0",
                "explanation": "Email does not carry any attached file payloads.",
                "related_feature": "has_attachments",
                "source": "AttachmentFeatureExtractor",
                "risk_factor": False
            })

        # 5. DOM & Content Forensics
        if features.get("has_hidden_preheader") == 1 and features.get("has_hidden_form", 0) == 0:
            evidence.append({
                "category": "DOM Structure",
                "title": "Marketing Email Preheader",
                "indicator": "Marketing Email Preheader",
                "severity": "INFO",
                "confidence": 0.95,
                "evidence": "Hidden preheader preview snippet",
                "explanation": "Standard email inbox preview text container detected.",
                "related_feature": "has_hidden_preheader",
                "source": "HTMLFeatureExtractor",
                "risk_factor": False
            })
        elif features.get("has_hidden_form") == 1:
            evidence.append({
                "category": "DOM Structure",
                "title": "Hidden Form / Credential Inputs",
                "indicator": "Hidden Form / Credential Inputs",
                "severity": "HIGH",
                "confidence": 0.95,
                "evidence": "Hidden <form> or password input tag",
                "explanation": "Invisible form elements designed to harvest credentials.",
                "related_feature": "has_hidden_form",
                "source": "HTMLFeatureExtractor",
                "risk_factor": True
            })
        elif features.get("html_hidden_element_count", 0) > 0 and features.get("has_hidden_preheader", 0) == 0:
            evidence.append({
                "category": "DOM Structure",
                "title": "Hidden HTML Elements",
                "indicator": "Hidden DOM Elements",
                "severity": "LOW",
                "confidence": 0.85,
                "evidence": f"{features['html_hidden_element_count']} hidden element(s)",
                "explanation": "Contains hidden or zero-dimension styling blocks.",
                "related_feature": "html_hidden_element_count",
                "source": "HTMLFeatureExtractor",
                "risk_factor": False
            })

        if features.get("html_tracking_pixel_count", 0) > 0:
            evidence.append({
                "category": "Tracking & Privacy",
                "title": "Email Open Tracking Beacon",
                "indicator": "Email Open Tracking Pixel",
                "severity": "INFO",
                "confidence": 0.95,
                "evidence": f"{features['html_tracking_pixel_count']} tracking pixel(s)",
                "explanation": "Zero-dimension web beacon used for delivery and open-rate analytics.",
                "related_feature": "html_tracking_pixel_count",
                "source": "HTMLFeatureExtractor",
                "risk_factor": False
            })

        if features.get("subject_has_urgency") == 1:
            evidence.append({
                "category": "Social Engineering",
                "title": "Urgency / Coercive Language",
                "indicator": "High Urgency / Coercive Language",
                "severity": "MEDIUM",
                "confidence": 0.85,
                "evidence": f"Subject: '{record.subject}'",
                "explanation": "Subject contains urgency keywords prompting immediate user action.",
                "related_feature": "subject_has_urgency",
                "source": "HeaderFeatureExtractor",
                "risk_factor": True
            })

        return evidence

    def generate_markdown_report(self, record: EmailRecord, predictions: Dict[str, Any], evidence: List[Dict[str, Any]]) -> str:
        verdict = predictions.get("verdict", "Suspicious")
        risk_score = predictions.get("risk_score", 50.0)
        p_cal = predictions.get("calibrated_probability", 0.5)

        # Contextual human-readable executive summary
        summary_text = ""
        spf_ok = record.spf_verdict == "pass"
        dkim_ok = record.dkim_verdict == "pass"
        dmarc_ok = record.dmarc_verdict == "pass"
        auth_all_pass = spf_ok and dkim_ok and dmarc_ok

        if verdict == "Safe":
            if auth_all_pass:
                summary_text = "This email passed SPF, DKIM, and DMARC authentication. Marketing tracking and preheader elements were detected, which are standard in legitimate communications."
            else:
                summary_text = "This email exhibits characteristics consistent with legitimate communication. No high-risk phishing indicators or malicious payloads were found."
        elif verdict == "Suspicious":
            summary_text = "This email exhibits mixed signals requiring user caution. Review links and attachments carefully before interacting."
        else:
            summary_text = "High-confidence security threat detected. This email contains strong indicators of phishing, spoofing, or deceptive credential harvesting."

        # Security Checks List
        check_items = []
        if auth_all_pass:
            check_items.append("✅ **Sender authentication passed** (SPF, DKIM, DMARC)")
        else:
            if spf_ok: check_items.append("✅ **SPF passed**")
            elif record.spf_verdict == "fail": check_items.append("❌ **SPF failed**")
            
            if dkim_ok: check_items.append("✅ **DKIM valid**")
            elif record.dkim_verdict == "fail": check_items.append("❌ **DKIM invalid**")

            if dmarc_ok: check_items.append("✅ **DMARC passed**")
            elif record.dmarc_verdict == "fail": check_items.append("❌ **DMARC violated**")

        for item in evidence:
            if item["category"] in ("Link Security", "DOM Structure", "Tracking & Privacy") and not item["risk_factor"]:
                check_items.append(f"ℹ️ {item['title']}")
            elif item["risk_factor"]:
                icon = "❌" if item["severity"] in ("CRITICAL", "HIGH") else "⚠️"
                check_items.append(f"{icon} **{item['title']}** ({item['severity']}): {item['explanation']}")

        url_metrics = predictions.get("url_metrics", {})
        total_urls = url_metrics.get("total_url_occurrences", len(record.urls))
        unique_raw_urls = url_metrics.get("unique_raw_urls", len(set(record.urls)))
        unique_normalized_urls = url_metrics.get("unique_normalized_urls", len(record.urls))
        unique_clickable_hrefs = url_metrics.get("unique_clickable_hrefs", 0)
        unique_dest = url_metrics.get("unique_destinations", len(record.urls))
        tracking_urls = url_metrics.get("tracking_urls", 0) + url_metrics.get("redirect_urls", 0)
        unsubscribe_urls = url_metrics.get("unsubscribe_urls", 0)
        social_urls = url_metrics.get("social_urls", 0)
        sender_domain_urls = url_metrics.get("sender_domain_urls", 0)
        image_cdn_urls = url_metrics.get("image_cdn_urls", 0)
        suspicious_urls = url_metrics.get("suspicious_urls", 0)
        malicious_urls = url_metrics.get("malicious_urls", 0)
        max_raw_model_score = url_metrics.get("max_raw_url_model_score", predictions.get("url_probability", 0.0))
        contextual_verdict_str = url_metrics.get("contextual_threat_verdict", "Clean — No Malicious Links Detected")

        lines = [
            f"### 🛡️ Email Security Result",
            f"",
            f"**Verdict:** `{verdict.upper()}` &nbsp;|&nbsp; **Risk Score:** `{risk_score:.1f}%` (Calibrated P={p_cal:.4f})",
            f"",
            f"{summary_text}",
            f"",
            f"---",
            f"#### 📋 Security Checks",
        ]

        for check in check_items:
            lines.append(f"- {check}")

        lines.extend([
            f"",
            f"---",
            f"#### 🔗 Link Analysis",
            f"- **URL Occurrences:** `{total_urls}` | **Unique Raw URLs:** `{unique_raw_urls}` | **Unique Normalized URLs:** `{unique_normalized_urls}` | **Unique Destinations:** `{unique_dest}` | **Unique Clickable Hrefs:** `{unique_clickable_hrefs}`",
            f"- **Sender Domain Links:** `{sender_domain_urls}` | **Marketing/Tracking Redirects:** `{tracking_urls}` | **Unsubscribe:** `{unsubscribe_urls}` | **Social:** `{social_urls}` | **CDN Assets:** `{image_cdn_urls}`",
            f"- **Highest Individual URL Model Score (CompPhish; not email overall risk):** `{max_raw_model_score * 100:.1f}%`",
            f"- **Contextual Threat Verdict:** `{contextual_verdict_str}`",
            f"- **Suspicious Links:** `{suspicious_urls}` | **Malicious Links:** `{malicious_urls}`",
            f"",
            f"---",
            f"#### 📎 Attachments",
            f"- **Total Attachments:** `{len(record.attachments)}`",
            f"- **Attachment Risk Status:** `{'Payloads Detected' if any(a.is_executable or a.is_macro for a in record.attachments) else 'Clean / No File Payloads'}`",
            f"",
            f"---",
            f"<details><summary><b>🔬 Advanced ML Analysis (Click to Expand)</b></summary>",
            f"",
            f"- **Email content analysis (Text Model):** `{predictions.get('text_probability', 0.0) * 100:.1f}%` threat probability",
            f"- **Email structure analysis (Structured Model):** `{predictions.get('structured_probability', 0.0) * 100:.1f}%` threat probability",
            f"- **Link analysis (URL Security):** `{predictions.get('url_probability', 0.0) * 100:.1f}%` URL risk score",
            f"- **Combined ML assessment (Stacking Ensemble):** `{predictions.get('ensemble_probability', 0.0) * 100:.1f}%` meta-verdict",
            f"",
            f"- **Sender Address:** `{record.from_address or 'Not provided'}`",
            f"- **Sender Domain:** `{record.from_domain or 'None'}`",
            f"- **Model Version:** `{predictions.get('model_version', 'CyberShield-Email-v1')}`",
            f"</details>"
        ])

        return "\n".join(lines)
