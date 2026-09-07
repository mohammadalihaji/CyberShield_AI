import socket
import ipaddress
import logging
import time
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import requests

from ml.config import (
    REQUEST_TIMEOUT,
    MAX_REDIRECTS,
    MAX_HTML_SIZE,
    USER_AGENT,
    ALLOWED_SCHEMES,
    BLOCKED_HOSTNAMES,
    METADATA_IPS
)
from ml.features.url_features import extract_base_domain

logger = logging.getLogger(__name__)


class SSRFSecurityException(Exception):
    """Raised when a request targets a private, loopback, or metadata address."""
    pass


@dataclass
class FetchResult:
    """Encapsulates the result of a safe webpage fetch operation."""
    success: bool
    url: str
    final_url: str = ""
    status_code: Optional[int] = None
    html_content: str = ""
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    redirect_count: int = 0
    domain_changed: bool = False
    response_time_ms: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    is_tls: bool = False
    content_type: str = ""


def is_ip_disallowed(ip_str: str) -> bool:
    """
    Evaluates whether an IP address belongs to loopback, private, link-local,
    multicast, unspecified, or cloud metadata ranges.
    """
    if not ip_str:
        return True

    # Check explicit metadata IP blocklist
    if ip_str in METADATA_IPS:
        return True

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    return (
        ip.is_loopback or
        ip.is_private or
        ip.is_link_local or
        ip.is_multicast or
        ip.is_reserved or
        ip.is_unspecified
    )


def validate_hostname_safe(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses and checks for SSRF vulnerabilities.
    Returns list of safe resolved IP strings, or raises SSRFSecurityException.
    """
    if not hostname:
        raise SSRFSecurityException("Empty hostname.")

    hostname_clean = hostname.lower().strip()
    if hostname_clean in BLOCKED_HOSTNAMES:
        raise SSRFSecurityException(f"Destination hostname '{hostname_clean}' is in the SSRF blocklist.")

    # Direct IP string validation
    try:
        ip = ipaddress.ip_address(hostname_clean)
        if is_ip_disallowed(str(ip)):
            raise SSRFSecurityException(f"Destination IP address {ip} is restricted (private/loopback/metadata).")
        return [str(ip)]
    except ValueError:
        pass

    # Resolve hostname via DNS
    try:
        addr_info = socket.getaddrinfo(hostname_clean, None)
    except socket.gaierror as e:
        raise SSRFSecurityException(f"DNS resolution failed for hostname '{hostname_clean}': {e}")
    except Exception as e:
        raise SSRFSecurityException(f"Socket resolution error for '{hostname_clean}': {e}")

    resolved_ips = []
    for info in addr_info:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        if is_ip_disallowed(ip_str):
            raise SSRFSecurityException(f"Hostname '{hostname_clean}' resolved to disallowed IP address: {ip_str}")
        resolved_ips.append(ip_str)

    if not resolved_ips:
        raise SSRFSecurityException(f"No valid IP addresses resolved for hostname '{hostname_clean}'.")

    return resolved_ips


class SafeWebpageFetcher:
    """
    SSRF-protected HTTP client for safely fetching HTML documents.
    Enforces scheme validation, DNS resolution checks, redirect hop validation,
    response size limits, and timeouts.
    """

    def __init__(
        self,
        timeout: int = REQUEST_TIMEOUT,
        max_redirects: int = MAX_REDIRECTS,
        max_size: int = MAX_HTML_SIZE,
        user_agent: str = USER_AGENT
    ):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_size = max_size
        self.user_agent = user_agent

    def fetch(self, target_url: str) -> FetchResult:
        """
        Safely fetches the HTML content of the target URL.
        """
        start_time = time.time()
        raw_url = target_url.strip()

        # Scheme validation before prefixing
        if ":" in raw_url:
            init_scheme = raw_url.split(":")[0].lower()
            if init_scheme not in ALLOWED_SCHEMES and not raw_url.startswith(("//", "/")):
                return FetchResult(
                    success=False,
                    url=target_url,
                    final_url=raw_url,
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=f"Disallowed scheme '{init_scheme}'. Only HTTP and HTTPS are permitted."
                )

        current_url = raw_url
        if not current_url.startswith(("http://", "https://")):
            current_url = "https://" + current_url

        redirect_chain: List[Dict[str, Any]] = []
        initial_parsed = urlparse(current_url)
        initial_domain = extract_base_domain(initial_parsed.hostname or "")

        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        for hop_index in range(self.max_redirects + 1):
            parsed = urlparse(current_url)

            # Scheme validation
            if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                return FetchResult(
                    success=False,
                    url=target_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    redirect_count=len(redirect_chain),
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=f"Disallowed scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
                )

            # Hostname and SSRF validation
            hostname = parsed.hostname
            if not hostname:
                return FetchResult(
                    success=False,
                    url=target_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    redirect_count=len(redirect_chain),
                    response_time_ms=(time.time() - start_time) * 1000,
                    error="Invalid or missing hostname in URL."
                )

            try:
                validate_hostname_safe(hostname)
            except SSRFSecurityException as e:
                logger.warning(f"SSRF protection blocked fetch for {current_url}: {e}")
                return FetchResult(
                    success=False,
                    url=target_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    redirect_count=len(redirect_chain),
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=f"Security Policy: {e}"
                )

            # Perform non-redirecting GET request
            try:
                response = session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True
                )
            except requests.exceptions.Timeout:
                return FetchResult(
                    success=False,
                    url=target_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    redirect_count=len(redirect_chain),
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=f"Connection timed out after {self.timeout} seconds."
                )
            except requests.exceptions.RequestException as e:
                return FetchResult(
                    success=False,
                    url=target_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    redirect_count=len(redirect_chain),
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=f"HTTP request error: {str(e)}"
                )

            # Check for redirect status codes (301, 302, 303, 307, 308)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break
                
                next_url = urljoin(current_url, location)
                redirect_chain.append({
                    "hop": hop_index + 1,
                    "from_url": current_url,
                    "to_url": next_url,
                    "status_code": response.status_code,
                    "domain": extract_base_domain(urlparse(next_url).hostname or "")
                })

                if hop_index == self.max_redirects:
                    return FetchResult(
                        success=False,
                        url=target_url,
                        final_url=next_url,
                        status_code=response.status_code,
                        redirect_chain=redirect_chain,
                        redirect_count=len(redirect_chain),
                        response_time_ms=(time.time() - start_time) * 1000,
                        error=f"Excessive redirects: exceeded maximum limit of {self.max_redirects} hops."
                    )

                current_url = next_url
                continue

            # Reached final non-redirect response
            content_type = response.headers.get("Content-Type", "").lower()
            
            # Read content with byte limit enforcement
            chunks = []
            total_bytes = 0
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    chunks.append(chunk)
                    total_bytes += len(chunk)
                    if total_bytes > self.max_size:
                        break
            except Exception as e:
                logger.error(f"Error streaming response body for {current_url}: {e}")

            raw_bytes = b"".join(chunks)
            
            # Decode text
            encoding = response.encoding or "utf-8"
            try:
                html_text = raw_bytes.decode(encoding, errors="replace")
            except Exception:
                html_text = raw_bytes.decode("utf-8", errors="replace")

            final_parsed = urlparse(current_url)
            final_domain = extract_base_domain(final_parsed.hostname or "")
            domain_changed = (initial_domain != final_domain) if initial_domain and final_domain else False
            is_tls = final_parsed.scheme.lower() == "https"

            return FetchResult(
                success=True,
                url=target_url,
                final_url=current_url,
                status_code=response.status_code,
                html_content=html_text,
                redirect_chain=redirect_chain,
                redirect_count=len(redirect_chain),
                domain_changed=domain_changed,
                response_time_ms=round((time.time() - start_time) * 1000, 2),
                headers=dict(response.headers),
                is_tls=is_tls,
                content_type=content_type
            )

        return FetchResult(
            success=False,
            url=target_url,
            final_url=current_url,
            redirect_chain=redirect_chain,
            redirect_count=len(redirect_chain),
            response_time_ms=(time.time() - start_time) * 1000,
            error="Fetch loop terminated without reaching a destination."
        )
