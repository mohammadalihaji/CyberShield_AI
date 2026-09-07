import os
import re
from urllib.parse import urlparse
from typing import Dict, Any, List
from bs4 import BeautifulSoup

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".vbs", ".apk", ".msi", ".cmd", ".ps1",
    ".jar", ".dmg", ".iso", ".hta", ".wsf", ".pif", ".reg", ".dll",
    ".com", ".cpl", ".msp", ".gadget"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}


def extract_download_features(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
    """
    Scans HTML for direct binary download links, executable attachments, and forced download attributes.
    """
    if not soup:
        return {
            "num_download_links": 0,
            "num_executable_downloads": 0,
            "has_executable_download": 0,
            "num_archive_downloads": 0,
            "has_auto_download_tag": 0
        }

    links = soup.find_all(["a", "area", "embed", "object"])
    
    num_downloads = 0
    num_executables = 0
    num_archives = 0
    has_auto_download = 0

    for el in links:
        href = (el.get("href") or el.get("src") or "").strip()
        has_dl_attr = el.has_attr("download")
        
        if has_dl_attr:
            has_auto_download = 1
            num_downloads += 1

        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        try:
            parsed = urlparse(href)
            path = parsed.path.lower()
            _, ext = os.path.splitext(path)
            
            if ext in DANGEROUS_EXTENSIONS:
                num_executables += 1
                num_downloads += 1
            elif ext in ARCHIVE_EXTENSIONS:
                num_archives += 1
                num_downloads += 1
        except Exception:
            pass

    return {
        "num_download_links": num_downloads,
        "num_executable_downloads": num_executables,
        "has_executable_download": 1 if num_executables > 0 else 0,
        "num_archive_downloads": num_archives,
        "has_auto_download_tag": has_auto_download
    }
