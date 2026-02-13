"""Email (.eml) parser for phishing analysis.

Parses email headers, body, attachments, and extracts IOCs
relevant to phishing detection.
"""

import email
import email.policy
import re
import uuid
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Optional
from .sysmon import AlertData
from .ioc_extractor import IOCExtractor


class EmailParser:
    """Parses .eml email files for phishing analysis."""

    # Suspicious indicators in emails
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".js",
        ".wsf", ".hta", ".cpl", ".msi", ".dll", ".ps1", ".jar",
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    }

    PHISHING_KEYWORDS = [
        "urgent", "verify your account", "suspended", "click here",
        "confirm your identity", "unusual activity", "security alert",
        "password expired", "update your payment", "invoice attached",
        "wire transfer", "bitcoin", "gift card", "act now",
        "limited time", "congratulations", "you've won",
    ]

    @classmethod
    def parse(cls, content: str) -> AlertData:
        """Parse email content (.eml format or raw email text).

        Args:
            content: Raw email content as string.

        Returns:
            Normalized AlertData object with phishing-relevant fields.
        """
        alert = AlertData(
            raw_content=content,
            alert_type="phishing",
        )

        raw_fields = {}

        try:
            msg = email.message_from_string(content, policy=email.policy.default)
        except Exception:
            # If email parsing fails, treat as raw text
            alert.extracted_iocs = IOCExtractor.extract(content)
            return alert

        # Extract headers
        raw_fields["from"] = str(msg.get("From", ""))
        raw_fields["to"] = str(msg.get("To", ""))
        raw_fields["subject"] = str(msg.get("Subject", ""))
        raw_fields["date"] = str(msg.get("Date", ""))
        raw_fields["return_path"] = str(msg.get("Return-Path", ""))
        raw_fields["reply_to"] = str(msg.get("Reply-To", ""))
        raw_fields["message_id"] = str(msg.get("Message-ID", ""))
        raw_fields["x_mailer"] = str(msg.get("X-Mailer", ""))
        raw_fields["content_type"] = str(msg.get("Content-Type", ""))

        # Extract authentication headers
        raw_fields["spf"] = str(msg.get("Received-SPF", ""))
        raw_fields["dkim"] = str(msg.get("DKIM-Signature", ""))
        raw_fields["dmarc"] = str(msg.get("Authentication-Results", ""))

        # Extract Received headers (trace route)
        received_headers = msg.get_all("Received", [])
        raw_fields["received_headers"] = [str(h) for h in received_headers]
        raw_fields["hop_count"] = len(received_headers)

        # Parse sender
        from_header = raw_fields["from"]
        email_match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", from_header)
        if email_match:
            alert.email_from = email_match.group(0)
            sender_domain = alert.email_from.split("@")[-1]
            raw_fields["sender_domain"] = sender_domain

        alert.email_subject = raw_fields["subject"]

        # Check for display name spoofing
        if from_header:
            display_match = re.match(r'"?([^"<]+)"?\s*<', from_header)
            if display_match:
                display_name = display_match.group(1).strip()
                raw_fields["display_name"] = display_name
                # Check if display name contains an email (spoofing attempt)
                if "@" in display_name:
                    raw_fields["display_name_spoofing"] = True

        # Parse date
        if raw_fields["date"]:
            try:
                alert.timestamp = parsedate_to_datetime(raw_fields["date"])
            except (ValueError, TypeError):
                pass

        # Extract body text
        body_parts = []
        html_parts = []
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disp = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if filename:
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(part.get_payload(decode=True) or b""),
                    })
                elif content_type == "text/plain":
                    try:
                        body_parts.append(part.get_content())
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(payload.decode("utf-8", errors="replace"))
                elif content_type == "text/html":
                    try:
                        html_parts.append(part.get_content())
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_parts.append(payload.decode("utf-8", errors="replace"))
        else:
            content_type = msg.get_content_type()
            try:
                body_text = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                body_text = payload.decode("utf-8", errors="replace") if payload else ""

            if content_type == "text/html":
                html_parts.append(body_text)
            else:
                body_parts.append(body_text)

        raw_fields["body_text"] = "\n".join(body_parts)
        raw_fields["body_html"] = "\n".join(html_parts)
        raw_fields["attachments"] = attachments

        # Check for suspicious attachments
        suspicious_attachments = []
        for att in attachments:
            fname = att["filename"].lower()
            for ext in cls.SUSPICIOUS_EXTENSIONS:
                if fname.endswith(ext):
                    suspicious_attachments.append(att)
                    break
            # Double extension check (e.g., "invoice.pdf.exe")
            parts = fname.rsplit(".", 2)
            if len(parts) >= 3:
                suspicious_attachments.append(att)
        raw_fields["suspicious_attachments"] = suspicious_attachments

        # Check for phishing keywords
        full_text = (raw_fields["subject"] + " " + raw_fields["body_text"] + " " + raw_fields["body_html"]).lower()
        found_keywords = [kw for kw in cls.PHISHING_KEYWORDS if kw in full_text]
        raw_fields["phishing_keywords_found"] = found_keywords

        # Extract URLs from HTML (look for href attributes)
        url_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        html_urls = url_pattern.findall(" ".join(html_parts))
        raw_fields["html_urls"] = html_urls

        # Check for URL/text mismatch (display text says one URL, href is different)
        link_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>', re.IGNORECASE)
        mismatched_links = []
        for href, display in link_pattern.findall(" ".join(html_parts)):
            if display.startswith("http") and href != display:
                mismatched_links.append({"display": display, "actual": href})
        raw_fields["mismatched_links"] = mismatched_links

        # SPF/DKIM analysis
        auth_results = raw_fields.get("dmarc", "").lower()
        raw_fields["spf_pass"] = "spf=pass" in auth_results
        raw_fields["dkim_pass"] = "dkim=pass" in auth_results

        alert.raw_fields = raw_fields

        # Extract all IOCs from email content
        all_text = " ".join([
            content,
            raw_fields["body_text"],
            raw_fields["body_html"],
            " ".join(html_urls),
        ])
        alert.extracted_iocs = IOCExtractor.extract(all_text)

        # Extract any URLs found
        url_iocs = [ioc for ioc in alert.extracted_iocs if ioc.ioc_type.value == "url"]
        if url_iocs:
            alert.url = url_iocs[0].value

        # Extract domains
        domain_iocs = [ioc for ioc in alert.extracted_iocs if ioc.ioc_type.value == "domain"]
        if domain_iocs:
            alert.domain = domain_iocs[0].value

        return alert

    @classmethod
    def can_parse(cls, content: str) -> bool:
        """Check if content looks like an email."""
        indicators = ["From:", "Subject:", "Date:", "MIME-Version:", "Content-Type:", "Received:"]
        return sum(1 for ind in indicators if ind in content) >= 3
