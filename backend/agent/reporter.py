"""Incident report generator.

Produces HTML and PDF investigation reports using Jinja2 templates.
"""

import os
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from config import config


class ReportGenerator:
    """Generates HTML and PDF incident reports."""

    def __init__(self):
        template_dir = Path(__file__).parent.parent / "reports" / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

    def generate_html(self, investigation_data: Dict, alert_id: str) -> str:
        """Generate an HTML incident report.

        Args:
            investigation_data: Complete investigation results.
            alert_id: The alert ID for file naming.

        Returns:
            Path to the generated HTML file.
        """
        config.init()
        output_path = config.REPORT_DIR / f"{alert_id}.html"

        template = self.env.get_template("report_template.html")
        html_content = template.render(
            alert_id=alert_id,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            **investigation_data,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(output_path)

    def generate_pdf(self, html_path: str, alert_id: str) -> Optional[str]:
        """Generate a PDF report from the HTML report.

        Args:
            html_path: Path to the HTML report.
            alert_id: The alert ID for file naming.

        Returns:
            Path to the generated PDF file, or None if generation fails.
        """
        config.init()
        output_path = config.REPORT_DIR / f"{alert_id}.pdf"

        try:
            from xhtml2pdf import pisa

            with open(html_path, "r", encoding="utf-8") as html_file:
                html_content = html_file.read()

            with open(output_path, "wb") as pdf_file:
                pisa_status = pisa.CreatePDF(html_content, dest=pdf_file)

            if pisa_status.err:
                return None

            return str(output_path)

        except ImportError:
            # xhtml2pdf not available, try weasyprint
            try:
                from weasyprint import HTML
                HTML(filename=html_path).write_pdf(str(output_path))
                return str(output_path)
            except ImportError:
                return None
        except Exception:
            return None

    def generate_html_string(self, investigation_data: Dict, alert_id: str) -> str:
        """Generate HTML report as a string (for API responses).

        Args:
            investigation_data: Complete investigation results.
            alert_id: The alert ID.

        Returns:
            HTML content string.
        """
        template = self.env.get_template("report_template.html")
        return template.render(
            alert_id=alert_id,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            **investigation_data,
        )
