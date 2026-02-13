"""PDF report generation wrapper."""

from agent.reporter import ReportGenerator


def generate_pdf_report(investigation_data: dict, alert_id: str) -> str:
    """Generate a PDF report for an investigation.

    Args:
        investigation_data: Complete investigation data.
        alert_id: Alert identifier.

    Returns:
        Path to generated PDF, or empty string on failure.
    """
    gen = ReportGenerator()
    html_path = gen.generate_html(investigation_data, alert_id)
    pdf_path = gen.generate_pdf(html_path, alert_id)
    return pdf_path or ""
