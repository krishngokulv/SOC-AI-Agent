"""HTML report generation wrapper."""

from agent.reporter import ReportGenerator


def generate_html_report(investigation_data: dict, alert_id: str) -> str:
    """Generate an HTML report for an investigation.

    Args:
        investigation_data: Complete investigation data.
        alert_id: Alert identifier.

    Returns:
        Path to generated HTML file.
    """
    gen = ReportGenerator()
    return gen.generate_html(investigation_data, alert_id)
