"""Main LLM agent orchestration engine.

Coordinates the full investigation pipeline:
Triage -> IOC Extraction -> Enrichment -> Correlation -> ATT&CK Mapping -> Verdict -> Report
"""

import asyncio
import json
from datetime import datetime
from typing import AsyncGenerator, Dict, Optional
from parsers.sysmon import AlertData, SysmonParser
from parsers.windows_event import WindowsEventParser
from parsers.firewall import FirewallParser
from parsers.email_parser import EmailParser
from parsers.pcap_parser import PcapParser
from parsers.generic import GenericParser
from parsers.ioc_extractor import IOCExtractor
from agent.triage import TriageEngine
from agent.investigator import Investigator
from agent.correlator import Correlator
from agent.mapper import AttackMapper
from agent.verdict import VerdictEngine
from agent.reporter import ReportGenerator
from database.db import DatabaseManager


class Orchestrator:
    """Orchestrates the full investigation pipeline.

    Accepts raw alert data, runs it through all analysis stages,
    and yields progress events for real-time streaming.
    """

    PARSERS = [
        ("sysmon", SysmonParser),
        ("windows_event", WindowsEventParser),
        ("firewall", FirewallParser),
        ("phishing", EmailParser),
        ("pcap", PcapParser),
        ("generic", GenericParser),
    ]

    def __init__(self, db: DatabaseManager):
        self.db = db
        self.investigator = Investigator(db)
        self.correlator = Correlator(db)
        self.reporter = ReportGenerator()

    async def close(self) -> None:
        """Clean up resources."""
        await self.investigator.close()

    def parse_alert(self, raw_content: str, alert_type: str = "auto") -> AlertData:
        """Parse raw alert content into normalized AlertData.

        Args:
            raw_content: Raw alert text or file content.
            alert_type: Type hint (auto, sysmon, firewall, phishing, etc.)

        Returns:
            Normalized AlertData object.
        """
        if alert_type and alert_type != "auto":
            parser_map = {p[0]: p[1] for p in self.PARSERS}
            if alert_type in parser_map:
                return parser_map[alert_type].parse(raw_content)

        # Auto-detect
        for name, parser_cls in self.PARSERS:
            if name == "generic":
                continue
            if parser_cls.can_parse(raw_content):
                return parser_cls.parse(raw_content)

        return GenericParser.parse(raw_content)

    async def investigate(
        self,
        raw_content: str,
        alert_type: str = "auto",
        alert_id: Optional[str] = None,
    ) -> AsyncGenerator[Dict, None]:
        """Run the full investigation pipeline with streaming progress.

        Args:
            raw_content: Raw alert content.
            alert_type: Alert type hint.
            alert_id: Pre-assigned alert ID (avoids double-parse UUID mismatch).

        Yields:
            Progress event dicts at each investigation stage.
        """
        timeline = []
        start_time = datetime.utcnow()

        # Stage 1: Parse and Triage
        yield {"stage": "triage", "status": "in_progress", "detail": "Parsing and classifying alert..."}

        alert = self.parse_alert(raw_content, alert_type)
        if alert_id:
            alert.alert_id = alert_id
        severity, classification, description = TriageEngine.classify(alert)

        triage_data = {
            "severity": severity,
            "classification": classification,
            "description": description,
            "alert_type": alert.alert_type,
        }

        timeline.append({
            "stage": "Triage",
            "status": "Complete",
            "detail": f"Classified as {classification}. Severity: {severity}.",
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "triage",
            "status": "complete",
            "result": triage_data,
        }

        # Create database record
        investigation = await self.db.create_investigation(
            alert_id=alert.alert_id,
            raw_alert=raw_content,
            alert_type=alert.alert_type,
        )

        # Stage 2: IOC Extraction
        yield {"stage": "extraction", "status": "in_progress", "detail": "Extracting IOCs..."}

        iocs = alert.extracted_iocs
        if not iocs:
            iocs = IOCExtractor.extract(raw_content)

        ioc_summary = {}
        for ioc in iocs:
            t = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
            ioc_summary[t] = ioc_summary.get(t, 0) + 1

        timeline.append({
            "stage": "IOC Extraction",
            "status": "Complete",
            "detail": f"Extracted {len(iocs)} IOCs: {ioc_summary}",
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "extraction",
            "status": "complete",
            "result": {
                "total_iocs": len(iocs),
                "by_type": ioc_summary,
                "iocs": [ioc.to_dict() if hasattr(ioc, "to_dict") else ioc for ioc in iocs[:20]],
            },
        }

        # Stage 3: Enrichment
        yield {"stage": "enriching", "status": "in_progress", "detail": f"Enriching {len(iocs)} IOCs..."}

        enrichment_events = []

        async def enrichment_callback(source, ioc_value, result, cached):
            event = {
                "stage": "enriching",
                "source": source,
                "ioc": ioc_value,
                "cached": cached,
                "risk_score": result.risk_score,
                "malicious": result.malicious,
                "summary": result.summary,
                "error": result.error,
            }
            enrichment_events.append(event)

        enrichment_results = await self.investigator.enrich_all(iocs, enrichment_callback)

        # Yield individual enrichment events
        for event in enrichment_events:
            yield event

        timeline.append({
            "stage": "Enrichment",
            "status": "Complete",
            "detail": f"Enriched {len(enrichment_results)} IOCs across threat intel sources.",
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "enriching",
            "status": "complete",
            "result": {
                "total_enriched": len(enrichment_results),
                "results_preview": [
                    {
                        "value": r.get("value"),
                        "type": r.get("type"),
                        "risk_score": r.get("risk_score"),
                        "malicious_count": r.get("malicious_count"),
                    }
                    for r in enrichment_results[:10]
                ],
            },
        }

        # Stage 4: Correlation
        yield {"stage": "correlating", "status": "in_progress", "detail": "Checking historical data..."}

        ioc_values = [ioc.value for ioc in iocs]
        correlation_data = await self.correlator.correlate(
            alert_id=alert.alert_id,
            ioc_values=ioc_values,
            source_ip=alert.source_ip,
            dest_ip=alert.dest_ip,
            user=alert.user,
        )

        timeline.append({
            "stage": "Correlation",
            "status": "Complete",
            "detail": correlation_data.get("correlation_summary", "No correlations found."),
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "correlating",
            "status": "complete",
            "result": {
                "related_count": correlation_data.get("related_count", 0),
                "related_alerts": correlation_data.get("related_investigations", [])[:5],
                "summary": correlation_data.get("correlation_summary", ""),
            },
        }

        # Stage 5: MITRE ATT&CK Mapping
        yield {"stage": "mapping", "status": "in_progress", "detail": "Mapping to MITRE ATT&CK..."}

        mitre_data = AttackMapper.map(alert, enrichment_results)

        timeline.append({
            "stage": "ATT&CK Mapping",
            "status": "Complete",
            "detail": f"Matched {mitre_data.get('technique_count', 0)} techniques across {len(mitre_data.get('tactics_covered', []))} tactics.",
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "mapping",
            "status": "complete",
            "result": {
                "techniques": mitre_data.get("techniques", []),
                "technique_count": mitre_data.get("technique_count", 0),
                "tactics_covered": mitre_data.get("tactics_covered", []),
            },
        }

        # Stage 6: Verdict
        yield {"stage": "verdict", "status": "in_progress", "detail": "Computing verdict..."}

        verdict_data = VerdictEngine.evaluate(
            alert=alert,
            enrichment_results=enrichment_results,
            correlation_data=correlation_data,
            mitre_data=mitre_data,
            triage_severity=severity,
        )

        timeline.append({
            "stage": "Verdict",
            "status": "Complete",
            "detail": f"{verdict_data['verdict']} (confidence: {verdict_data['confidence']}%)",
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "verdict",
            "status": "complete",
            "result": {
                "verdict": verdict_data["verdict"],
                "confidence": verdict_data["confidence"],
                "reasoning_summary": verdict_data.get("reasoning_summary", ""),
                "recommended_actions": verdict_data.get("recommended_actions", []),
            },
        }

        # Stage 7: Report Generation
        yield {"stage": "report", "status": "in_progress", "detail": "Generating investigation report..."}

        investigation_report_data = {
            "alert_data": alert.to_dict(),
            "alert_type": alert.alert_type,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "raw_alert": raw_content[:5000],
            "triage_data": triage_data,
            "enrichment_results": enrichment_results,
            "correlation_data": correlation_data,
            "mitre_data": mitre_data,
            "verdict_data": verdict_data,
            "timeline": timeline,
        }

        html_path = self.reporter.generate_html(investigation_report_data, alert.alert_id)
        pdf_path = self.reporter.generate_pdf(html_path, alert.alert_id)

        timeline.append({
            "stage": "Report",
            "status": "Complete",
            "detail": f"HTML and PDF reports generated.",
            "timestamp": datetime.utcnow().isoformat(),
        })

        yield {
            "stage": "report",
            "status": "complete",
            "result": {
                "html_path": html_path,
                "pdf_path": pdf_path,
                "report_url_html": f"/api/reports/{alert.alert_id}/html",
                "report_url_pdf": f"/api/reports/{alert.alert_id}/pdf",
            },
        }

        # Stage 8: Save to Database
        ioc_records = [
            {
                "value": r.get("value", ""),
                "type": r.get("type", ""),
                "risk_score": r.get("risk_score", 0),
                "enrichment_data": r.get("enrichment_data", {}),
            }
            for r in enrichment_results
        ]

        mitre_techniques = mitre_data.get("techniques", [])

        await self.db.update_investigation(
            alert_id=alert.alert_id,
            verdict=verdict_data["verdict"],
            confidence=verdict_data["confidence"],
            reasoning=verdict_data.get("reasoning_summary", ""),
            mitre_techniques=mitre_techniques,
            report_path_html=html_path,
            report_path_pdf=pdf_path,
            investigation_data=investigation_report_data,
        )

        if investigation and ioc_records:
            await self.db.save_iocs(investigation.id, ioc_records)

        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        yield {
            "stage": "complete",
            "status": "complete",
            "result": {
                "alert_id": alert.alert_id,
                "verdict": verdict_data["verdict"],
                "confidence": verdict_data["confidence"],
                "techniques_matched": len(mitre_techniques),
                "iocs_found": len(iocs),
                "duration_seconds": round(duration, 2),
                "report_url_html": f"/api/reports/{alert.alert_id}/html",
                "report_url_pdf": f"/api/reports/{alert.alert_id}/pdf",
            },
        }
