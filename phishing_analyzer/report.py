from __future__ import annotations

import html
import io
import json
import re
import uuid
import zipfile
from dataclasses import asdict

from .models import AnalysisResult


def _xml_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def json_report(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def _report_lines(result: AnalysisResult) -> list[str]:
    regions = (
        ", ".join(
            f"{item.get('label', item.get('code', ''))} ({item.get('strength', 'possible')})"
            for item in result.metadata.get("regional_pattern_matches", [])
        )
        or "None observed"
    )
    advanced = result.metadata.get("advanced_detection", {})
    attack_mappings = (
        ", ".join(sorted({item.get("mapping", "") for item in advanced.get("attack_mappings", []) if item.get("mapping")}))
        or "None observed"
    )
    indicator_types = (
        ", ".join(sorted({item.get("type", "") for item in advanced.get("sensitive_indicators", []) if item.get("type")}))
        or "None observed"
    )
    lines = [
        "NexVision OSINT Phishing Email Analysis",
        f"Case: {result.metadata.get('case_id', '')}",
        f"SHA-256: {result.metadata.get('message_sha256', '')}",
        f"Risk: {result.risk} | Triage score: {result.score}/100 | Confidence: {result.confidence}",
        f"Classification: {result.classification}",
        f"Languages: {', '.join(result.metadata.get('language_names', [])) or 'Undetermined'}",
        f"Regional wording patterns: {regions}",
        f"Rule pack: {result.metadata.get('rule_pack_version', 'not recorded')}",
        f"Advanced rule pack: {advanced.get('version', 'not recorded')} | Tactics: {advanced.get('tactic_count', 0)}",
        f"ATT&CK mappings: {attack_mappings}",
        f"Redacted indicator types: {indicator_types}",
        result.summary,
        "",
        "Score dimensions",
    ]
    lines.extend(f"- {name.replace('_', ' ').title()}: {value}" for name, value in asdict(result.dimensions).items())
    lines.extend(["", "Evidence status"])
    lines.extend(f"- {name}: {status}" for name, status in result.evidence_status.items())
    lines.extend(["", "Message findings"])
    lines.extend(f"- [{f.severity}] {f.title} ({f.points}): {f.evidence}" for f in result.findings)
    if not result.findings:
        lines.append("- None")
    lines.extend(["", f"Destinations ({result.links_checked} deeply inspected of {result.links_found} found)"])
    for link in sorted(result.links, key=lambda item: -item.rank_score):
        marker = "deep" if link.selected_for_deep_inspection else "static only"
        lines.append(f"- [{link.risk}] {link.host} score={link.score} rank={link.rank_score} ({marker}) {link.display_url}")
    lines.extend(["", "Attachments"])
    for item in result.attachments:
        lines.append(f"- [{item.risk}] {item.filename} {item.detected_type} {item.size_bytes} bytes SHA-256 {item.sha256}")
    if not result.attachments:
        lines.append("- None")
    lines.extend(["", "Limitations"])
    lines.extend(f"- {item}" for item in result.limitations)
    return lines


def html_report(result: AnalysisResult) -> str:
    esc = lambda value: html.escape(str(value))
    language_names = ", ".join(result.metadata.get("language_names", [])) or "Undetermined"
    region_names = (
        ", ".join(
            f"{item.get('label', item.get('code', ''))} ({item.get('strength', 'possible')})"
            for item in result.metadata.get("regional_pattern_matches", [])
        )
        or "None observed"
    )
    findings = (
        "".join(
            f"<tr><td>{esc(f.status)}</td><td>{esc(f.severity)}</td><td>{esc(f.title)}</td><td>{f.points}</td><td>{esc(f.evidence)}</td></tr>"
            for f in result.findings
        )
        or "<tr><td colspan='5'>No message-level findings.</td></tr>"
    )
    links = (
        "".join(
            f"<tr><td>{'Deep' if link.selected_for_deep_inspection else 'Static'}</td><td>{esc(link.registrable_domain or link.host)}</td><td>{link.rank_score}</td><td>{link.score}</td><td>{esc(link.risk)}</td><td><code>{esc(link.display_url)}</code><br><small>{esc(', '.join(f.code for f in link.findings) or 'No static finding')}</small></td></tr>"
            for link in sorted(result.links, key=lambda item: -item.rank_score)
        )
        or "<tr><td colspan='6'>No links found.</td></tr>"
    )
    attachments = (
        "".join(
            f"<tr><td>{esc(item.filename)}</td><td>{esc(item.detected_type)}</td><td>{item.size_bytes}</td><td>{esc(item.risk)}</td><td><code>{esc(item.sha256)}</code><br><small>{esc(', '.join(f.code for f in item.findings) or 'No static finding')}</small></td></tr>"
            for item in result.attachments
        )
        or "<tr><td colspan='5'>No attachments.</td></tr>"
    )
    dimensions = "".join(
        f"<tr><td>{esc(k.replace('_', ' ').title())}</td><td>{v}/100</td></tr>" for k, v in asdict(result.dimensions).items()
    )
    statuses = "".join(f"<tr><td>{esc(k.replace('_', ' ').title())}</td><td>{esc(v)}</td></tr>" for k, v in result.evidence_status.items())
    limits = "".join(f"<li>{esc(item)}</li>" for item in result.limitations)
    advanced = result.metadata.get("advanced_detection", {})
    attack_mappings = (
        ", ".join(sorted({item.get("mapping", "") for item in advanced.get("attack_mappings", []) if item.get("mapping")}))
        or "None observed"
    )
    indicator_types = (
        ", ".join(sorted({item.get("type", "") for item in advanced.get("sensitive_indicators", []) if item.get("type")}))
        or "None observed"
    )
    color = {"high": "#b42318", "likely_phishing": "#d92d20", "suspicious": "#dc6803", "low": "#027a48"}[result.risk]
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><title>NexVision Phishing Analysis</title>
<style>body{{font:15px system-ui;margin:0;background:#f4f7fb;color:#172b4d}}main{{max-width:1100px;margin:32px auto;background:white;padding:32px;border-radius:16px;box-shadow:0 8px 30px #102a4318}}.banner{{border-left:8px solid {color};padding:14px 18px;background:#f8fafc}}.score{{font-size:34px;font-weight:750;color:{color}}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}th,td{{padding:9px;border-bottom:1px solid #dfe3e8;text-align:left;vertical-align:top}}th{{background:#f6f8fa}}code{{overflow-wrap:anywhere}}small{{color:#667085}}@media(max-width:700px){{.grid{{grid-template-columns:1fr}}}}</style>
<main><h1>NexVision OSINT Phishing Email Analysis</h1><p><small>Case {esc(result.metadata.get("case_id", ""))} · SHA-256 <code>{esc(result.metadata.get("message_sha256", ""))}</code></small></p><section class="banner"><div class="score">{result.score}/100 — {esc(result.risk.replace("_", " ").title())}</div><p>{esc(result.summary)}</p></section>
<h2>Assessment</h2><p><b>{esc(result.classification)}</b> · Confidence: {esc(result.confidence)} · Analyst disposition: {esc(result.analyst_disposition)}</p><p>Languages: {esc(language_names)} · Regional wording patterns: {esc(region_names)} · Rule pack: {esc(result.metadata.get("rule_pack_version", "not recorded"))}</p><p>Advanced rule pack: {esc(advanced.get("version", "not recorded"))} · Tactics: {esc(advanced.get("tactic_count", 0))}<br>ATT&amp;CK mappings: {esc(attack_mappings)}<br>Redacted indicator types: {esc(indicator_types)}</p><div class="grid"><section><h2>Score dimensions</h2><table>{dimensions}</table></section><section><h2>Evidence coverage</h2><table>{statuses}</table></section></div>
<h2>Message findings</h2><table><tr><th>Status</th><th>Severity</th><th>Finding</th><th>Points</th><th>Evidence</th></tr>{findings}</table>
<h2>Destinations ({result.links_checked} deeply inspected of {result.links_found} found)</h2><table><tr><th>Inspection</th><th>Domain</th><th>Rank</th><th>Score</th><th>Risk</th><th>Observed URL</th></tr>{links}</table>
<h2>Attachments</h2><table><tr><th>Name</th><th>Detected type</th><th>Bytes</th><th>Risk</th><th>SHA-256</th></tr>{attachments}</table>
<h2>Important limitations</h2><ul>{limits}</ul><small>Analyzer v{esc(result.version)}. Automated triage only; consequential decisions require examiner review.</small></main></html>"""


_PDF_MAX_LINE = 1500


def pdf_report(result: AnalysisResult) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    if "NexVisionSans" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("NexVisionSans", "Vera.ttf"))
        pdfmetrics.registerFont(TTFont("NexVisionSans-Bold", "VeraBd.ttf"))

    def safe(value: str) -> str:
        # Standard PDF fonts are deliberately used for portable rendering.
        # Preserve the full original evidence in JSON/HTML/DOCX and make any
        # unsupported script explicit instead of rendering question marks.
        value = re.sub(r"[^\x09\x0a\x0d\x20-\xff]+", " [non-Latin text] ", value)
        value = re.sub(r"\s+", " ", value).strip()
        # ReportLab lays out an unbreakable run character by character, which is quadratic: one 1 MB
        # URL took minutes. Cap each line; the full value stays in the JSON/HTML/DOCX reports.
        if len(value) > _PDF_MAX_LINE:
            value = value[:_PDF_MAX_LINE] + f" ... [truncated, {len(value) - _PDF_MAX_LINE} more characters]"
        return html.escape(value)

    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="NexVisionSans",
        fontSize=8.8,
        leading=11.4,
        textColor=colors.HexColor("#172B4D"),
        spaceAfter=2.5,
    )
    heading = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontName="NexVisionSans-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#172B4D"),
        spaceBefore=10,
        spaceAfter=6,
    )
    title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="NexVisionSans-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#172B4D"),
        spaceAfter=10,
    )
    footer = ParagraphStyle("ReportFooter", parent=body, fontSize=8, textColor=colors.HexColor("#667085"), alignment=TA_RIGHT)
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.45 * inch,
        title="NexVision OSINT Phishing Email Analysis",
    )

    headings = {"Score dimensions", "Evidence status", "Message findings", "Attachments", "Limitations"}
    story = []
    for index, line in enumerate(_report_lines(result)):
        if index == 0:
            story.append(Paragraph(safe(line), title))
        elif line in headings or line.startswith("Destinations ("):
            story.append(Paragraph(safe(line), heading))
        elif not line:
            story.append(Spacer(1, 5))
        else:
            story.append(Paragraph(safe(line), body))
    story.append(Spacer(1, 8))
    story.append(Paragraph(safe(f"Analyzer v{result.version} - automated triage only - case {result.metadata.get('case_id', '')}"), footer))
    document.build(story)
    return buffer.getvalue()


def docx_report(result: AnalysisResult) -> bytes:
    headings = {"Score dimensions", "Evidence status", "Message findings", "Attachments", "Limitations"}

    def paragraph(index: int, line: str) -> str:
        style = "Title" if index == 0 else "Heading1" if line in headings or line.startswith("Destinations (") else "Body"
        if not line:
            return '<w:p><w:pPr><w:spacing w:after="80"/></w:pPr></w:p>'
        return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr><w:r><w:t xml:space="preserve">{_xml_escape(line)}</w:t></w:r></w:p>'

    paragraphs = "".join(paragraph(index, line) for index, line in enumerate(_report_lines(result)))
    document = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{paragraphs}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="720" w:right="900" w:bottom="720" w:left="900"/></w:sectPr></w:body></w:document>'
    styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="21"/><w:color w:val="172B4D"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Body"><w:name w:val="Body"/><w:qFormat/></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Body"/><w:qFormat/><w:pPr><w:spacing w:after="240"/></w:pPr><w:rPr><w:b/><w:color w:val="000000"/><w:sz w:val="34"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Body"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="220" w:after="90"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="000000"/><w:sz w:val="26"/></w:rPr></w:style>
</w:styles>"""
    content_types = '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'
    rels = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    document_rels = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/_rels/document.xml.rels", document_rels)
        archive.writestr("word/styles.xml", styles)
    return buffer.getvalue()


def stix_report(result: AnalysisResult) -> str:
    message_hash = result.metadata["message_sha256"]
    analyzed_at = result.metadata["analyzed_at"]
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:sha256:{message_hash}")
    objects = []
    for link in result.links:
        reputation_match = link.reputation.get("status") == "matched"
        if link.score <= 0 and not reputation_match:
            continue
        escaped_url = link.normalized_url.replace("\\", "\\\\").replace("'", "\\'")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(namespace, link.normalized_url)}",
                "created": analyzed_at,
                "modified": analyzed_at,
                "valid_from": analyzed_at,
                "pattern_type": "stix",
                "pattern": f"[url:value = '{escaped_url}']",
                "labels": ["suspicious-activity"],
                "confidence": min(100, link.score),
                "description": "Static triage indicator; analyst validation is required before operational use.",
            }
        )
    bundle_id = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:nexvision:bundle:{message_hash}")
    return json.dumps({"type": "bundle", "id": f"bundle--{bundle_id}", "objects": objects}, indent=2)
