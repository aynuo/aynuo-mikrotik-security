from __future__ import annotations

import csv
import io
import json
from html import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.services.parser import redact


def _safe(value) -> str:
    return redact(str(value if value is not None else ""))


def _cve_csv(result: dict) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(["CVE", "Applicability", "Severity", "CVSS", "CVSS Version", "Published", "Affected Range", "Fixed Version", "Description", "Remediation"])
    for row in result.get("findings", []) + result.get("potential_findings", []):
        writer.writerow([
            row.get("id"), row.get("applicability"), row.get("severity"), row.get("cvss_score"),
            row.get("cvss_version"), row.get("published"), row.get("affected_range"),
            row.get("fixed_version") or "Unknown", _safe(row.get("description")), _safe(row.get("remediation")),
        ])
    return ("\ufeff" + out.getvalue()).encode("utf-8")


def _cve_html(result: dict) -> bytes:
    summary = result.get("summary", {})
    rows = "".join(
        "<tr>" + "".join(f"<td>{escape(_safe(value))}</td>" for value in (
            row.get("id"), row.get("applicability"), row.get("severity"), row.get("cvss_score"),
            row.get("published"), row.get("affected_range"), row.get("fixed_version") or "Unknown",
            row.get("description"), row.get("remediation"),
        )) + "</tr>"
        for row in result.get("findings", []) + result.get("potential_findings", [])
    ) or '<tr><td colspan="9">No CVE records were returned. Check the data status before interpreting this result.</td></tr>'
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AYNUO CVE Assessment</title>
<style>body{{font-family:Arial;margin:40px;color:#172554}}h1{{color:#4338ca}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}th{{background:#4338ca;color:white}}</style></head><body>
<h1>AYNUO</h1><h2>RouterOS CVE Assessment</h2><p>Version: <b>{escape(_safe(result.get('routeros_version')))}</b> · Confirmed matches: <b>{summary.get('total_cves', 0)}</b> · Unknown applicability: <b>{summary.get('potential_cves', 0)}</b></p>
<p>Data source: NVD · Generated: {escape(_safe(result.get('created_at')))}</p><table><thead><tr><th>CVE</th><th>Applicability</th><th>Severity</th><th>CVSS</th><th>Published</th><th>Affected range</th><th>Fixed</th><th>Description</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table></body></html>"""
    return html.encode("utf-8")


def _cve_pdf(result: dict) -> bytes:
    out = io.BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=12 * mm, leftMargin=12 * mm, topMargin=14 * mm, bottomMargin=14 * mm, title="AYNUO RouterOS CVE Assessment")
    story = [Paragraph("AYNUO RouterOS CVE Assessment", styles["Title"]),
             Paragraph(f"RouterOS version: {escape(_safe(result.get('routeros_version')))}", styles["BodyText"]), Spacer(1, 4 * mm)]
    rows = [["CVE", "State", "CVSS", "Affected / fixed", "Description"]]
    for item in result.get("findings", []) + result.get("potential_findings", []):
        rows.append([
            _safe(item.get("id")), _safe(item.get("applicability")), _safe(item.get("cvss_score") or "—"),
            Paragraph(escape(_safe(item.get("affected_range"))) + "<br/>Fixed: " + escape(_safe(item.get("fixed_version") or "Unknown")), styles["BodyText"]),
            Paragraph(escape(_safe(item.get("description"))), styles["BodyText"]),
        ])
    if len(rows) == 1:
        rows.append(["—", "—", "—", "—", "No CVE records returned; review data status."])
    table = Table(rows, colWidths=[25 * mm, 20 * mm, 16 * mm, 48 * mm, 77 * mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4338CA")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#D9DEEA"))]))
    story.append(table)
    doc.build(story)
    return out.getvalue()


def _scan_rows(result: dict):
    audit = result.get("audit") or {}
    cve = result.get("cve") or {}
    for row in audit.get("findings", []):
        yield "AUDIT", row.get("id"), row.get("severity"), row.get("title"), " | ".join(row.get("evidence", [])), row.get("remediation")
    for row in cve.get("findings", []) + cve.get("potential_findings", []):
        yield "CVE", row.get("id"), row.get("severity"), row.get("description"), row.get("affected_range"), row.get("remediation")


def _scan_export(result: dict, kind: str):
    rows = list(_scan_rows(result))
    if kind == "csv":
        out = io.StringIO(newline=""); writer = csv.writer(out)
        writer.writerow(["Type", "ID", "Severity", "Finding", "Evidence / affected range", "Remediation"])
        writer.writerows([[_safe(value) for value in row] for row in rows])
        return ("\ufeff" + out.getvalue()).encode("utf-8"), "text/csv; charset=utf-8", "csv"
    if kind == "html":
        device, summary = result.get("device", {}), result.get("summary", {})
        body = "".join("<tr>" + "".join(f"<td>{escape(_safe(value))}</td>" for value in row) + "</tr>" for row in rows)
        html = f"""<!doctype html><html><head><meta charset="utf-8"><title>AYNUO Unified Security Scan</title><style>body{{font-family:Arial;margin:40px;color:#172554}}h1{{color:#4338ca}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}th{{background:#4338ca;color:#fff}}</style></head><body><h1>AYNUO Unified Security Scan</h1><p>Device: {escape(_safe(device.get('identity')))} · RouterOS {escape(_safe(result.get('routeros_version')))} · Status {escape(_safe(summary.get('scan_status')))}</p><table><thead><tr><th>Type</th><th>ID</th><th>Severity</th><th>Finding</th><th>Evidence / range</th><th>Remediation</th></tr></thead><tbody>{body}</tbody></table></body></html>"""
        return html.encode("utf-8"), "text/html; charset=utf-8", "html"
    out = io.BytesIO(); styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=10*mm, leftMargin=10*mm, topMargin=12*mm, bottomMargin=12*mm, title="AYNUO Unified Security Scan")
    story = [Paragraph("AYNUO Unified Security Scan", styles["Title"]), Spacer(1,4*mm)]
    for row in rows:
        story.extend([
            Paragraph(f"<b>{escape(_safe(row[0]))} · {escape(_safe(row[1]))} · {escape(_safe(row[2]))}</b>", styles["Heading3"]),
            Paragraph(escape(_safe(row[3])), styles["BodyText"]),
            Paragraph("<b>Evidence / affected range:</b> " + escape(_safe(row[4])), styles["BodyText"]),
            Paragraph("<b>Remediation:</b> " + escape(_safe(row[5])), styles["BodyText"]),
            Spacer(1, 3*mm),
        ])
    if not rows:
        story.append(Paragraph("No findings were returned by the completed scan.", styles["BodyText"]))
    doc.build(story)
    return out.getvalue(), "application/pdf", "pdf"


def pdf_report(result: dict) -> bytes:
    out = io.BytesIO()
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "AynuoTitle", parent=styles["Title"], textColor=colors.HexColor("#4338CA"),
        fontSize=24, leading=29,
    )
    doc = SimpleDocTemplate(
        out, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
        topMargin=17 * mm, bottomMargin=16 * mm,
        title="AYNUO MikroTik Security Assessment Report",
    )
    summary = result["summary"]
    device = result.get("device", {})
    source = _safe(result.get("source", "OFFLINE"))
    target = _safe(device.get("management_ip") or device.get("target") or "Not supplied")
    story = [
        Paragraph("AYNUO", title),
        Paragraph("MikroTik Security Assessment Report", styles["Heading2"]),
        Spacer(1, 5 * mm),
        Paragraph(f"Device: <b>{escape(_safe(device.get('identity') or 'Unnamed device'))}</b>", styles["BodyText"]),
        Paragraph(f"Assessment source: <b>{escape(source)}</b>", styles["BodyText"]),
        Paragraph(f"Management target: <b>{escape(target)}</b>", styles["BodyText"]),
        Paragraph(f"Security score: <b>{summary['score']}/100</b>", styles["BodyText"]),
        Paragraph(
            f"Coverage: <b>{summary['evaluated_controls']}/{summary['total_controls']} controls "
            f"({summary['coverage']}%)</b>", styles["BodyText"],
        ),
        Paragraph(f"Assessment timestamp: {escape(_safe(result['created_at']))}", styles["BodyText"]),
        Paragraph(
            "Severity counts: " + ", ".join(
                f"{name.title()} {summary['severity'].get(name, 0)}" for name in ("critical", "high", "medium", "low", "informational")
            ), styles["BodyText"],
        ),
        Spacer(1, 5 * mm), Paragraph("Verified findings", styles["Heading2"]),
    ]
    rows = [["ID", "Severity", "Finding", "Evidence / remediation"]]
    for finding in result["findings"]:
        evidence = " | ".join(_safe(item) for item in finding["evidence"])
        rows.append([
            finding["id"], finding["severity"].upper(),
            Paragraph(escape(_safe(finding["title"])), styles["BodyText"]),
            Paragraph(escape(evidence + " - " + _safe(finding["remediation"])), styles["BodyText"]),
        ])
    if len(rows) == 1:
        rows.append(["—", "—", "No failed controls", "See coverage; missing sections are not counted as passes."])
    table = Table(rows, colWidths=[23 * mm, 25 * mm, 43 * mm, 82 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4338CA")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D9DEEA")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFF")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([
        table, Spacer(1, 5 * mm),
        Paragraph(
            "Assessment limitation: results cover only data returned by RouterOS or present in the uploaded "
            "export. Missing or inaccessible sections are reported as not evaluated.",
            styles["BodyText"],
        ),
    ])
    doc.build(story)
    return out.getvalue()


def export(result: dict, kind: str):
    if kind == "json":
        return json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8"), "application/json", "json"
    if result.get("assessment_type") == "SCAN":
        return _scan_export(result, kind)
    if result.get("assessment_type") == "CVE":
        if kind == "csv":
            return _cve_csv(result), "text/csv; charset=utf-8", "csv"
        if kind == "html":
            return _cve_html(result), "text/html; charset=utf-8", "html"
        if kind == "pdf":
            return _cve_pdf(result), "application/pdf", "pdf"
    if kind == "pdf":
        return pdf_report(result), "application/pdf", "pdf"
    if kind == "csv":
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        writer.writerow(["Source", "Device", "Target", "ID", "Severity", "Control", "Category", "Evidence", "Remediation"])
        for finding in result["findings"]:
            writer.writerow([
                result.get("source", "OFFLINE"), _safe(result.get("device", {}).get("identity")),
                _safe(result.get("device", {}).get("management_ip") or result.get("device", {}).get("target")),
                finding["id"], finding["severity"], _safe(finding["title"]), finding["category"],
                " | ".join(_safe(item) for item in finding["evidence"]), _safe(finding["remediation"]),
            ])
        return ("\ufeff" + out.getvalue()).encode("utf-8"), "text/csv; charset=utf-8", "csv"

    summary = result["summary"]
    severity = summary["severity"]
    device = result.get("device", {})
    rows = "".join(
        "<tr>"
        f"<td>{escape(_safe(finding['id']))}</td><td>{escape(_safe(finding['severity']))}</td>"
        f"<td>{escape(_safe(finding['title']))}</td>"
        f"<td>{escape(' | '.join(_safe(item) for item in finding['evidence']))}</td>"
        f"<td>{escape(_safe(finding['remediation']))}</td></tr>"
        for finding in result["findings"]
    ) or '<tr><td colspan="5">No failed controls. Review coverage before interpreting this result.</td></tr>'
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AYNUO Assessment Report</title><style>
body{{font-family:Arial,sans-serif;margin:40px;color:#172554}}h1{{color:#4338ca}}
.summary{{display:flex;gap:24px;flex-wrap:wrap;background:#f5f5ff;padding:16px;border-radius:10px}}
table{{border-collapse:collapse;width:100%;margin-top:20px}}td,th{{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}
th{{background:#4338ca;color:white}}.limit{{margin-top:24px;color:#52607a}}</style></head><body>
<h1>AYNUO</h1><p>MikroTik Security Assessment Report</p><div class="summary">
<b>Security score: {summary['score']}/100</b><b>Coverage: {summary['evaluated_controls']}/{summary['total_controls']} ({summary['coverage']}%)</b>
<span>Critical {severity['critical']} · High {severity['high']} · Medium {severity['medium']} · Low {severity['low']} · Informational {severity.get('informational', 0)}</span></div>
<p>Source: <b>{escape(_safe(result.get('source', 'OFFLINE')))}</b> · Device: <b>{escape(_safe(device.get('identity') or 'Unnamed device'))}</b> · Target: {escape(_safe(device.get('management_ip') or device.get('target') or 'Not supplied'))}</p>
<p>Assessment timestamp: {escape(_safe(result['created_at']))}</p>
<table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table>
<p class="limit">Assessment limitation: results cover only data returned by RouterOS or present in the uploaded export. Missing or inaccessible sections are not counted as passes.</p>
</body></html>"""
    return html.encode("utf-8"), "text/html; charset=utf-8", "html"

