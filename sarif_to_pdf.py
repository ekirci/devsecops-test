import json
import os
import glob
from datetime import datetime
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def _get(obj, path, default=""):
    cur = obj
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def parse_sarif(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    runs = data.get("runs") or []
    for run in runs:
        tool = _get(run, ["tool", "driver", "name"], os.path.basename(path))
        results = run.get("results") or []
        for r in results:
            rule_id = r.get("ruleId", "")
            level = r.get("level", "")  # error/warning/note/none
            msg = _get(r, ["message", "text"], "")
            # Locations
            loc0 = (r.get("locations") or [{}])[0]
            ploc = loc0.get("physicalLocation") or {}
            uri = _get(ploc, ["artifactLocation", "uri"], "")
            region = ploc.get("region") or {}
            line = region.get("startLine", "")
            col = region.get("startColumn", "")
            end_line = region.get("endLine", "")
            # Severity sometimes stored in properties
            props = r.get("properties") or {}
            sev = props.get("severity") or props.get("security-severity") or props.get("cvss") or ""
            rows.append({
                "source_sarif": os.path.basename(path),
                "tool": tool,
                "ruleId": rule_id,
                "level": level,
                "severity": str(sev),
                "message": msg.replace("\n", " ").strip(),
                "file": uri,
                "line": line,
                "col": col,
                "endLine": end_line,
            })

    return pd.DataFrame(rows)

def make_charts(df, out_dir):
    charts = []
    if df.empty:
        return charts

    # Normalize severity bucket from level if severity missing
    def bucket(row):
        if row["severity"] and row["severity"] != "None":
            return row["severity"]
        lv = (row["level"] or "").lower()
        if lv == "error":
            return "HIGH"
        if lv == "warning":
            return "MEDIUM"
        if lv == "note":
            return "LOW"
        return "UNKNOWN"

    df2 = df.copy()
    df2["sev_bucket"] = df2.apply(bucket, axis=1)

    # Severity distribution
    sev_counts = df2["sev_bucket"].value_counts()
    plt.figure()
    sev_counts.plot(kind="bar")
    plt.title("Severity distribution (best-effort)")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    p1 = os.path.join(out_dir, "severity_distribution.png")
    plt.tight_layout()
    plt.savefig(p1, dpi=200)
    plt.close()
    charts.append(p1)

    # Top rules
    top_rules = df2["ruleId"].value_counts().head(10)
    plt.figure()
    top_rules.plot(kind="bar")
    plt.title("Top rules (Top 10)")
    plt.xlabel("Rule")
    plt.ylabel("Count")
    p2 = os.path.join(out_dir, "top_rules.png")
    plt.tight_layout()
    plt.savefig(p2, dpi=200)
    plt.close()
    charts.append(p2)

    return charts

def df_to_table_data(df, max_rows=40):
    cols = ["tool", "ruleId", "level", "severity", "file", "line", "message"]
    df = df.copy()
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    df = df[cols].head(max_rows)

    data = [cols]
    for _, row in df.iterrows():
        msg = str(row["message"])
        if len(msg) > 120:
            msg = msg[:117] + "..."
        filep = str(row["file"])
        if len(filep) > 45:
            filep = "..." + filep[-42:]
        data.append([
            str(row["tool"]),
            str(row["ruleId"]),
            str(row["level"]),
            str(row["severity"]),
            filep,
            str(row["line"]),
            msg
        ])
    return data

def build_pdf(df_all, pdf_path, charts):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path, pagesize=A4, title="Security Findings Report")
    story = []

    story.append(Paragraph("Security Findings Report", styles["Title"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    story.append(Spacer(1, 12))

    if df_all.empty:
        story.append(Paragraph("No findings found in provided SARIF files.", styles["Normal"]))
        doc.build(story)
        return

    story.append(Paragraph(f"Total findings: <b>{len(df_all)}</b>", styles["Normal"]))
    story.append(Spacer(1, 10))

    # Charts
    for ch in charts:
        if os.path.exists(ch):
            story.append(Image(ch, width=520, height=280))
            story.append(Spacer(1, 10))

    story.append(PageBreak())

    # Per SARIF table sections
    for sarif_name, df_s in df_all.groupby("source_sarif"):
        story.append(Paragraph(f"Findings from: <b>{sarif_name}</b> (count: {len(df_s)})", styles["Heading2"]))
        story.append(Spacer(1, 6))
        data = df_to_table_data(df_s, max_rows=60)

        tbl = Table(data, repeatRows=1, colWidths=[70, 85, 45, 55, 110, 35, 120])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
            ("TEXTCOLOR", (0,0), (-1,0), colors.black),
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.whitesmoke, colors.white]),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 12))
        story.append(Paragraph("Note: table is truncated to the first 60 rows for readability.", styles["Italic"]))
        story.append(PageBreak())

    doc.build(story)

def main():
    sarifs = sorted(set(glob.glob("*.sarif") + glob.glob("**/*.sarif", recursive=True)))
    # filter out node_modules or .git noise if any
    sarifs = [s for s in sarifs if "/.git/" not in s and "node_modules" not in s]

    out_dir = "reports"
    os.makedirs(out_dir, exist_ok=True)

    dfs = []
    for s in sarifs:
        try:
            df = parse_sarif(s)
            if not df.empty:
                dfs.append(df)
        except Exception as e:
            print(f"[WARN] Failed to parse {s}: {e}")

    df_all = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    csv_path = os.path.join(out_dir, "findings.csv")
    df_all.to_csv(csv_path, index=False)

    charts = make_charts(df_all, out_dir)
    pdf_path = os.path.join(out_dir, "security-report.pdf")
    build_pdf(df_all, pdf_path, charts)

    print(f"Found SARIF files: {len(sarifs)}")
    print(f"Findings: {len(df_all)}")
    print(f"Wrote: {csv_path}")
    print(f"Wrote: {pdf_path}")

if __name__ == "__main__":
    main()
