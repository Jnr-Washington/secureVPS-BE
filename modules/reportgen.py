import sys
import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

def generate_report(results, output_path=None, format="HTML", report_name=None):
    """
    Generates a security report in HTML, PDF, or XML format following the 
    SecureOps emerald theme.
    """
    meta = results.get("meta", {})
    target = meta.get("target", "Unknown")
    timestamp = meta.get("timestamp", datetime.now(timezone.utc).isoformat())
    display_name = report_name or f"Security Audit - {target}"

    # Emerald Theme Colors
    EMERALD = "#10b981"
    DARK_BG = "#0d0d0d"
    SURFACE = "#1a1a1a"
    BORDER = "#2a2a2a"

    def severity_color(severity):
        return {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#f59e0b",
            "Low": "#10b981",
        }.get(severity, "#6b7280")

    # [HTML Rendering Logic - Optimized for Emerald Theme]
    html_content = f"""
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <style>
            body {{ background: {DARK_BG}; color: #e5e7eb; font-family: 'Inter', sans-serif; padding: 40px; }}
            .header {{ border-bottom: 2px solid {EMERALD}; padding-bottom: 20px; margin-bottom: 30px; }}
            .brand {{ color: {EMERALD}; font-weight: bold; letter-spacing: 1px; }}
            .card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            h2 {{ color: {EMERALD}; font-size: 1.1rem; text-transform: uppercase; margin-bottom: 15px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ text-align: left; color: #9ca3af; border-bottom: 1px solid {BORDER}; padding: 10px; }}
            td {{ padding: 10px; border-bottom: 1px solid #262626; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
            .btn-emerald {{ background: {EMERALD}; color: {DARK_BG}; padding: 8px 16px; border-radius: 6px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class='header'>
            <div class='brand'>SECUREOPS / VULN SCANNER</div>
            <h1>{display_name}</h1>
            <p style='color: #6b7280;'>Target: {target} | Generated: {timestamp}</p>
        </div>
        
        <div class='card'>
            <h2>Vulnerability Summary</h2>
            <!-- Logic to render scan findings tables here -->
        </div>
    </body>
    </html>
    """

    # --- Export Logic ---
    host = urlparse(target).netloc or target
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    final_path = output_path or os.path.join(reports_dir, f"report_{host}_{ts}.{format.lower()}")

    if format.upper() == "HTML":
        with open(final_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    elif format.upper() == "PDF":
        try:
            import pdfkit
            pdfkit.from_string(html_content, final_path)
        except ImportError:
            logging.error("pdfkit not found. Defaulting to HTML.")
            return generate_report(results, format="HTML")

    elif format.upper() == "XML":
        import xml.etree.ElementTree as ET
        root = ET.Element("OpenVAS_Scan_Report")
        # Recursive helper to convert results dict to XML tags
        def build_xml(parent, d):
            for k, v in d.items():
                child = ET.SubElement(parent, str(k).replace(" ", "_"))
                if isinstance(v, dict): build_xml(child, v)
                else: child.text = str(v)
        build_xml(root, results)
        tree = ET.ElementTree(root)
        tree.write(final_path)

    return final_path