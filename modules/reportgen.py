def generate_report(results, output_path=None):
    """
    Generates a styled HTML report from scan results.

    Args:
        results     (dict): Full scan results from run_scan()
        output_path (str):  Optional file path. Auto-named if not provided.

    Returns:
        str: Path to the generated HTML file
    """
    import json
    from datetime import datetime, timezone
    from urllib.parse import urlparse

    meta      = results.get("meta", {})
    target    = meta.get("target", "Unknown")
    timestamp = meta.get("timestamp", datetime.now(timezone.utc).isoformat())

    def severity_color(severity):
        return {
            "High":     "#ff4d4d",
            "Medium":   "#ff9900",
            "Low":      "#f0c040",
            "Critical": "#cc0000",
            "Info":     "#4da6ff",
        }.get(severity, "#aaaaaa")

    def score_results():
        score = 0
        headers = results.get("headers", [])
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict):
                    score += {"High": 30, "Medium": 15, "Low": 5, "Critical": 50}.get(h.get("severity"), 0)

        dirs = results.get("directories", [])
        if isinstance(dirs, list):
            score += len([d for d in dirs if isinstance(d, dict) and "url" in d]) * 10

        ports = results.get("ports", {}).get("open_ports", [])
        score += len([p for p in ports if p.get("risk")]) * 20

        cms = results.get("cms", {}).get("risks", [])
        score += len(cms) * 15

        if score >= 100: return "CRITICAL", "#cc0000"
        if score >= 60:  return "HIGH",     "#ff4d4d"
        if score >= 30:  return "MEDIUM",   "#ff9900"
        return "LOW", "#4caf50"

    risk_label, risk_color = score_results()

    def render_headers():
        headers = results.get("headers", [])
        if not isinstance(headers, list) or not headers:
            return "<p class='none'>No issues found.</p>"
        rows = ""
        for h in headers:
            if not isinstance(h, dict):
                continue
            color = severity_color(h.get("severity", ""))
            rows += f"""
            <tr>
                <td><span class='badge' style='background:{color}'>{h.get('severity','?')}</span></td>
                <td>{h.get('issue','')}</td>
                <td><code>{h.get('header','')}</code></td>
            </tr>"""
        return f"<table><tr><th>Severity</th><th>Issue</th><th>Header</th></tr>{rows}</table>"

    def render_directories():
        dirs = results.get("directories", [])
        if not isinstance(dirs, list) or not dirs:
            return "<p class='none'>No directories found.</p>"
        rows = ""
        for d in dirs:
            if not isinstance(d, dict):
                continue
            if "info" in d or "error" in d:
                return f"<p class='none'>{list(d.values())[0]}</p>"
            status = d.get("status", "?")
            color  = "#4caf50" if status == 200 else "#ff9900"
            rows += f"""
            <tr>
                <td><span class='badge' style='background:{color}'>{status}</span></td>
                <td><a href='{d.get('url','')}' target='_blank'>{d.get('url','')}</a></td>
                <td>{d.get('size', 0)} bytes</td>
            </tr>"""
        return f"<table><tr><th>Status</th><th>URL</th><th>Size</th></tr>{rows}</table>"

    def render_links():
        links = results.get("links", {})
        if isinstance(links, dict) and "error" not in links:
            internal = links.get("internal", [])
            external = links.get("external", [])
            int_list = "".join(f"<li><a href='{l}' target='_blank'>{l}</a></li>" for l in internal[:20])
            ext_list = "".join(f"<li><a href='{l}' target='_blank'>{l}</a></li>" for l in external[:20])
            return f"""
            <p><strong>Internal ({len(internal)})</strong></p>
            <ul class='link-list'>{int_list}{'<li>...and more</li>' if len(internal) > 20 else ''}</ul>
            <p><strong>External ({len(external)})</strong></p>
            <ul class='link-list'>{ext_list}{'<li>...and more</li>' if len(external) > 20 else ''}</ul>
            """
        return "<p class='none'>No links found.</p>"

    def render_ports():
        ports = results.get("ports", {})
        if not ports or "error" in ports:
            return f"<p class='none'>{ports.get('error', 'Port scan not run.')}</p>"
        open_ports = ports.get("open_ports", [])
        if not open_ports:
            return "<p class='none'>No open ports found.</p>"
        rows = ""
        for p in open_ports:
            risk  = p.get("risk")
            color = "#ff4d4d" if risk else "#4caf50"
            rows += f"""
            <tr>
                <td><strong>{p['port']}</strong></td>
                <td>{p['service']}</td>
                <td style='color:{color}'>{risk or '—'}</td>
            </tr>"""
        return f"<table><tr><th>Port</th><th>Service</th><th>Risk</th></tr>{rows}</table>"

    def render_cms():
        cms = results.get("cms", {})
        if not cms or "error" in cms:
            return "<p class='none'>CMS detection not run.</p>"
        detected = cms.get("detected", [])
        risks    = cms.get("risks", [])
        if not detected:
            return "<p class='none'>No CMS/technology identified.</p>"
        tech_tags = "".join(f"<span class='tech-tag'>{t}</span>" for t in detected)
        risk_items = "".join(f"<li>⚠ {r}</li>" for r in risks)
        return f"<div class='tech-tags'>{tech_tags}</div><ul class='risk-list'>{risk_items}</ul>"

    def render_subdomains():
        subs = results.get("subdomains", {})
        if not subs or "error" in subs:
            return "<p class='none'>Subdomain scan not run.</p>"
        found = subs.get("found", [])
        if not found:
            return "<p class='none'>No subdomains discovered.</p>"
        rows = ""
        for s in found:
            status = s.get("status") or "N/A"
            color  = "#4caf50" if status == 200 else "#ff9900"
            rows += f"""
            <tr>
                <td><a href='{s.get('url','')}' target='_blank'>{s.get('subdomain','')}</a></td>
                <td>{s.get('ip','')}</td>
                <td><span class='badge' style='background:{color}'>{status}</span></td>
            </tr>"""
        return f"<table><tr><th>Subdomain</th><th>IP</th><th>Status</th></tr>{rows}</table>"

    def render_vuln(key, label):
        data = results.get(key, {})
        if isinstance(data, dict):
            if "skipped" in data:
                return f"<p class='none'>Skipped: {data['skipped']}</p>"
            if "error" in data:
                return f"<p class='none'>Error: {data['error']}</p>"
        if isinstance(data, list):
            clean = [d for d in data if isinstance(d, dict) and d.get("type") != "clean"]
            if not clean:
                return "<p class='none'>No vulnerabilities found.</p>"
            rows = ""
            for item in clean:
                rows += f"""
                <tr>
                    <td><span class='badge' style='background:#ff4d4d'>{item.get('type','?')}</span></td>
                    <td><code>{item.get('parameter','')}</code></td>
                    <td><code>{item.get('payload','')}</code></td>
                    <td><a href='{item.get('url','')}' target='_blank'>View</a></td>
                </tr>"""
            return f"<table><tr><th>Type</th><th>Parameter</th><th>Payload</th><th>URL</th></tr>{rows}</table>"
        return "<p class='none'>No data.</p>"

    def render_summary():
        ADVICE = {
            "Missing X-Frame-Options": {
                "priority": "High",
                "action":   "Add <code>X-Frame-Options: DENY</code> to your server response headers to prevent clickjacking attacks."
            },
            "Missing Content-Security-Policy": {
                "priority": "High",
                "action":   "Define a <code>Content-Security-Policy</code> header to restrict which scripts, styles, and resources the browser can load."
            },
            "Missing Strict-Transport-Security": {
                "priority": "High",
                "action":   "Add <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code> to enforce HTTPS-only connections."
            },
            "Missing X-Content-Type-Options": {
                "priority": "Medium",
                "action":   "Add <code>X-Content-Type-Options: nosniff</code> to prevent browsers from MIME-sniffing responses."
            },
            "Missing X-XSS-Protection": {
                "priority": "Medium",
                "action":   "Add <code>X-XSS-Protection: 1; mode=block</code> to enable browser-level XSS filtering."
            },
            "Missing Referrer-Policy": {
                "priority": "Low",
                "action":   "Add <code>Referrer-Policy: strict-origin-when-cross-origin</code> to control referrer information leakage."
            },
            "Missing Permissions-Policy": {
                "priority": "Low",
                "action":   "Add a <code>Permissions-Policy</code> header to restrict access to browser features like camera, microphone, and geolocation."
            },
            "Missing Cache-Control": {
                "priority": "Low",
                "action":   "Add <code>Cache-Control: no-store</code> on sensitive pages to prevent browsers from caching private data."
            },
        }

        PORT_ADVICE = {
            21:    ("High",   "Disable FTP or replace with SFTP. FTP sends credentials in plaintext."),
            22:    ("Medium", "Restrict SSH access by IP using firewall rules. Disable password auth, use key-based auth only."),
            23:    ("High",   "Disable Telnet immediately. It is fully unencrypted. Use SSH instead."),
            25:    ("Medium", "Configure SMTP to require authentication. Check for open relay misconfiguration."),
            445:   ("High",   "Block SMB port 445 from public internet access. Apply MS17-010 patch if not done."),
            1433:  ("High",   "Block MSSQL port from public internet. Database ports should never be publicly exposed."),
            3306:  ("High",   "Block MySQL port from public internet. Bind to localhost only in my.cnf."),
            3389:  ("High",   "Restrict RDP access by IP. Enable Network Level Authentication and use strong passwords."),
            5432:  ("High",   "Block PostgreSQL port from public internet. Bind to localhost in postgresql.conf."),
            5900:  ("High",   "Disable VNC or restrict by IP. Enable VNC authentication if it must remain active."),
            6379:  ("High",   "Bind Redis to localhost only. Enable Redis AUTH password in redis.conf."),
            9200:  ("High",   "Restrict Elasticsearch to localhost or VPN. Unauthenticated instances expose all data."),
            27017: ("High",   "Bind MongoDB to localhost. Enable authentication in mongod.conf."),
        }

        items = []

        headers = results.get("headers", [])
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict) and h.get("issue") in ADVICE:
                    advice = ADVICE[h["issue"]]
                    items.append({
                        "priority": advice["priority"],
                        "source":   "Headers",
                        "finding":  h["issue"],
                        "action":   advice["action"],
                    })

        ports = results.get("ports", {}).get("open_ports", [])
        for p in ports:
            port_num = p.get("port")
            if port_num in PORT_ADVICE:
                priority, action = PORT_ADVICE[port_num]
                items.append({
                    "priority": priority,
                    "source":   "Ports",
                    "finding":  f"Port {port_num} ({p.get('service','')}) exposed",
                    "action":   action,
                })

        cms = results.get("cms", {})
        if isinstance(cms, dict):
            detected = cms.get("detected", [])
            if "WordPress" in detected:
                items.append({
                    "priority": "High",
                    "source":   "CMS",
                    "finding":  "WordPress xmlrpc.php exposed",
                    "action":   "Disable xmlrpc.php by adding <code>deny from all</code> in .htaccess or blocking it in Nginx config.",
                })
                items.append({
                    "priority": "Medium",
                    "source":   "CMS",
                    "finding":  "WordPress REST API user enumeration",
                    "action":   "Block <code>/wp-json/wp/v2/users</code> endpoint or require authentication to access it.",
                })

        sqli = results.get("sqli", [])
        if isinstance(sqli, list) and any(d.get("type") not in ("clean", "info") for d in sqli if isinstance(d, dict)):
            items.append({
                "priority": "Critical",
                "source":   "SQLi",
                "finding":  "SQL Injection vulnerability detected",
                "action":   "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            })

        xss = results.get("xss", [])
        if isinstance(xss, list) and any(d.get("type") not in ("clean", "info") for d in xss if isinstance(d, dict)):
            items.append({
                "priority": "Critical",
                "source":   "XSS",
                "finding":  "Cross-Site Scripting vulnerability detected",
                "action":   "Sanitize and encode all user input before rendering. Implement a strict Content-Security-Policy.",
            })

        dirs = results.get("directories", [])
        if isinstance(dirs, list) and any("url" in d for d in dirs if isinstance(d, dict)):
            items.append({
                "priority": "Medium",
                "source":   "Directories",
                "finding":  "Hidden directories accessible",
                "action":   "Review each discovered path. Restrict access with authentication or remove endpoints that should not be public.",
            })

        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        items.sort(key=lambda x: order.get(x["priority"], 4))

        if not items:
            return "<p class='none'>No actionable findings.</p>"

        rows = ""
        for i, item in enumerate(items, 1):
            color = severity_color(item["priority"])
            rows += f"""
            <tr>
                <td style='color:#888;font-size:0.8rem'>{i}</td>
                <td><span class='badge' style='background:{color}'>{item['priority']}</span></td>
                <td style='color:#aaa;font-size:0.8rem'>{item['source']}</td>
                <td>{item['finding']}</td>
                <td style='font-size:0.82rem;color:#ccc'>{item['action']}</td>
            </tr>"""

        return f"<table><tr><th>#</th><th>Priority</th><th>Source</th><th>Finding</th><th>Recommended Action</th></tr>{rows}</table>"

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>Scan Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d0d0d; color: #e0e0e0; padding: 30px; }}
  h1 {{ font-size: 1.6rem; color: #fff; margin-bottom: 4px; }}
  .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 30px; }}
  .risk-banner {{ display: inline-block; padding: 8px 20px; border-radius: 6px;
                  font-weight: bold; font-size: 1rem; margin-bottom: 30px;
                  background: {risk_color}22; color: {risk_color};
                  border: 1px solid {risk_color}; }}
  .section {{ background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 10px;
              padding: 20px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 1rem; color: #ccc; margin-bottom: 14px;
                 text-transform: uppercase; letter-spacing: 1px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; color: #888; padding: 8px; border-bottom: 1px solid #2a2a2a; }}
  td {{ padding: 8px; border-bottom: 1px solid #1e1e1e; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  a {{ color: #4da6ff; text-decoration: none; word-break: break-all; }}
  a:hover {{ text-decoration: underline; }}
  code {{ background: #252525; padding: 2px 6px; border-radius: 4px;
          font-family: monospace; font-size: 0.8rem; word-break: break-all; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            font-size: 0.75rem; font-weight: bold; color: #fff; }}
  .none {{ color: #555; font-style: italic; font-size: 0.85rem; }}
  .tech-tag {{ display: inline-block; background: #252525; border: 1px solid #333;
               padding: 4px 12px; border-radius: 20px; margin: 4px;
               font-size: 0.85rem; color: #4da6ff; }}
  .tech-tags {{ margin-bottom: 12px; }}
  .risk-list {{ padding-left: 18px; font-size: 0.85rem; color: #ff9900; }}
  .risk-list li {{ margin-bottom: 6px; }}
  .link-list {{ padding-left: 18px; font-size: 0.8rem; }}
  .link-list li {{ margin-bottom: 4px; }}
</style>
</head>
<body>
<h1>🔍 Scan Report</h1>
<p class='meta'>Target: <strong>{target}</strong> &nbsp;|&nbsp; {timestamp}</p>
<div class='risk-banner'>Overall Risk: {risk_label}</div>

<div class='section'>
  <h2>⚡ Actionable Summary</h2>
  {render_summary()}
</div>

<div class='section'>
  <h2>Security Headers</h2>
  {render_headers()}
</div>

<div class='section'>
  <h2>CMS / Technology Detection</h2>
  {render_cms()}
</div>

<div class='section'>
  <h2>Open Ports</h2>
  {render_ports()}
</div>

<div class='section'>
  <h2>Directories</h2>
  {render_directories()}
</div>

<div class='section'>
  <h2>Subdomains</h2>
  {render_subdomains()}
</div>

<div class='section'>
  <h2>SQL Injection</h2>
  {render_vuln('sqli', 'SQLi')}
</div>

<div class='section'>
  <h2>Cross-Site Scripting (XSS)</h2>
  {render_vuln('xss', 'XSS')}
</div>

<div class='section'>
  <h2>Links</h2>
  {render_links()}
</div>

</body>
</html>"""

    if not output_path:
        import os
        host        = urlparse(target).netloc or target
        ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")  # ← this line
        os.makedirs(reports_dir, exist_ok=True)
        output_path = os.path.join(reports_dir, f"scan_{host}_{ts}.html")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path