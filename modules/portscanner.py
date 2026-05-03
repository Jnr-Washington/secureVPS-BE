def port_scan(url):
    """
    Scans common ports using pure Python sockets. No dependencies required.

    Args:
        url (str): Target URL or hostname

    Returns:
        dict: Open ports with service and risk info
    """
    import socket
    from urllib.parse import urlparse
    from concurrent.futures import ThreadPoolExecutor, as_completed

    PORTS = {
        21:    "FTP",
        22:    "SSH",
        23:    "Telnet",
        25:    "SMTP",
        53:    "DNS",
        80:    "HTTP",
        110:   "POP3",
        143:   "IMAP",
        443:   "HTTPS",
        445:   "SMB",
        1433:  "MSSQL",
        3306:  "MySQL",
        3389:  "RDP",
        5432:  "PostgreSQL",
        5900:  "VNC",
        6379:  "Redis",
        8080:  "HTTP-Alt",
        8443:  "HTTPS-Alt",
        8888:  "HTTP-Dev",
        9200:  "Elasticsearch",
        27017: "MongoDB",
    }

    RISKS = {
        21:    "FTP — credentials sent in plaintext",
        22:    "SSH — brute force if weak credentials",
        23:    "Telnet — fully unencrypted, critical risk",
        25:    "SMTP — open relay possible",
        445:   "SMB — EternalBlue/ransomware target",
        1433:  "MSSQL — DB exposed to internet",
        3306:  "MySQL — DB exposed to internet",
        3389:  "RDP — brute force / BlueKeep target",
        5432:  "PostgreSQL — DB exposed to internet",
        5900:  "VNC — remote desktop, often no auth",
        6379:  "Redis — unauthenticated access common",
        9200:  "Elasticsearch — data exposure common",
        27017: "MongoDB — unauthenticated access common",
    }

    parsed = urlparse(url)
    host   = parsed.hostname or parsed.path.strip("/")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": f"Could not resolve host: {host}"}

    open_ports = []

    def probe(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except socket.error:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(probe, port): port for port in PORTS}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    open_ports.sort()

    findings = []
    for port in open_ports:
        findings.append({
            "port":    port,
            "service": PORTS.get(port, "Unknown"),
            "risk":    RISKS.get(port),
        })

    return {
        "host":       host,
        "ip":         ip,
        "open_ports": findings,
        "count":      len(findings),
        "method":     "python-socket",
    }


def run_nmap(url):
    """
    Runs a full Nmap scan with service detection, OS fingerprinting,
    and vuln scripts. Falls back gracefully if Nmap is not installed.

    Args:
        url (str): Target URL, hostname, or IP

    Returns:
        dict: Nmap findings including services, OS, and vulnerabilities
    """
    import subprocess
    import shutil
    from urllib.parse import urlparse

    if not shutil.which("nmap"):
        return {"error": "Nmap is not installed or not in PATH"}

    parsed = urlparse(url)
    host   = parsed.hostname or parsed.path.strip("/")

    if not host:
        return {"error": f"Could not extract host from: {url}"}

    findings = {
        "host":       host,
        "open_ports": [],
        "os_guess":   None,
        "services":   [],
        "vulns":      [],
        "raw":        "",
        "method":     "nmap",
    }

    base_cmd = ["nmap", "-sV", "-sC", "-O", "--open", "-T4", host]
    vuln_cmd = ["nmap", "--script", "vuln", "-T4", host]

    try:
        base_result = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        findings["raw"] = base_result.stdout

        for line in base_result.stdout.splitlines():
            line = line.strip()

            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    findings["open_ports"].append(parts[0])
                    findings["services"].append({
                        "port":    parts[0],
                        "service": parts[2],
                        "version": " ".join(parts[3:]) if len(parts) > 3 else "unknown",
                    })

            if "OS details:" in line or "Running:" in line:
                findings["os_guess"] = line.split(":", 1)[-1].strip()

        vuln_result = subprocess.run(
            vuln_cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        capture     = False
        current_vuln = []

        for line in vuln_result.stdout.splitlines():
            if "| " in line or "|_" in line:
                capture = True
            if capture:
                current_vuln.append(line.strip())
            if capture and line.strip() == "":
                if current_vuln:
                    findings["vulns"].append(" ".join(current_vuln))
                    current_vuln = []
                capture = False

        if current_vuln:
            findings["vulns"].append(" ".join(current_vuln))

    except subprocess.TimeoutExpired:
        findings["error"] = "Nmap scan timed out"
    except subprocess.SubprocessError as e:
        findings["error"] = str(e)

    return findings


if __name__ == "__main__":
    import shutil

    target = input("Enter target URL or IP: ").strip()
    mode   = input("Use Nmap if available? (Y/n): ").strip().lower()

    if mode != "n" and shutil.which("nmap"):
        print("\nNmap detected — running full scan...")
        results = run_nmap(target)
        print(f"\n[ NMAP SCAN — {results.get('host')} ]")
        print(f"  OS       : {results.get('os_guess') or 'Unknown'}")
        print(f"  Services :")
        for svc in results.get("services", []):
            print(f"    {svc['port']:<10} {svc['service']:<15} {svc['version']}")
        if results.get("vulns"):
            print("  Vulns:")
            for v in results["vulns"]:
                print(f"    - {v}")
    else:
        print("\nRunning pure Python port scan...")
        results = port_scan(target)
        if "error" in results:
            print(f"\n[ERROR] {results['error']}")
        else:
            print(f"\n[ PORT SCAN — {results['host']} ({results['ip']}) ]")
            print(f"  Open ports: {results['count']}\n")
            for item in results["open_ports"]:
                risk = f" ⚠ {item['risk']}" if item["risk"] else ""
                print(f"  {item['port']:<6} {item['service']:<20}{risk}")