"""
SecureOps – VPS Deployment Pipeline
────────────────────────────────────────────────────────────────
Refactored to accept CLI arguments so it can be spawned by the
Express bridge (server.js) as a subprocess.

Usage (direct):
  python3 deployment.py \
    --api-key dop_v1_xxxx \
    --name web-prod-02 \
    --provider digitalocean \
    --os ubuntu-22-04-x64 \
    --size s-1vcpu-2gb \
    --region nyc3 \
    --ssh-key ~/.ssh/id_rsa.pub \
    --auto-scan

Usage (via Express /deploy endpoint):
  Spawned automatically by server.js.

Install dependencies:
  pip install requests fabric ansible-runner
"""

import argparse
import time
import sys
import requests
from pathlib import Path


# ── Provider API adapters ─────────────────────────────────────────────────────

class DigitalOceanAdapter:
    BASE = "https://api.digitalocean.com/v2"

    def __init__(self, api_key: str):
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def get_ssh_key_id(self, pub_key_path: str) -> list:
        """Upload local public key to DO and return its ID (or empty list)."""
        try:
            path = Path(pub_key_path).expanduser()
            pub_key = path.read_text().strip()
            # Check if key already registered
            existing = requests.get(f"{self.BASE}/account/keys", headers=self.headers).json()
            for k in existing.get("ssh_keys", []):
                if k["public_key"].strip() == pub_key:
                    print(f"[+] SSH key already registered: {k['id']}", flush=True)
                    return [k["id"]]
            # Register new key
            payload = {"name": "secureops-key", "public_key": pub_key}
            resp = requests.post(f"{self.BASE}/account/keys", json=payload, headers=self.headers)
            key_id = resp.json()["ssh_key"]["id"]
            print(f"[+] SSH key registered: {key_id}", flush=True)
            return [key_id]
        except Exception as e:
            print(f"[!] SSH key registration skipped: {e}", flush=True)
            return []

    def provision(self, name: str, os_image: str, size: str, region: str, ssh_keys: list) -> int:
        payload = {
            "name": name,
            "region": region,
            "size": size,
            "image": os_image,
            "ssh_keys": ssh_keys,
            "tags": ["secureops"],
        }
        resp = requests.post(f"{self.BASE}/droplets", json=payload, headers=self.headers)
        resp.raise_for_status()
        return resp.json()["droplet"]["id"]

    def wait_for_ip(self, droplet_id: int, timeout: int = 300) -> str:
        print("[+] Waiting for IP assignment…", flush=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = requests.get(f"{self.BASE}/droplets/{droplet_id}", headers=self.headers)
            droplet = resp.json()["droplet"]
            if droplet["status"] == "active":
                networks = droplet["networks"]["v4"]
                if networks:
                    ip = networks[0]["ip_address"]
                    print(f"[!] Instance Live: {ip}", flush=True)
                    return ip
            time.sleep(10)
        raise TimeoutError("Timed out waiting for instance IP")


class HetznerAdapter:
    BASE = "https://api.hetzner.cloud/v1"

    def __init__(self, api_key: str):
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def provision(self, name: str, os_image: str, size: str, region: str, ssh_keys: list) -> int:
        # Map DO-style size to Hetzner server type
        size_map = {
            "s-1vcpu-1gb": "cx11", "s-1vcpu-2gb": "cx21",
            "s-2vcpu-4gb": "cx31", "s-4vcpu-8gb": "cx41",
        }
        htz_size = size_map.get(size, "cx21")
        payload = {
            "name": name,
            "server_type": htz_size,
            "image": "ubuntu-22.04",
            "location": region if region.startswith("nb") else "nbg1",
            "ssh_keys": ssh_keys,
        }
        resp = requests.post(f"{self.BASE}/servers", json=payload, headers=self.headers)
        resp.raise_for_status()
        return resp.json()["server"]["id"]

    def wait_for_ip(self, server_id: int, timeout: int = 300) -> str:
        print("[+] Waiting for IP assignment…", flush=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = requests.get(f"{self.BASE}/servers/{server_id}", headers=self.headers)
            server = resp.json()["server"]
            if server["status"] == "running" and server["public_net"]["ipv4"]:
                ip = server["public_net"]["ipv4"]["ip"]
                print(f"[!] Instance Live: {ip}", flush=True)
                return ip
            time.sleep(10)
        raise TimeoutError("Timed out waiting for instance IP")


# ── Pipeline ──────────────────────────────────────────────────────────────────

class VPSDeploymentPipeline:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.provider = args.provider.lower().replace(" ", "_")

        if self.provider == "digitalocean":
            self.adapter = DigitalOceanAdapter(args.api_key)
        elif self.provider == "hetzner":
            self.adapter = HetznerAdapter(args.api_key)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}. Supported: digitalocean, hetzner")

    def provision_instance(self) -> str:
        print(f"[+] Provisioning {self.args.name} on {self.provider}…", flush=True)

        ssh_keys = []
        if hasattr(self.adapter, "get_ssh_key_id"):
            ssh_keys = self.adapter.get_ssh_key_id(self.args.ssh_key)

        instance_id = self.adapter.provision(
            name=self.args.name,
            os_image=self.args.os,
            size=self.args.size,
            region=self.args.region,
            ssh_keys=ssh_keys,
        )
        return self.adapter.wait_for_ip(instance_id)

    def harden_node(self, ip: str):
        """Run Ansible hardening playbook against the new instance."""
        import subprocess
        print(f"[+] Running Ansible hardening on {ip}…", flush=True)
        private_key = str(Path(self.args.ssh_key).expanduser()).replace(".pub", "")
        result = subprocess.run(
            [
                "ansible-playbook",
                "-i", f"{ip},",
                "-u", "root",
                "--private-key", private_key,
                "hardening.yml",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("[!] Hardening successful.", flush=True)
        else:
            print(f"[X] Hardening failed:\n{result.stderr}", flush=True)

    def run_openvas_scan(self, ip: str):
        """Trigger an OpenVAS baseline scan via gvm-cli."""
        import subprocess
        print(f"[+] Triggering OpenVAS scan for {ip}…", flush=True)
        try:
            xml = f"<create_target><name>{ip}</name><hosts>{ip}</hosts></create_target>"
            cmd = f"gvm-cli socket --xml '{xml}'"
            subprocess.run(cmd, shell=True, check=True)
            print(f"[!] OpenVAS scan initiated for {ip}. Check Greenbone dashboard.", flush=True)
        except Exception as e:
            print(f"[X] OpenVAS trigger failed: {e}", flush=True)

    def execute_pipeline(self):
        try:
            ip = self.provision_instance()
            self.harden_node(ip)
            if self.args.auto_scan:
                self.run_openvas_scan(ip)
            print(f"\n[SUCCESS] Pipeline complete. {self.args.name} is live at {ip}.", flush=True)
        except Exception as e:
            print(f"\n[FAILURE] Pipeline aborted: {e}", flush=True, file=sys.stderr)
            sys.exit(1)


# ── CLI entry point ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecureOps VPS Deployment Pipeline")
    parser.add_argument("--api-key",   required=True,  help="Provider API token")
    parser.add_argument("--name",      required=True,  help="Instance name (e.g. web-prod-02)")
    parser.add_argument("--provider",  default="digitalocean", help="digitalocean | hetzner")
    parser.add_argument("--os",        default="ubuntu-22-04-x64")
    parser.add_argument("--size",      default="s-1vcpu-2gb")
    parser.add_argument("--region",    default="nyc3")
    parser.add_argument("--ssh-key",   default="~/.ssh/id_rsa.pub")
    parser.add_argument("--auto-scan", action="store_true", help="Run OpenVAS after deploy")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    pipeline = VPSDeploymentPipeline(args)
    pipeline.execute_pipeline()
