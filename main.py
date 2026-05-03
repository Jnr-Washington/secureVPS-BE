from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from modules.cmsdetect import detect_cms
from modules.portscanner import run_nmap
from modules.portscanner import port_scan
from modules.headerscanner import check_headers
from modules.deployment import VPSDeploymentPipeline
from modules.directoryscan import directory_scan
from modules.reportgen import generate_report

app = FastAPI()

# Enable CORS for your React/Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], # Vite default port
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str

class DeployRequest(BaseModel):
    pass

@app.post("/deploy")
async def deploy_vps(request: DeployRequest):
    pipeline = VPSDeploymentPipeline(request)
    result = pipeline.execute_pipeline()
    return {"status": "ok", "ip": result}

@app.post("/vps/harden")
async def harden_vps(request: DeployRequest):
    harden = VPSDeploymentPipeline(request)
    result = harden.harden_node()
    return {"status": "ok", "ip": result}

@app.post("/vps/provision")
async def provision(request: DeployRequest):
    instance_provision = VPSDeploymentPipeline(request)
    result = instance_provision.provision_instance()
    return {"status": "ok", "ip": result}

@app.post("/scan/openvas")
async def start_openvas_scan(request: ScanRequest):
    openvas = VPSDeploymentPipeline(request)
    result = openvas.run_openvas_scan()
    return {"status": "ok", "ip": result}

@app.post("/scan/cms")
async def start_cms_scan(request: ScanRequest):
    # Call your module function
    result = detect_cms(request.target)
    return {"target": request.target, "cms": result}

@app.post("/scan/ports")
async def start_port_scan(request: ScanRequest):
    result = port_scan(request.target)
    return {"target": request.target, "open_ports": result}

@app.post("/scan/nmap")
async def start_nmap_scan(request: ScanRequest):
    result = run_nmap(request.target)
    return {"target": request.target, "nmap_scan_results": result}

@app.post("/scan/headers")
async def start_header_scan(request: ScanRequest):
    result = check_headers(request.target)
    return {"target": request.target, "headers": result}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)