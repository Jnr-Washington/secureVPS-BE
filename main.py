from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from modules.cmsdetect import detect_cms
from modules.portscanner import scan_ports

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

@app.post("/scan/cms")
async def start_cms_scan(request: ScanRequest):
    # Call your module function
    result = detect_cms(request.target)
    return {"target": request.target, "cms": result}

@app.post("/scan/ports")
async def start_port_scan(request: ScanRequest):
    result = scan_ports(request.target)
    return {"target": request.target, "open_ports": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)