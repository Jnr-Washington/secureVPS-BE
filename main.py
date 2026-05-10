from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from modules.cmsdetect import detect_cms
from modules.portscanner import run_nmap, port_scan
from modules.headerscanner import check_headers
from modules.deployment import VPSDeploymentPipeline
from modules.reportgen import generate_report

from db.base import Base
from db.session import engine, get_db
from schemas.user import SignupRequest, LoginRequest, TokenResponse, RefreshRequest, UserResponse
from services.auth_service import register_user, login_user, refresh_session, logout_user
from middleware.auth import get_current_user
from models.user import User
import models.user  # noqa: F401 — ensure models are registered with Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="SecureVPS API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Auth endpoints ───────────────────────────────────────────────────────────

@app.post("/auth/signup", response_model=UserResponse, status_code=201, tags=["auth"])
async def signup(body: SignupRequest, db: AsyncSession = Depends(get_db)):
    return await register_user(body.email, body.password, db)


@app.post("/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    access_token, refresh_token = await login_user(body.email, body.password, db)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@app.post("/auth/refresh", response_model=TokenResponse, tags=["auth"])
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    access_token, refresh_token = await refresh_session(body.refresh_token, db)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@app.post("/auth/logout", status_code=204, tags=["auth"])
async def logout(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    await logout_user(body.refresh_token, db)


@app.get("/auth/me", response_model=UserResponse, tags=["auth"])
async def me(current_user: User = Depends(get_current_user)):
    return current_user


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
