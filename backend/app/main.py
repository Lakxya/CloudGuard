from fastapi import FastAPI
from app.scanner import list_iam_users, scan_admin_access
from app.scanner import scan_mfa, scan_inactive_access_keys

app = FastAPI()

@app.get("/")
def home():
    return {
        "project": "CloudGuard",
        "status": "Running",
        "message": "Welcome to CloudGuard API!"
    }

@app.get("/scan/iam")
def scan_iam():
    return list_iam_users()

@app.get("/scan/mfa")
def scan_mfa_endpoint():
    return scan_mfa()

@app.get("/scan/admin-access")
def scan_admin_access_endpoint():
    return scan_admin_access()

@app.get("/scan/inactive-access-keys")
def scan_inactive_access_keys_endpoint():
    return scan_inactive_access_keys()