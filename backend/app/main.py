from fastapi import FastAPI
from app.scanner import list_iam_users
from app.scanner import scan_mfa

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