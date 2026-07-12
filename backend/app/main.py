from fastapi import FastAPI
from app.scanner import list_iam_users

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
