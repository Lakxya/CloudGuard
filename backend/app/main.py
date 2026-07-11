from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {
        "project": "CloudGuard",
        "status": "Running",
        "message": "Welcome to CloudGuard API!"
    }