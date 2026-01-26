# frontend/app.py - Simple FastAPI frontend

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import requests
import os

app = FastAPI()

CLIENT_ID = os.environ.get("CLIENT_ID")  # Set at deployment
FLOWER_SERVER = os.environ.get("FLOWER_SERVER", "http://flower-server:8081")
print(f"[FrontEnd] client ID {CLIENT_ID}  ")

@app.get("/")
async def index():
    html = open("static/index.html").read()
    return HTMLResponse(content=html.replace("{{CLIENT_ID}}", CLIENT_ID))

@app.get("/api/predict/{digit}")
async def predict_digit(digit: int):
    try:
        resp = requests.get(
            f"{FLOWER_SERVER}/predict_image/{digit}",
            params={"client_id": CLIENT_ID},
            timeout=10
        )
        # Check status and return appropriate response
        if resp.status_code == 403:
            error_data = resp.json()
            return {"error": error_data.get("detail", "Access denied"), "status": "denied"}
        elif resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"Unexpected status {resp.status_code}", "status": "error"}
             
    except Exception as ex:
        return {"error": str(ex)} 