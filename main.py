from fastapi import FastAPI
import uvicorn

app = FastAPI(
    title = "PhishEye",
    description = "API for detecting phishing URLs.",
    version = "0.1.0"
)

@app.get("/")
async def read_root():
    return {"message": "Welcome to PhishEye API"}

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "API is healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)