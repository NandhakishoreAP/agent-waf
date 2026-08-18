from fastapi import FastAPI

app = FastAPI(title="Agent WAF")


@app.get("/")
def read_root():
    return {
        "service": "Agent WAF",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok"
    }
