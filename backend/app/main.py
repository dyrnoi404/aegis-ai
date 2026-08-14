"""AEGIS AI core bootstrap."""

from fastapi import FastAPI

app = FastAPI(
    title="AEGIS AI",
    description="Local-first cybersecurity intelligence assistant",
    version="0.1.0",
)


@app.get("/")
def health():
    return {
        "name": "AEGIS AI",
        "version": "0.1.0",
        "status": "online",
    }
