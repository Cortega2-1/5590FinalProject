from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "5590 Final Project API is running"}
