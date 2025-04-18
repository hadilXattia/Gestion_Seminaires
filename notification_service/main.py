from fastapi import FastAPI
from notification_service.routers import notifications

app = FastAPI()

# Inclure les routes
app.include_router(notifications.router, tags=["events"])

@app.get("/")
async def root():
    return {"message": "Service is running"}
