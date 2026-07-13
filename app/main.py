from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.models import Base, engine
from app.routes.auth_routes import router as auth_router
from app.routes.customers import router as customers_router
from app.routes.detections import router as detections_router
from app.routes.incidents import router as incidents_router
from app.routes.signatures import router as signatures_router

app = FastAPI(title="Security Detection Platform")

templates = Jinja2Templates(directory="app/templates")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(auth_router)
app.include_router(customers_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(signatures_router)


@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return RedirectResponse(url="/login")


@app.get("/health")
def health_check():
    return {"status": "ok"}
