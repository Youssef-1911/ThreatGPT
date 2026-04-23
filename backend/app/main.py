from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import Base, engine, run_sqlite_migrations
from .routers import analysis, auth, documents, integrations, mitigations, projects, threats, versions, webhooks, reports
from .seed import seed_data_if_empty

Base.metadata.create_all(bind=engine)
run_sqlite_migrations()

app = FastAPI(title="ThreatGPT Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"] ,
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(threats.router)
app.include_router(mitigations.router)
app.include_router(documents.router)
app.include_router(versions.router)
app.include_router(analysis.router)
app.include_router(integrations.router)
app.include_router(webhooks.router)
app.include_router(reports.router)

@app.on_event("startup")
def seed_on_startup():
    seed_data_if_empty()

@app.get("/")
def root():
    return {"status": "ok"}
