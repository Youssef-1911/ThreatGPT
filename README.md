# ThreatGPT

AI-assisted threat modeling system for the SDLC.

## Overview
ThreatGPT automates threat modeling by:
- Ingesting security data (SAST, DAST, architecture)
- Parsing into a structured system model
- Generating threats, attack graphs, and scenarios
- Tracking changes through versioning

## Tech Stack
- Frontend: React
- Backend: FastAPI (Python)
- Database: SQLite
- AI: LLM-based parsing and generation

## How to Run

### Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

### Frontend
cd frontend
npm install
npm start
