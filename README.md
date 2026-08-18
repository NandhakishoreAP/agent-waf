# Agent WAF

An Agent Policy-Enforcing Proxy (WAF) designed to sit between an autonomous AI agent and its tools. It intercepts every tool invocation, evaluates rate-limit, parameter-validation, data-scope, and sequence rules, maintains an audit trail logs table, provides a real-time WebSocket dashboard, integrations, and supports shadow mode.

## Current Development Status
- **Milestone 1 (Scaffold):** Completed. Minimal application structure is set up with Fast API server, Docker environment, and base package directories.
- **Milestone 2 (Database & Rule Engine):** Pending implementation.
- **Milestone 3 (WAF Proxy & Dashboard):** Pending implementation.

---

## Local Setup Instructions

### 1. Set Up Environment Variables
Copy the example environment file:
```bash
cp .env.example .env
```

### 2. Create and Activate Virtual Environment
Create a virtual environment using Python 3.11:
```bash
python3.11 -m venv .venv
```

Activate the virtual environment:
- **On Linux/macOS:**
  ```bash
  source .venv/bin/activate
  ```
- **On Windows:**
  ```cmd
  .venv\Scripts\activate
  ```

### 3. Install Requirements
Install the required dependencies:
```bash
pip install -r requirements.txt
```

### 4. Start FastAPI Locally
Run the FastAPI application with Uvicorn:
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 5. Access the API
- Main entrypoint: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- Health check endpoint: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- API interactive docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Running with Docker Compose

To build and spin up the Agent WAF service container:
```bash
docker-compose up --build
```
This starts the service and exposes it at [http://localhost:8000](http://localhost:8000).
