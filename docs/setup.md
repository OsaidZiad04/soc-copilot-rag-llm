# Setup Guide

This guide prepares a local development environment for SOC Copilot.

## Prerequisites

- Python 3.11 or newer.
- Git.
- PostgreSQL with PGVector, or Docker Desktop / Docker Engine.
- An LLM backend:
  - local Ollama-compatible service, or
  - OpenAI-compatible API access.
- Cohere API key if `EMBEDDING_BACKEND="COHERE"`.

## 1. Create a Python Environment

```bash
git clone <your-repository-url>
cd soc-copilot-rag-llm
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install backend dependencies:

```bash
pip install -r src/requirements.txt
```

## 2. Configure Environment Variables

Copy the example file:

```bash
cp src/.env.example src/.env
```

Edit `src/.env` and replace placeholders:

```dotenv
POSTGRES_USERNAME="postgres"
POSTGRES_PASSWORD="<your-local-password>"
POSTGRES_HOST="localhost"
POSTGRES_PORT=5432
POSTGRES_MAIN_DATABASE="soc_copilot"

GENERATION_BACKEND="OLLAMA"
EMBEDDING_BACKEND="COHERE"

OPENAI_API_KEY="<api-key-or-empty-for-local-compatible-server>"
OPENAI_API_URL="http://localhost:11434/v1"
COHERE_API_KEY="<cohere-api-key>"
OLLAMA_API_URL="http://localhost:11434/v1"
```

Never commit `src/.env`.

## 3. Start PostgreSQL / PGVector

### Option A: Docker Compose

The current compose file starts a PGVector database.

```bash
cd docker
cp .env.example .env
```

Edit `docker/.env` and set `POSTGRES_PASSWORD`.

```bash
docker compose up -d pgvector
docker compose ps
```

Return to the repository root:

```bash
cd ..
```

### Option B: Existing PostgreSQL

Use an existing PostgreSQL instance with the PGVector extension enabled. Make sure `src/.env` points to that instance.

## 4. Run Database Migrations

`src/alembic.ini` contains placeholders for public repository safety. Replace them locally before running migrations, for example:

```ini
sqlalchemy.url = postgresql://postgres:<your-local-password>@localhost:5432/soc_copilot
```

Then run:

```bash
cd src
alembic upgrade head
```

## 5. Run the Backend

From `src/`:

```bash
uvicorn main:app --host 127.0.0.1 --port 8001 --reload
```

Useful URLs:

```text
http://127.0.0.1:8001/api/v1/
http://127.0.0.1:8001/docs
http://127.0.0.1:8001/web/
```

## 6. Run the Frontend

The frontend is static and is mounted by FastAPI from `web/`.

Open:

```text
http://127.0.0.1:8001/web/
```

Opening `web/index.html` directly may break API calls because the page expects the backend API to be available.

## 7. Optional Helper Scripts

The repository includes shell scripts under `scripts/`:

```bash
./scripts/start_all.sh
./scripts/status_api.sh
./scripts/stop_all.sh
```

These scripts are useful on Unix-like shells. On Windows, use Git Bash, WSL, or run the equivalent commands manually.

## 8. Safety Checklist Before Public Commit

- Keep `src/.env`, `docker/.env`, and `docker/env/.env.*` local.
- Do not commit `.run/`, virtual environments, uploaded files, local Docker database files, or caches.
- Do not commit real logs, malware samples, private incident data, or API keys.
- Replace team member placeholders in the README before final academic submission.
