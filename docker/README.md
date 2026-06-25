# Docker Notes

This directory contains local Docker support for SOC Copilot.

The current `docker-compose.yml` starts a PostgreSQL database with PGVector enabled. It is intended for local development and demos, not production deployment.

## Start PGVector

```bash
cd docker
cp .env.example .env
```

Edit `docker/.env` and set a local `POSTGRES_PASSWORD`.

```bash
docker compose up -d pgvector
docker compose ps
```

## Match the Backend Configuration

Set matching values in `src/.env`:

```dotenv
POSTGRES_USERNAME="postgres"
POSTGRES_PASSWORD="<same-value-as-docker-env>"
POSTGRES_HOST="localhost"
POSTGRES_PORT=5432
POSTGRES_MAIN_DATABASE="soc_copilot"
```

## Stop Services

```bash
docker compose down
```

To remove local database volumes during a reset:

```bash
docker compose down -v
```

Only run volume deletion when you are sure local demo data can be discarded.

## Files That Must Stay Local

- `docker/.env`
- `docker/env/.env.*` except `.env.example.*`
- `docker/mongodb/` or any other generated database directories
- Docker volume data, logs, and backups
