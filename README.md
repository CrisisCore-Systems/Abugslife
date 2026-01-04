# Okta- and Bugcrowd-Aware Recon Automation

This repo contains a practical blueprint for a hunter-side automation stack tuned for Bugcrowd programs such as Okta and Auth0 by Okta. It focuses on predictable scope ingestion, job queues that prevent duplicate work, and worker images that map directly to common recon and scanning tasks.

## Components

- **Scope ingestion** pulls in-scope assets and policy flags from Bugcrowd pages or Okta's VDP PDF and records them in the database. The loader now tracks hashes of applied YAML files so unchanged files can be skipped automatically.
- **Queues and workers** split recon into discrete job types so concurrency and rate limits can be tuned per program.
- **Recon flow** connects subdomain discovery through HTTP probing, template scanning, and lead scoring.
- **OPSEC guardrails** encode Bugcrowd rules into scheduler limits and disabled job types.

## Getting started

1. **Create the database schema**
   ```sh
   psql $DSN -f config/schema.sql
   ```
2. **Seed programs and targets** (manual or scripted)
   - Start from `config/scopes.example.yaml` to capture program metadata, policy flags (with optional notes), disabled job types (with optional notes), and seed targets (with optional notes) for Okta/Auth0.
   - Skim the pre-flight banner printed by `load_scope.py`; it shows the file, DSN (password automatically masked), every safety toggle, a zero-guess quickstart with copy/paste commands, and a one-line summary per program so you know exactly what will happen before the database is touched.
   - Validate the file without touching the database (optional):
     ```sh
     python scripts/load_scope.py --file config/scopes.example.yaml --dry-run
     ```
   - Load the YAML into Postgres:
     ```sh
     pip install -r requirements.txt
     python scripts/load_scope.py --dsn "$DSN" --file config/scopes.example.yaml
     ```
   - Keep the database in sync with your current YAML snapshot by marking removed targets inactive (optional):
     ```sh
     python scripts/load_scope.py --dsn "$DSN" --file config/scopes.example.yaml --deactivate-missing
     ```
   - Remove disabled-job rows that you have deleted from the YAML (optional):
      ```sh
      python scripts/load_scope.py --dsn "$DSN" --file config/scopes.example.yaml --prune-disabled-jobs
      ```
   - Skip work entirely if the YAML hash is unchanged from a prior run (optional):
     ```sh
     python scripts/load_scope.py --dsn "$DSN" --file config/scopes.example.yaml --skip-if-unchanged
     ```
   - Need to bypass the schema guard? Pass `--skip-schema-check` (not recommended) after you have already applied `config/schema.sql`.
   - Get help when something goes wrong: the loader now prints human-readable hints next to validation errors (e.g., supported target types or a DSN example) so you can fix mistakes quickly. If you forget the DSN, it auto-switches to a dry-run so you still get feedback instead of an abrupt failure. Validation errors are listed per program so you can fix everything in one pass.
3. **Configure queues and workers**
   - Adopt the queue names and dead-letter routing in `config/queue_config.yaml`.
   - Build Docker images per worker role (recon, HTTP, vuln, visual, optional AI/analysis) and point workers at the queues.
4. **Run the workflow**
   - Schedule scope ingestion to refresh `programs` and `targets` (reuse the loader against fresh Bugcrowd exports).
   - Enqueue `subenum` for each wildcard/root target, then let downstream jobs fire automatically as new assets are discovered.
   - Review lead scores and template hits in your dashboard/alerts pipeline.

## Files

- `config/schema.sql` – Minimal Postgres schema for programs, targets (with active/inactive tracking), policy flags, rate limits, disabled job types, and job telemetry.
- `config/queue_config.yaml` – Queue names, bindings, and sensible defaults for per-program throttling.
- `config/scopes.example.yaml` – Okta/Auth0-focused seed data showing program flags, rate limits, and targets.
- `scripts/load_scope.py` – Loader that ingests the YAML into Postgres tables.
- `requirements.txt` – Python dependencies for the loader.
- `scope_loader_runs` table (created by the schema) – audit log of loader executions with input hash, counts applied, and toggles for deactivate/prune/skip modes.

## Notes for Okta/Auth0 programs

- Okta and Auth0 by Okta pay for P4+ only; encode `min_payable_severity = 'P4'`.
- Respect Bugcrowd rules: disable heavy auth brute forcing and DoS-style load; keep HTTP concurrency conservative.
- Tag all Okta/Auth0-derived assets so lead scoring and alerts can prioritize identity-surface changes.
