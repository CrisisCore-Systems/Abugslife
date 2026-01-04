"""Load Bugcrowd/Okta-aware scope definitions into Postgres.

Features
========
- Validates program, target, and disabled job fields before writing to the database.
- Upserts programs, policy flags (with optional notes), rate limits, targets (with notes), and disabled job types.
- Optional "dry run" mode for quick validation without touching the DB.
- Optional deactivation of targets that are missing from the current YAML snapshot.
- Optional pruning of disabled jobs removed from the YAML.
- Optional change detection that skips a write when the scope file hash matches a previous run.
- Automatic dry-run fallback if you forget the DSN so you always get feedback instead of an abrupt exit.

Requires:
- psycopg2-binary
- PyYAML

Usage:
    python scripts/load_scope.py --dsn "$DSN" --file config/scopes.example.yaml
    python scripts/load_scope.py --file config/scopes.example.yaml --dry-run
    python scripts/load_scope.py --dsn "$DSN" --file config/scopes.example.yaml --deactivate-missing

UX goals:
    - Be ridiculously easy to run: obvious pre-flight summary, zero-surprise defaults.
    - Fail loudly *and* helpfully: every validation error includes a concrete fix.
    - Print what will happen before touching the DB so you can bail early if needed.
    - Celebrate the happy path: visible green checkmarks when validation or loading succeeds.
"""

import argparse
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence

import psycopg2
import yaml

PROGRAM_RATE_LIMIT_FIELDS = {
    "max_concurrent_jobs",
    "max_requests_per_minute",
    "max_http_qps",
}


ALLOWED_TARGET_TYPES = {
    "domain",
    "wildcard",
    "api",
    "mobile_app",
    "desktop_app",
    "other",
}


ALLOWED_SCOPE_TYPES = {"limited", "wide", "open"}
ALLOWED_SEVERITIES = {"P1", "P2", "P3", "P4", "P5"}
ALLOWED_JOB_TYPES = {
    "subenum",
    "alive_scan",
    "port_scan",
    "vuln_scan",
    "metadata",
    "lead_scoring",
}
ALLOWED_SOURCES = {"manual", "bugcrowd", "vdppdf", "automation"}
REQUIRED_TABLES = {
    "programs",
    "program_policy_flags",
    "program_rate_limits",
    "program_disabled_jobs",
    "targets",
    "scope_loader_runs",
}


@dataclass
class LoaderSummary:
    programs: int = 0
    targets: int = 0
    disabled_jobs: int = 0
    deactivated_targets: int = 0
    pruned_disabled_jobs: int = 0


class ScopeLoader:
    def __init__(
        self,
        dsn: str | None = None,
        dry_run: bool = False,
        deactivate_missing: bool = False,
        prune_disabled_jobs: bool = False,
        skip_if_unchanged: bool = False,
        schema_check: bool = True,
    ):
        self.dry_run = dry_run
        self.deactivate_missing = deactivate_missing
        self.prune_disabled_jobs = prune_disabled_jobs
        self.skip_if_unchanged = skip_if_unchanged
        self.schema_check = schema_check
        self.summary = LoaderSummary()
        self.skipped_due_to_hash = False
        self.conn = None if dry_run else psycopg2.connect(dsn)
        if self.conn:
            self.conn.autocommit = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.conn:
            return
        if exc:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

    def _validate_program(self, program: Mapping[str, object]):
        required_fields = {"name", "program_url", "scope_type", "min_payable_severity"}
        missing = required_fields - set(program.keys())
        if missing:
            raise ValueError(
                f"Program '{program.get('name', '<unknown>')}' missing required fields: {', '.join(sorted(missing))}"
            )
        scope_type = str(program["scope_type"]).lower()
        if scope_type not in ALLOWED_SCOPE_TYPES:
            raise ValueError(f"Invalid scope_type '{scope_type}' for program {program['name']}")
        severity = str(program["min_payable_severity"]).upper()
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid min_payable_severity '{severity}' for program {program['name']}")
        url = str(program["program_url"])
        if not url.startswith("http://") and not url.startswith("https://"):
            raise ValueError(f"Program URL must be absolute (got '{url}') for {program['name']}")

    def _validate_targets(self, targets: Sequence[Mapping[str, object]]):
        seen_keys: set[tuple[str, str]] = set()
        for target in targets:
            required_fields = {"target", "target_type"}
            missing = required_fields - set(target.keys())
            if missing:
                raise ValueError(f"Target missing required fields: {', '.join(sorted(missing))}")
            target_type = str(target["target_type"]).lower()
            if target_type not in ALLOWED_TARGET_TYPES:
                raise ValueError(f"Unsupported target_type: {target_type}")
            source = str(target.get("source", "automation"))
            if source not in ALLOWED_SOURCES:
                raise ValueError(f"Unsupported source '{source}' for target {target['target']}")
            key = (target["target"], target_type)
            if key in seen_keys:
                raise ValueError(f"Duplicate target entry detected: {target['target']} ({target_type})")
            seen_keys.add(key)

    def _validate_disabled_jobs(self, disabled_jobs: Iterable[Mapping[str, object]] | Iterable[str]):
        seen: set[str] = set()
        for job_entry in disabled_jobs:
            if isinstance(job_entry, str):
                job_type = job_entry
            else:
                job_type = str(job_entry.get("job_type"))
            if job_type not in ALLOWED_JOB_TYPES:
                raise ValueError(f"Unsupported disabled job type: {job_type}")
            if job_type in seen:
                raise ValueError(f"Duplicate disabled job '{job_type}' declared")
            seen.add(job_type)

    def upsert_program(self, cur, program: MutableMapping[str, object]) -> int:
        program["scope_type"] = str(program["scope_type"]).lower()
        program["min_payable_severity"] = str(program["min_payable_severity"]).upper()
        cur.execute(
            """
            INSERT INTO programs (name, platform, program_url, scope_type, min_payable_severity)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE
            SET platform = EXCLUDED.platform,
                program_url = EXCLUDED.program_url,
                scope_type = EXCLUDED.scope_type,
                min_payable_severity = EXCLUDED.min_payable_severity
            RETURNING id;
            """,
            (
                program["name"],
                program.get("platform", "bugcrowd"),
                program["program_url"],
                program["scope_type"],
                program["min_payable_severity"],
            ),
        )
        (program_id,) = cur.fetchone()
        return program_id

    def _parse_policy_flag(self, flag: str, value: object) -> tuple[bool, str | None]:
        if isinstance(value, Mapping):
            return bool(value.get("value", True)), value.get("note")
        return bool(value), None

    def upsert_policy_flags(self, cur, program_id: int, flags: Mapping[str, object]):
        for flag, raw_value in flags.items():
            value, note = self._parse_policy_flag(flag, raw_value)
            cur.execute(
                """
                INSERT INTO program_policy_flags (program_id, flag, value, note)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (program_id, flag) DO UPDATE
                SET value = EXCLUDED.value,
                    note = EXCLUDED.note;
                """,
                (program_id, flag, value, note),
            )

    def upsert_rate_limits(self, cur, program_id: int, rate_limits: Mapping[str, object]):
        limited = {k: rate_limits[k] for k in PROGRAM_RATE_LIMIT_FIELDS if k in rate_limits}
        if not limited:
            return
        cur.execute(
            """
            INSERT INTO program_rate_limits (program_id, max_concurrent_jobs, max_requests_per_minute, max_http_qps)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (program_id) DO UPDATE
            SET max_concurrent_jobs = EXCLUDED.max_concurrent_jobs,
                max_requests_per_minute = EXCLUDED.max_requests_per_minute,
                max_http_qps = EXCLUDED.max_http_qps;
            """,
            (
                program_id,
                limited.get("max_concurrent_jobs", 5),
                limited.get("max_requests_per_minute", 300),
                limited.get("max_http_qps", 1.0),
            ),
        )

    def _parse_disabled_job(self, job_entry: str | Mapping[str, object]) -> tuple[str, str | None]:
        if isinstance(job_entry, str):
            return job_entry, None
        return str(job_entry.get("job_type")), job_entry.get("note")

    def upsert_disabled_jobs(self, cur, program_id: int, disabled_jobs: Iterable[str | Mapping[str, object]]):
        seen_db: set[str] = set()
        for job_entry in disabled_jobs:
            job_type, note = self._parse_disabled_job(job_entry)
            cur.execute(
                """
                INSERT INTO program_disabled_jobs (program_id, job_type, note)
                VALUES (%s, %s, %s)
                ON CONFLICT (program_id, job_type) DO UPDATE
                SET note = COALESCE(EXCLUDED.note, program_disabled_jobs.note);
                """,
                (program_id, job_type, note),
            )
            seen_db.add(job_type)
            self.summary.disabled_jobs += 1
        if self.prune_disabled_jobs:
            cur.execute(
                """
                DELETE FROM program_disabled_jobs
                WHERE program_id = %s AND job_type <> ALL(%s);
                """,
                (program_id, list(seen_db) or ["__no_jobs__"]),
            )
            self.summary.pruned_disabled_jobs += cur.rowcount

    def _existing_target_keys(self, cur, program_id: int) -> set[tuple[str, str]]:
        cur.execute(
            """
            SELECT target, target_type
            FROM targets
            WHERE program_id = %s;
            """,
            (program_id,),
        )
        return {(target, target_type) for target, target_type in cur.fetchall()}

    def _deactivate_missing(self, cur, program_id: int, missing_keys: set[tuple[str, str]]):
        if not missing_keys:
            return
        cur.executemany(
            """
            UPDATE targets
            SET active = FALSE, last_seen = NOW()
            WHERE program_id = %s AND target = %s AND target_type = %s;
            """,
            [(program_id, target, target_type) for target, target_type in missing_keys],
        )
        self.summary.deactivated_targets += cur.rowcount

    def upsert_targets(self, cur, program_id: int, targets: Sequence[Mapping[str, object]]):
        seen_keys: set[tuple[str, str]] = set()
        for target in targets:
            target_type = str(target["target_type"]).lower()
            cur.execute(
                """
                INSERT INTO targets (program_id, target, target_type, source, wildcard, policy_flags, note, active, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (program_id, target, target_type) DO UPDATE
                SET policy_flags = EXCLUDED.policy_flags,
                    wildcard = EXCLUDED.wildcard,
                    note = COALESCE(EXCLUDED.note, targets.note),
                    active = TRUE,
                    last_seen = NOW();
                """,
                (
                    program_id,
                    target["target"],
                    target_type,
                    target.get("source", "automation"),
                    bool(target.get("wildcard", False)),
                    target.get("policy_flags", []),
                    target.get("note"),
                ),
            )
            seen_keys.add((target["target"], target_type))
            self.summary.targets += 1

        if self.deactivate_missing:
            existing_keys = self._existing_target_keys(cur, program_id)
            missing = existing_keys - seen_keys
            self._deactivate_missing(cur, program_id, missing)

    def _hash_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _already_processed(self, cur, file_hash: str) -> bool:
        cur.execute(
            """
            SELECT 1 FROM scope_loader_runs
            WHERE file_hash = %s AND dry_run = FALSE
            LIMIT 1;
            """,
            (file_hash,),
        )
        return cur.fetchone() is not None

    def _record_loader_run(self, cur, source_path: Path, file_hash: str):
        cur.execute(
            """
            INSERT INTO scope_loader_runs (
                source_path, file_hash, dry_run, deactivate_missing, prune_disabled_jobs,
                skip_if_unchanged, programs_processed, targets_processed, disabled_jobs_processed,
                deactivated_targets, pruned_disabled_jobs
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (
                str(source_path),
                file_hash,
                self.dry_run,
                self.deactivate_missing,
                self.prune_disabled_jobs,
                self.skip_if_unchanged,
                self.summary.programs,
                self.summary.targets,
                self.summary.disabled_jobs,
                self.summary.deactivated_targets,
                self.summary.pruned_disabled_jobs,
            ),
        )

    def _ensure_schema(self, cur):
        cur.execute(
            """
            SELECT tablename
            FROM pg_catalog.pg_tables
            WHERE schemaname = 'public' AND tablename = ANY(%s);
            """,
            (list(REQUIRED_TABLES),),
        )
        present = {row[0] for row in cur.fetchall()}
        missing = REQUIRED_TABLES - present
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise ValueError(
                "Schema check failed: missing table(s): "
                f"{missing_list}. Run 'psql -f config/schema.sql' then retry."
            )

    def load(self, path: Path, data: Mapping[str, object] | None = None):
        if data is None:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

        programs = data.get("programs", [])
        if not programs:
            raise ValueError("No programs defined in scope file")

        file_hash = self._hash_file(path)

        self._validate_programs(programs, verbose=self.dry_run)

        if self.dry_run:
            return

        with self.conn.cursor() as cur:
            if self.schema_check:
                self._ensure_schema(cur)
            if self.skip_if_unchanged and self._already_processed(cur, file_hash):
                print(f"Skipping load: hash {file_hash[:12]} already applied.")
                self.skipped_due_to_hash = True
                return

            for program in programs:
                program_id = self.upsert_program(cur, program)
                self.summary.programs += 1
                self.upsert_policy_flags(cur, program_id, program.get("policy_flags", {}))
                self.upsert_rate_limits(cur, program_id, program.get("rate_limits", {}))
                self.upsert_disabled_jobs(cur, program_id, program.get("disabled_jobs", []))
                self.upsert_targets(cur, program_id, program.get("targets", []))

            self._record_loader_run(cur, path, file_hash)

    def _validate_programs(self, programs: Sequence[Mapping[str, object]], verbose: bool = False):
        seen_programs: set[str] = set()
        errors: list[str] = []
        for idx, program in enumerate(programs, start=1):
            try:
                name = str(program.get("name"))
                if name in seen_programs:
                    raise ValueError(f"Duplicate program name in YAML: {name}")
                seen_programs.add(name)
                self._validate_program(program)
                self._validate_targets(program.get("targets", []))
                self._validate_disabled_jobs(program.get("disabled_jobs", []))
            except ValueError as exc:
                errors.append(f"#{idx} ({program.get('name', '<unnamed>')}): {exc}")
        if errors:
            bullet_list = "\n - " + "\n - ".join(errors)
            raise ValueError(f"Validation failed for {len(errors)} program(s):{bullet_list}")
        if verbose:
            print(f"✅ Validated {len(programs)} program(s); no database writes performed (dry-run).")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Load scope definitions into Postgres.")
    parser.add_argument("--dsn", default=os.getenv("DSN"), help="Postgres DSN or DSN env var DSN")
    parser.add_argument("--file", default="config/scopes.example.yaml", help="YAML file with program definitions")
    parser.add_argument("--dry-run", action="store_true", help="Validate YAML only; do not write to the database")
    parser.add_argument(
        "--deactivate-missing",
        action="store_true",
        help="Mark targets absent from the YAML as inactive (requires DB write)",
    )
    parser.add_argument(
        "--prune-disabled-jobs",
        action="store_true",
        help="Remove disabled job rows that are no longer present in the YAML",
    )
    parser.add_argument(
        "--skip-if-unchanged",
        action="store_true",
        help="Skip applying the YAML if its SHA256 hash already exists in scope_loader_runs",
    )
    parser.add_argument(
        "--skip-schema-check",
        action="store_true",
        help="Skip the preflight schema check (not recommended unless you know the DB is ready)",
    )
    return parser.parse_args()


def _friendly_hint(error: Exception) -> str:
    message = str(error)
    if "Schema check failed" in message:
        return "Run psql -f config/schema.sql (or the equivalent) before re-running the loader."
    if "scope_type" in message:
        return "Valid scope_type values: limited, wide, open."
    if "min_payable_severity" in message:
        return "Use P1-P5 (e.g., Okta/Auth0 pay P4+)."
    if "target_type" in message:
        return "Try one of: domain, wildcard, api, mobile_app, desktop_app, other."
    if "disabled job" in message or "disabled job" in message.lower():
        return "Allowed job types: subenum, alive_scan, port_scan, vuln_scan, metadata, lead_scoring."
    if "Program URL" in message:
        return "Include https:// or http:// in the program_url field."
    if "DSN must be provided" in message:
        return "Pass --dsn or set DSN env var (e.g., DSN=postgresql://user:pass@localhost/db)."
    lowered = message.lower()
    if "could not connect" in lowered or "connection refused" in lowered:
        return "Verify the DSN host/port are reachable and the database is running."
    if "Scope file not found" in message:
        return "Double-check the --file path; try config/scopes.example.yaml."
    return "See README for examples and the YAML template."  # fallback


def _mask_dsn(dsn: str | None) -> str:
    if not dsn:
        return "<env:DSN>"
    if "@" in dsn and "://" in dsn:
        prefix, rest = dsn.split("://", 1)
        if "@" in rest:
            before_at, after_at = rest.rsplit("@", 1)
            if ":" in before_at:
                user, _ = before_at.split(":", 1)
                return f"{prefix}://{user}:***@{after_at}"
    return dsn


def _print_plan(scope_path: Path, program_count: int, args: argparse.Namespace) -> None:
    flags = []
    if args.dry_run:
        flags.append("dry-run ✅ (no database writes)")
    if args.deactivate_missing:
        flags.append("deactivate_missing: mark absent targets inactive")
    if args.prune_disabled_jobs:
        flags.append("prune_disabled_jobs: delete removed disabled jobs")
    if args.skip_if_unchanged:
        flags.append("skip_if_unchanged: compare YAML hash before writing")
    if not flags:
        flags.append("defaults only: safe upserts, no deletes")

    print("\n📋 Scope loader plan")
    print(f"  file: {scope_path} ({program_count} program(s) detected)")
    print(f"  dsn:  {_mask_dsn(args.dsn)}")
    print("  mode: " + "; ".join(flags))
    if args.deactivate_missing or args.prune_disabled_jobs:
        print("  safety: destructive toggles enabled → review the plan above before proceeding.")
    print("  tip:  add --dry-run first if you are unsure.\n")


def _print_preflight(scope_path: Path, programs: Sequence[Mapping[str, object]], args: argparse.Namespace) -> None:
    print("🧭 Zero-guess quickstart")
    print("  1) Validate only: python scripts/load_scope.py --file" f" {scope_path} --dry-run")
    print(
        "  2) Apply safely:  python scripts/load_scope.py --file"
        f" {scope_path} --dsn $DSN"
        + (" --skip-if-unchanged" if not args.dry_run else "")
    )
    print("  3) Need deletes?: add --deactivate-missing and/or --prune-disabled-jobs once happy\n")

    print("🧪 Preflight checklist")
    dsn_status = "✅" if args.dsn else "⚠️"
    dry_run_status = "✅" if args.dry_run else "ℹ️"
    schema_status = "✅" if not args.skip_schema_check else "⚠️"
    print(f"  {dsn_status} DSN provided or set via DSN env (current: {_mask_dsn(args.dsn)})")
    print(f"  {dry_run_status} Dry-run set? {'yes' if args.dry_run else 'no; first run will write' if args.dsn else 'auto-enabled'}")
    print(
        "  "
        f"{schema_status} Schema guard: {'enabled → warns on missing tables' if not args.skip_schema_check else 'skipped (only skip if you know the DB matches config/schema.sql)'}"
    )
    print(f"  ✅ Scope file reachable: {scope_path}")
    print(f"  ✅ Programs detected: {len(programs)}\n")


def _print_program_overview(programs: Sequence[Mapping[str, object]]) -> None:
    if not programs:
        return
    print("Programs detected:")
    for program in programs:
        disabled = program.get("disabled_jobs", [])
        targets = program.get("targets", [])
        rate_limits = program.get("rate_limits", {})
        disabled_summary = f"disabled_jobs={len(disabled)}" if disabled else "disabled_jobs=0"
        target_summary = f"targets={len(targets)}" if targets else "targets=0"
        rate_limit_summary = ", ".join(
            f"{k}={rate_limits[k]}" for k in PROGRAM_RATE_LIMIT_FIELDS if k in rate_limits
        ) or "default rate limits"
        print(
            "  - "
            f"{program.get('name', '<unnamed>')} "
            f"({program.get('scope_type', 'limited')}, {program.get('min_payable_severity', 'P4')}) → "
            f"{target_summary}; {disabled_summary}; {rate_limit_summary}"
        )
    print()


def _print_next_steps(loader: ScopeLoader, args: argparse.Namespace, scope_path: Path) -> None:
    print("🚀 Next steps")
    if loader.dry_run:
        print("  - Looks good! Re-run with --dsn to apply changes when you're ready.")
    elif loader.skipped_due_to_hash:
        print("  - Nothing changed: update the YAML or drop --skip-if-unchanged to force a write.")
    else:
        print("  - Done! Keep the YAML as your source of truth and re-run after edits.")
    print(
        "  - Safety tip: commit config/scopes.example.yaml (or your scope file) so teammates reuse the same truth set."
    )
    print(f"  - Ran against: {scope_path}\n")


def main():
    args = parse_args()
    if not args.dsn and not args.dry_run:
        print(
            "ℹ️  No DSN provided; running in dry-run mode so you can validate the file without writes.\n"
            "    Add --dsn or DSN env var to apply changes."
        )
        args.dry_run = True

    scope_path = Path(args.file)
    if not scope_path.exists():
        raise SystemExit(f"Scope file not found: {scope_path}")

    with scope_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    program_count = len(data.get("programs", []) or [])
    _print_plan(scope_path, program_count, args)
    _print_preflight(scope_path, data.get("programs", []) or [], args)
    _print_program_overview(data.get("programs", []) or [])

    try:
        with ScopeLoader(
            args.dsn,
            dry_run=args.dry_run,
            deactivate_missing=args.deactivate_missing,
            prune_disabled_jobs=args.prune_disabled_jobs,
            skip_if_unchanged=args.skip_if_unchanged,
            schema_check=not args.skip_schema_check,
        ) as loader:
            loader.load(scope_path, data=data)
    except (ValueError, psycopg2.OperationalError) as exc:
        hint = _friendly_hint(exc)
        raise SystemExit(f"❌ {exc}\n   Hint: {hint}") from exc

    if loader.skipped_due_to_hash:
        action = "Skipped (unchanged hash)"
    else:
        action = "Validated" if args.dry_run else "Loaded"
    print(
        f"{action} scope from {scope_path} "
        f"(programs={loader.summary.programs}, targets={loader.summary.targets}, "
        f"disabled_jobs={loader.summary.disabled_jobs}, deactivated={loader.summary.deactivated_targets}, "
        f"pruned_disabled_jobs={loader.summary.pruned_disabled_jobs})"
    )
    _print_next_steps(loader, args, scope_path)


if __name__ == "__main__":
    main()
