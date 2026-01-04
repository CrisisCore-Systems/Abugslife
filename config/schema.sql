-- Minimal schema for Bugcrowd/Okta-aware recon automation
-- Postgres dialect

CREATE TABLE IF NOT EXISTS programs (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL DEFAULT 'bugcrowd',
    program_url TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('limited', 'wide', 'open')),
    min_payable_severity TEXT NOT NULL CHECK (min_payable_severity IN ('P1','P2','P3','P4','P5')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Track loader executions for change detection and auditing.
CREATE TABLE IF NOT EXISTS scope_loader_runs (
    id BIGSERIAL PRIMARY KEY,
    source_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    dry_run BOOLEAN NOT NULL,
    deactivate_missing BOOLEAN NOT NULL,
    prune_disabled_jobs BOOLEAN NOT NULL,
    skip_if_unchanged BOOLEAN NOT NULL,
    programs_processed INTEGER NOT NULL,
    targets_processed INTEGER NOT NULL,
    disabled_jobs_processed INTEGER NOT NULL,
    deactivated_targets INTEGER NOT NULL,
    pruned_disabled_jobs INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (file_hash, dry_run, deactivate_missing, prune_disabled_jobs, skip_if_unchanged)
);

CREATE TABLE IF NOT EXISTS program_policy_flags (
    id SERIAL PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    flag TEXT NOT NULL,
    value BOOLEAN NOT NULL DEFAULT TRUE,
    note TEXT,
    UNIQUE (program_id, flag)
);

CREATE TABLE IF NOT EXISTS program_rate_limits (
    program_id INTEGER PRIMARY KEY REFERENCES programs(id) ON DELETE CASCADE,
    max_concurrent_jobs INTEGER NOT NULL DEFAULT 5,
    max_requests_per_minute INTEGER NOT NULL DEFAULT 300,
    max_http_qps NUMERIC(10,2) NOT NULL DEFAULT 1.00,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS program_disabled_jobs (
    id SERIAL PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL CHECK (job_type IN ('subenum','alive_scan','port_scan','vuln_scan','metadata','lead_scoring')),
    note TEXT,
    UNIQUE (program_id, job_type)
);

CREATE TABLE IF NOT EXISTS targets (
    id SERIAL PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('domain', 'wildcard', 'api', 'mobile_app', 'desktop_app', 'other')),
    source TEXT NOT NULL CHECK (source IN ('manual', 'bugcrowd', 'vdppdf', 'automation')),
    wildcard BOOLEAN NOT NULL DEFAULT FALSE,
    policy_flags TEXT[] NOT NULL DEFAULT '{}',
    note TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (program_id, target, target_type)
);

CREATE TABLE IF NOT EXISTS job_runs (
    id BIGSERIAL PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    job_type TEXT NOT NULL CHECK (job_type IN ('subenum','alive_scan','port_scan','vuln_scan','metadata','lead_scoring')),
    queue_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued','running','done','failed','dead_letter')),
    payload JSONB NOT NULL DEFAULT '{}',
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_programs_updated
BEFORE UPDATE ON programs
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

CREATE TRIGGER trg_program_rate_limits_updated
BEFORE UPDATE ON program_rate_limits
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

CREATE INDEX IF NOT EXISTS idx_program_policy_flags_program_id ON program_policy_flags(program_id);
CREATE INDEX IF NOT EXISTS idx_program_policy_flags_flag ON program_policy_flags(flag);
CREATE INDEX IF NOT EXISTS idx_program_disabled_jobs_program_id ON program_disabled_jobs(program_id);
CREATE INDEX IF NOT EXISTS idx_targets_program_id ON targets(program_id);
CREATE INDEX IF NOT EXISTS idx_targets_active ON targets(active);
CREATE INDEX IF NOT EXISTS idx_targets_policy_flags_gin ON targets USING GIN(policy_flags);
CREATE INDEX IF NOT EXISTS idx_job_runs_program_id_status ON job_runs(program_id, status);
