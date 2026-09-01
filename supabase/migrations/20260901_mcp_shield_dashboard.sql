-- ============================================================================
-- 🛡️ MCP-SHIELD DATABASE SCHEMA & MULTI-TENANCY RLS POLICIES
-- Target: PostgreSQL 15+ / Supabase Free Tier (Zero-Credit-Card Required)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'free' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    user_id UUID NOT NULL,
    role TEXT CHECK (role IN ('owner', 'admin', 'viewer')) DEFAULT 'viewer' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    UNIQUE(organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    security_score INT DEFAULT 100 CHECK (security_score BETWEEN 0 AND 100),
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    UNIQUE(organization_id, slug)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    instance_name TEXT NOT NULL,
    hostname TEXT,
    os TEXT,
    client_name TEXT,
    shield_version TEXT NOT NULL,
    status TEXT CHECK (status IN ('ONLINE', 'OFFLINE', 'QUARANTINED')) DEFAULT 'ONLINE' NOT NULL,
    last_heartbeat_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_instance_id UUID REFERENCES agent_instances(id) ON DELETE CASCADE NOT NULL,
    server_name TEXT NOT NULL,
    server_hash TEXT NOT NULL,
    tool_count INT DEFAULT 0,
    trust_score INT DEFAULT 100 CHECK (trust_score BETWEEN 0 AND 100),
    discovered_tools JSONB DEFAULT '[]'::jsonb,
    last_scanned_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    agent_instance_id UUID REFERENCES agent_instances(id) ON DELETE SET NULL,
    session_id TEXT NOT NULL,
    event_type TEXT CHECK (event_type IN ('BLOCK', 'SANITIZE', 'QUARANTINE', 'RATE_LIMIT', 'PROMPT', 'PASSTHROUGH')) NOT NULL,
    detector TEXT NOT NULL,
    risk_level TEXT CHECK (risk_level IN ('BENIGN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    tool_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    sanitized_preview JSONB,
    client_timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_events_project_time ON security_events(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_risk ON security_events(project_id, risk_level);

CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    is_enabled BOOLEAN DEFAULT true NOT NULL,
    parameters JSONB NOT NULL,
    version INT DEFAULT 1 NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS honey_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    token_identifier TEXT NOT NULL,
    label TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    trigger_count INT DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    batch_index INT NOT NULL,
    batch_hash TEXT NOT NULL,
    prev_batch_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    event_count INT NOT NULL,
    verified BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
