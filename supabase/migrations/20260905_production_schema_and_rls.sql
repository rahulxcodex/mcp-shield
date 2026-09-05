-- ============================================================================
-- 🛡️ MCP-SHIELD PRODUCTION DATABASE SCHEMA & MULTI-TENANT RLS POLICIES
-- Target: PostgreSQL 15+ / Supabase Production Tier
-- Verification: Automated Schema Diff & RLS Policy Conformance Gates
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS uuid-ossp;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')) DEFAULT 'free' NOT NULL,
    subscription_status TEXT CHECK (subscription_status IN ('active', 'past_due', 'suspended', 'canceled')) DEFAULT 'active' NOT NULL,
    stripe_customer_id TEXT UNIQUE,
    stripe_subscription_id TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- 2. Organization Members
CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    user_id UUID NOT NULL,
    role TEXT CHECK (role IN ('owner', 'admin', 'member', 'viewer')) DEFAULT 'viewer' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    UNIQUE(organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org_role ON organization_members(organization_id, role);

-- 3. Projects
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    security_score INT DEFAULT 100 CHECK (security_score BETWEEN 0 AND 100) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    UNIQUE(organization_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(organization_id);

-- 4. API Keys
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT UNIQUE NOT NULL,
    key_hash TEXT NOT NULL,
    status TEXT CHECK (status IN ('active', 'revoked', 'expired')) DEFAULT 'active' NOT NULL,
    revoked BOOLEAN DEFAULT false NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_lookup ON api_keys(key_prefix, status);
CREATE INDEX IF NOT EXISTS idx_api_keys_proj ON api_keys(project_id);

-- 5. Processed Webhook Events (Durable Idempotency)
CREATE TABLE IF NOT EXISTS processed_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    processed_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhook_events_id ON processed_webhook_events(event_id);

-- 6. Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    actor_id UUID,
    target_id TEXT,
    reason TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(organization_id, created_at DESC);

-- 7. Policy Bundles
CREATE TABLE IF NOT EXISTS policy_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    manifest_version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    rules JSONB NOT NULL,
    algorithm TEXT DEFAULT 'Ed25519' NOT NULL,
    signature TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    revoked_at TIMESTAMPTZ,
    issued_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_bundles_active ON policy_bundles(organization_id, is_active, policy_version DESC);

-- 8. Security Events
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id TEXT UNIQUE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    installation_id TEXT,
    session_id TEXT NOT NULL,
    sequence_number BIGINT DEFAULT 0,
    event_type TEXT CHECK (event_type IN ('BLOCK', 'SANITIZE', 'QUARANTINE', 'RATE_LIMIT', 'PROMPT', 'PASSTHROUGH', 'ERROR')) NOT NULL,
    detector TEXT NOT NULL,
    risk_level TEXT CHECK (risk_level IN ('BENIGN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    tool_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    sanitized_preview JSONB,
    client_timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_events_proj_time ON security_events(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_type_risk ON security_events(project_id, event_type, risk_level);

-- 9. Billing Records
CREATE TABLE IF NOT EXISTS billing_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    stripe_invoice_id TEXT UNIQUE,
    amount_cents BIGINT NOT NULL,
    currency TEXT DEFAULT 'usd' NOT NULL,
    status TEXT CHECK (status IN ('draft', 'open', 'paid', 'uncollectible', 'void')) DEFAULT 'open' NOT NULL,
    invoice_pdf_url TEXT,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_billing_records_org ON billing_records(organization_id, created_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_records ENABLE ROW LEVEL SECURITY;

-- Helper function to check if current authenticated user belongs to the org
CREATE OR REPLACE FUNCTION is_org_member(p_org_id UUID) RETURNS BOOLEAN AS 
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM organization_members
        WHERE organization_id = p_org_id
        AND user_id = auth.uid()
    );
END;
 LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- RLS: Organizations
CREATE POLICY org_select_policy ON organizations
    FOR SELECT USING (is_org_member(id));

CREATE POLICY org_insert_policy ON organizations
    FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY org_update_policy ON organizations
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = organizations.id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- RLS: Organization Members
CREATE POLICY org_members_select_policy ON organization_members
    FOR SELECT USING (is_org_member(organization_id));

CREATE POLICY org_members_insert_policy ON organization_members
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM organization_members AS m
            WHERE m.organization_id = organization_members.organization_id
            AND m.user_id = auth.uid()
            AND m.role IN ('owner', 'admin')
        )
        OR NOT EXISTS (
            SELECT 1 FROM organization_members AS m
            WHERE m.organization_id = organization_members.organization_id
        )
    );

CREATE POLICY org_members_update_policy ON organization_members
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM organization_members AS m
            WHERE m.organization_id = organization_members.organization_id
            AND m.user_id = auth.uid()
            AND m.role IN ('owner', 'admin')
        )
    );

CREATE POLICY org_members_delete_policy ON organization_members
    FOR DELETE USING (
        user_id = auth.uid()
        OR EXISTS (
            SELECT 1 FROM organization_members AS m
            WHERE m.organization_id = organization_members.organization_id
            AND m.user_id = auth.uid()
            AND m.role IN ('owner', 'admin')
        )
    );

-- RLS: Projects
CREATE POLICY proj_select_policy ON projects
    FOR SELECT USING (is_org_member(organization_id));

CREATE POLICY proj_insert_policy ON projects
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = projects.organization_id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin', 'member')
        )
    );

CREATE POLICY proj_update_policy ON projects
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = projects.organization_id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

CREATE POLICY proj_delete_policy ON projects
    FOR DELETE USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = projects.organization_id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- RLS: API Keys
CREATE POLICY api_keys_select_policy ON api_keys
    FOR SELECT USING (is_org_member(organization_id));

CREATE POLICY api_keys_modify_policy ON api_keys
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = api_keys.organization_id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- RLS: Audit Logs (Append-only immutable audit trail)
CREATE POLICY audit_logs_select_policy ON audit_logs
    FOR SELECT USING (is_org_member(organization_id));

CREATE POLICY audit_logs_insert_policy ON audit_logs
    FOR INSERT WITH CHECK (
        auth.role() = 'authenticated' AND is_org_member(organization_id)
    );

-- RLS: Policy Bundles
CREATE POLICY policy_bundles_select_policy ON policy_bundles
    FOR SELECT USING (is_org_member(organization_id));

CREATE POLICY policy_bundles_modify_policy ON policy_bundles
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = policy_bundles.organization_id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- RLS: Security Events
CREATE POLICY sec_events_select_policy ON security_events
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM projects p
            JOIN organization_members m ON m.organization_id = p.organization_id
            WHERE p.id = security_events.project_id
            AND m.user_id = auth.uid()
        )
    );

CREATE POLICY sec_events_insert_policy ON security_events
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM projects p
            JOIN organization_members m ON m.organization_id = p.organization_id
            WHERE p.id = security_events.project_id
            AND m.user_id = auth.uid()
        )
    );

-- RLS: Billing Records
CREATE POLICY billing_select_policy ON billing_records
    FOR SELECT USING (is_org_member(organization_id));

CREATE POLICY billing_modify_policy ON billing_records
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM organization_members
            WHERE organization_id = billing_records.organization_id
            AND user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- ============================================================================
-- ATOMIC STORED PROCEDURES
-- ============================================================================

CREATE OR REPLACE FUNCTION transfer_organization_ownership(
    p_org_id UUID,
    p_caller_id UUID,
    p_target_id UUID,
    p_reason TEXT
) RETURNS JSONB AS 
DECLARE
    v_caller_role TEXT;
    v_target_role TEXT;
    v_now TIMESTAMPTZ := now();
BEGIN
    -- 1. Pessimistic row locking on organization membership to eliminate TOCTOU races
    PERFORM 1 FROM organization_members 
    WHERE organization_id = p_org_id 
    FOR UPDATE;

    -- 2. Verify caller is authorized owner
    SELECT role INTO v_caller_role 
    FROM organization_members 
    WHERE organization_id = p_org_id AND user_id = p_caller_id;

    IF v_caller_role IS NULL OR v_caller_role <> 'owner' THEN
        RAISE EXCEPTION 'FORBIDDEN: Only the current owner may transfer ownership';
    END IF;

    -- 3. Verify target is active member of org
    SELECT role INTO v_target_role 
    FROM organization_members 
    WHERE organization_id = p_org_id AND user_id = p_target_id;

    IF v_target_role IS NULL THEN
        RAISE EXCEPTION 'TARGET_NOT_MEMBER: Target user is not an active member of this organization';
    END IF;

    IF p_caller_id = p_target_id THEN
        RAISE EXCEPTION 'INVALID_TARGET: Cannot transfer ownership to oneself';
    END IF;

    -- 4. Atomically swap roles: caller -> admin, target -> owner
    UPDATE organization_members 
    SET role = 'admin', updated_at = v_now 
    WHERE organization_id = p_org_id AND user_id = p_caller_id;

    UPDATE organization_members 
    SET role = 'owner', updated_at = v_now 
    WHERE organization_id = p_org_id AND user_id = p_target_id;

    -- 5. Mandatory atomic audit log creation in exact same transaction
    INSERT INTO audit_logs (organization_id, action, actor_id, target_id, reason, details, created_at)
    VALUES (
        p_org_id,
        'ORGANIZATION_OWNER_TRANSFERRED',
        p_caller_id,
        p_target_id::text,
        p_reason,
        jsonb_build_object('previous_owner', p_caller_id, 'new_owner', p_target_id),
        v_now
    );

    RETURN jsonb_build_object(
        'success', true,
        'organization_id', p_org_id,
        'previous_owner_id', p_caller_id,
        'new_owner_id', p_target_id,
        'timestamp', v_now
    );
END;
 LANGUAGE plpgsql SECURITY DEFINER;
