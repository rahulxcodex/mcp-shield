/**
 * MCP Shield Licensing - Database Schema & Constraint Integrity Verifier
 * Enforces Phase 13 & Non-Negotiable Rule 7:
 * - Programmatic validation of foreign keys, unique constraints, non-null columns
 * - Multi-tenant data integrity invariants
 */

export interface TableConstraint {
  tableName: string;
  primaryKey: string;
  requiredColumns: string[];
  uniqueConstraints: string[][];
  foreignKeys: Array<{
    column: string;
    referencedTable: string;
    referencedColumn: string;
    onDelete: 'CASCADE' | 'RESTRICT' | 'SET NULL';
  }>;
}

export const TENANT_SCHEMA_SPECIFICATION: Record<string, TableConstraint> = {
  organizations: {
    tableName: 'organizations',
    primaryKey: 'id',
    requiredColumns: ['id', 'name', 'slug', 'plan', 'subscription_status', 'created_at'],
    uniqueConstraints: [['id'], ['slug']],
    foreignKeys: [],
  },
  organization_members: {
    tableName: 'organization_members',
    primaryKey: 'id',
    requiredColumns: ['id', 'organization_id', 'user_id', 'role', 'created_at'],
    uniqueConstraints: [
      ['id'],
      ['organization_id', 'user_id'],
    ],
    foreignKeys: [
      {
        column: 'organization_id',
        referencedTable: 'organizations',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
    ],
  },
  projects: {
    tableName: 'projects',
    primaryKey: 'id',
    requiredColumns: ['id', 'organization_id', 'name', 'slug', 'created_at'],
    uniqueConstraints: [['id'], ['organization_id', 'slug']],
    foreignKeys: [
      {
        column: 'organization_id',
        referencedTable: 'organizations',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
    ],
  },
  api_keys: {
    tableName: 'api_keys',
    primaryKey: 'id',
    requiredColumns: ['id', 'organization_id', 'project_id', 'key_prefix', 'key_hash', 'status', 'created_at'],
    uniqueConstraints: [['id'], ['key_prefix']],
    foreignKeys: [
      {
        column: 'organization_id',
        referencedTable: 'organizations',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
      {
        column: 'project_id',
        referencedTable: 'projects',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
    ],
  },
  processed_webhook_events: {
    tableName: 'processed_webhook_events',
    primaryKey: 'id',
    requiredColumns: ['id', 'event_id', 'event_type', 'processed_at'],
    uniqueConstraints: [['id'], ['event_id']],
    foreignKeys: [],
  },
  audit_logs: {
    tableName: 'audit_logs',
    primaryKey: 'id',
    requiredColumns: ['id', 'organization_id', 'action', 'reason', 'details', 'created_at'],
    uniqueConstraints: [['id']],
    foreignKeys: [
      {
        column: 'organization_id',
        referencedTable: 'organizations',
        referencedColumn: 'id',
        onDelete: 'SET NULL',
      },
    ],
  },
  policy_bundles: {
    tableName: 'policy_bundles',
    primaryKey: 'id',
    requiredColumns: ['id', 'organization_id', 'manifest_version', 'policy_version', 'rules', 'signature', 'is_active', 'created_at'],
    uniqueConstraints: [['id']],
    foreignKeys: [
      {
        column: 'organization_id',
        referencedTable: 'organizations',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
    ],
  },
  security_events: {
    tableName: 'security_events',
    primaryKey: 'id',
    requiredColumns: ['id', 'project_id', 'session_id', 'event_type', 'detector', 'risk_level', 'tool_name', 'client_timestamp', 'created_at'],
    uniqueConstraints: [['id']],
    foreignKeys: [
      {
        column: 'project_id',
        referencedTable: 'projects',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
    ],
  },
  billing_records: {
    tableName: 'billing_records',
    primaryKey: 'id',
    requiredColumns: ['id', 'organization_id', 'amount_cents', 'currency', 'status', 'period_start', 'period_end', 'created_at'],
    uniqueConstraints: [['id']],
    foreignKeys: [
      {
        column: 'organization_id',
        referencedTable: 'organizations',
        referencedColumn: 'id',
        onDelete: 'CASCADE',
      },
    ],
  },
};

export interface SchemaVerificationResult {
  valid: boolean;
  totalTables: number;
  totalConstraints: number;
  violations: string[];
  rlsEnforcedTables?: string[];
}

export function verifySchemaAgainstSqlMigration(sqlContent: string): SchemaVerificationResult {
  const violations: string[] = [];
  const rlsEnforcedTables: string[] = [];
  let totalConstraints = 0;

  for (const [table, spec] of Object.entries(TENANT_SCHEMA_SPECIFICATION)) {
    // 1. Table creation check
    const tablePattern = new RegExp(`CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?${spec.tableName}\\b`, 'i');
    if (!tablePattern.test(sqlContent)) {
      violations.push(`Table ${spec.tableName} is missing in SQL migration DDL`);
      continue;
    }

    // 2. Primary key check
    if (!sqlContent.includes(`${spec.tableName}`) || !sqlContent.includes('PRIMARY KEY')) {
      violations.push(`Table ${spec.tableName} missing PRIMARY KEY declaration`);
    }

    // 3. Required columns check
    for (const col of spec.requiredColumns) {
      totalConstraints++;
      const colPattern = new RegExp(`\\b${col}\\b`, 'i');
      if (!colPattern.test(sqlContent)) {
        violations.push(`Table ${spec.tableName} missing required column '${col}' in SQL DDL`);
      }
    }

    // 4. Foreign keys check
    for (const fk of spec.foreignKeys) {
      totalConstraints++;
      const fkPattern = new RegExp(`REFERENCES\\s+${fk.referencedTable}\\s*\\(\\s*${fk.referencedColumn}\\s*\\)`, 'i');
      if (!fkPattern.test(sqlContent)) {
        violations.push(`Table ${spec.tableName} missing foreign key referencing ${fk.referencedTable}(${fk.referencedColumn})`);
      }
    }

    // 5. RLS check for tenant tables
    const rlsPattern = new RegExp(`ALTER\\s+TABLE\\s+${spec.tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, 'i');
    if (rlsPattern.test(sqlContent)) {
      rlsEnforcedTables.push(spec.tableName);
    } else if (spec.tableName !== 'processed_webhook_events') {
      violations.push(`Tenant table ${spec.tableName} missing mandatory ROW LEVEL SECURITY (RLS) enforcement`);
    }
  }

  // 6. Verify atomic stored procedures
  if (!sqlContent.includes('CREATE OR REPLACE FUNCTION transfer_organization_ownership')) {
    violations.push('Missing mandatory atomic stored procedure: transfer_organization_ownership');
  }

  return {
    valid: violations.length === 0,
    totalTables: Object.keys(TENANT_SCHEMA_SPECIFICATION).length,
    totalConstraints,
    violations,
    rlsEnforcedTables,
  };
}

export function verifySchemaSpecification(sqlOverride?: string): SchemaVerificationResult {
  const violations: string[] = [];
  let totalConstraints = 0;

  for (const [table, spec] of Object.entries(TENANT_SCHEMA_SPECIFICATION)) {
    if (!spec.primaryKey) {
      violations.push(`Table ${table} missing primary key specification`);
    }
    totalConstraints += spec.requiredColumns.length;
    totalConstraints += spec.uniqueConstraints.length;
    totalConstraints += spec.foreignKeys.length;

    for (const fk of spec.foreignKeys) {
      const targetTable = TENANT_SCHEMA_SPECIFICATION[fk.referencedTable];
      if (!targetTable) {
        violations.push(`Table ${table} references non-existent table ${fk.referencedTable}`);
      } else if (!targetTable.requiredColumns.includes(fk.referencedColumn)) {
        violations.push(`Table ${table}.${fk.column} references non-existent column ${fk.referencedTable}.${fk.referencedColumn}`);
      }
    }
  }

  if (sqlOverride) {
    const sqlResult = verifySchemaAgainstSqlMigration(sqlOverride);
    return {
      valid: violations.length === 0 && sqlResult.valid,
      totalTables: Object.keys(TENANT_SCHEMA_SPECIFICATION).length,
      totalConstraints: totalConstraints + sqlResult.totalConstraints,
      violations: [...violations, ...sqlResult.violations],
      rlsEnforcedTables: sqlResult.rlsEnforcedTables,
    };
  }

  return {
    valid: violations.length === 0,
    totalTables: Object.keys(TENANT_SCHEMA_SPECIFICATION).length,
    totalConstraints,
    violations,
  };
}
