import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';
import { supabase as adminSupabase } from '@/lib/supabase';
import { getAuthenticatedUserWithBearer } from '@/lib/authz';

export const runtime = 'nodejs';

// In-memory oversight registry for tenant sessions
interface OversightRecordDto {
  id: string;
  requestId: string;
  action: 'QUARANTINE' | 'BLOCK';
  riskScore: number;
  detectorIds: string[];
  reasons: string[];
  status: 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  createdAt: string;
  approvals: { reviewer: string; timestamp: string; comment?: string }[];
  requiredQuorum: number;
}

const oversightStore: Map<string, OversightRecordDto> = new Map();

export async function GET(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { user, error: authError } = await getAuthenticatedUserWithBearer(req, supabase, adminSupabase);

    if (!user || authError) {
      return NextResponse.json({ error: 'Unauthorized: Authentication required' }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const statusFilter = searchParams.get('status');

    const records = Array.from(oversightStore.values()).filter(
      (r) => !statusFilter || r.status === statusFilter
    );

    return NextResponse.json({
      success: true,
      records,
      totalCount: records.length,
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Internal server error' }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { user, error: authError } = await getAuthenticatedUserWithBearer(req, supabase, adminSupabase);

    if (!user || authError) {
      return NextResponse.json({ error: 'Unauthorized: Authentication required' }, { status: 401 });
    }

    const body = await req.json();
    const { recordId, decision, comment } = body;

    if (!recordId || !decision) {
      return NextResponse.json(
        { error: 'Bad Request: recordId and decision ("APPROVE" | "REJECT") are required' },
        { status: 400 }
      );
    }

    let record = oversightStore.get(recordId);
    if (!record) {
      // Create pending record if this is an initial submission from agent
      if (decision === 'SUBMIT') {
        record = {
          id: recordId,
          requestId: body.requestId || recordId,
          action: body.action || 'BLOCK',
          riskScore: body.riskScore || 0.85,
          detectorIds: body.detectorIds || ['ML_FUSION'],
          reasons: body.reasons || ['Automated risk threshold exceeded'],
          status: 'PENDING_REVIEW',
          createdAt: new Date().toISOString(),
          approvals: [],
          requiredQuorum: body.requiredQuorum || 1
        };
        oversightStore.set(recordId, record);
        return NextResponse.json({ success: true, record }, { status: 201 });
      }
      return NextResponse.json({ error: `Record '${recordId}' not found` }, { status: 404 });
    }

    if (decision === 'APPROVE') {
      const alreadyApproved = record.approvals.some((a) => a.reviewer === user.id);
      if (!alreadyApproved) {
        record.approvals.push({
          reviewer: user.email || user.id,
          timestamp: new Date().toISOString(),
          comment
        });
      }

      if (record.approvals.length >= record.requiredQuorum) {
        record.status = 'APPROVED';
      }

      return NextResponse.json({
        success: true,
        record,
        quorumSatisfied: record.status === 'APPROVED',
        message: `Approval recorded (${record.approvals.length}/${record.requiredQuorum})`
      });
    } else if (decision === 'REJECT') {
      record.status = 'REJECTED';
      return NextResponse.json({
        success: true,
        record,
        quorumSatisfied: false,
        message: 'Decision confirmed blocked by human reviewer'
      });
    }

    return NextResponse.json({ error: 'Invalid decision action' }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Internal server error' }, { status: 500 });
  }
}
