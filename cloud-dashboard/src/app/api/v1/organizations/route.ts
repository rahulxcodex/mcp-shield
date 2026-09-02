import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export async function GET() {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();

  if (authError || !user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Get organizations the user is a member of
  const { data: members, error: membersError } = await supabase
    .from('organization_members')
    .select('organization_id, role, organizations(*)')
    .eq('user_id', user.id);

  if (membersError) {
    return NextResponse.json({ error: membersError.message }, { status: 500 });
  }

  const organizations = members.map(m => ({
    ...m.organizations,
    role: m.role
  }));

  return NextResponse.json(organizations);
}

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();

  if (authError || !user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { name, slug } = body;

    if (!name || !slug) {
      return NextResponse.json({ error: 'Name and slug are required' }, { status: 400 });
    }

    // Start a transaction-like sequence (insert org, then insert member)
    const { data: org, error: orgError } = await supabase
      .from('organizations')
      .insert([{ name, slug, plan: 'free' }])
      .select()
      .single();

    if (orgError) {
      return NextResponse.json({ error: orgError.message }, { status: 500 });
    }

    const { error: memberError } = await supabase
      .from('organization_members')
      .insert([{ organization_id: org.id, user_id: user.id, role: 'owner' }]);

    if (memberError) {
      // In a real scenario, consider rolling back the organization creation or using an RPC call
      console.error('Error adding owner to organization:', memberError);
      return NextResponse.json({ error: memberError.message }, { status: 500 });
    }

    return NextResponse.json(org, { status: 201 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 });
  }
}
