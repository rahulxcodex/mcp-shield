import { NextResponse } from 'next/server';
import { createClient } from '@/utils/supabase/server';

export async function GET(
  req: Request,
  context: { params: Promise<{ id: string }> }
) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();

  if (authError || !user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const organizationId = (await context.params).id;

  // Check if current user is part of the organization
  const { data: userMembership, error: membershipError } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', user.id)
    .single();

  if (membershipError || !userMembership) {
    return NextResponse.json({ error: 'Not authorized for this organization' }, { status: 403 });
  }

  // Fetch all members
  const { data: members, error: membersError } = await supabase
    .from('organization_members')
    .select(`
      id,
      role,
      created_at,
      user_id
    `) // Ideally you'd join with profiles or users table to get email/name
    .eq('organization_id', organizationId);

  if (membersError) {
    return NextResponse.json({ error: membersError.message }, { status: 500 });
  }

  return NextResponse.json(members);
}

export async function POST(
  req: Request,
  context: { params: Promise<{ id: string }> }
) {
  const supabase = await createClient();
  const { data: { user }, error: authError } = await supabase.auth.getUser();

  if (authError || !user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const organizationId = (await context.params).id;

  // Check if current user has permission to invite (owner or admin)
  const { data: userMembership, error: membershipError } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', user.id)
    .single();

  if (membershipError || !userMembership) {
    return NextResponse.json({ error: 'Not authorized for this organization' }, { status: 403 });
  }

  if (userMembership.role !== 'owner' && userMembership.role !== 'admin') {
    return NextResponse.json({ error: 'Must be an owner or admin to invite members' }, { status: 403 });
  }

  try {
    const body = await req.json();
    let { email, role = 'member' } = body;

    const allowedRoles = ['owner', 'admin', 'member', 'viewer'];
    if (!allowedRoles.includes(role)) {
      return NextResponse.json({ error: `Invalid role. Allowed roles: ${allowedRoles.join(', ')}` }, { status: 400 });
    }

    // Admins cannot assign owner or admin roles — only owners can appoint admins or owners
    if (userMembership.role !== 'owner' && (role === 'owner' || role === 'admin')) {
      return NextResponse.json({
        error: 'Forbidden: Only organization owners can assign admin or owner privileges.'
      }, { status: 403 });
    }

    if (!email) {
      return NextResponse.json({ error: 'Email is required' }, { status: 400 });
    }

    // In a real application, you would invite the user via Supabase Auth admin API 
    // or send an invite email. For this stub, we might just look up the user by email
    // Or insert directly if we have a way to match emails.
    // 
    // Since we don't have access to auth.users without admin role, 
    // we would typically use an edge function with a service_role key to lookup or invite,
    // or insert into a pending_invites table.
    //
    // For this implementation, we will assume we can look up the user (e.g. from a public profiles table)
    // or we will insert a mock record into pending_invites.
    
    // As requested: "inserting into organization_members with role".
    // Note: We need a user_id to insert into organization_members. 
    // Let's assume we have an RPC or another table `profiles` to find the user id.
    const { createClient: createAdminClient } = await import('@supabase/supabase-js');
    const supabaseAdmin = createAdminClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!
    );
    
    // Controlled indexed lookup of target user (SEC-FINDING-009)
    const normalizedEmail = email.trim().toLowerCase();
    const { data: profileUser } = await supabaseAdmin
      .from('profiles')
      .select('id, email')
      .ilike('email', normalizedEmail)
      .maybeSingle();

    let targetUserId = profileUser?.id;

    if (!targetUserId) {
      try {
        const { data: authUser } = await (supabaseAdmin as any)
          .schema('auth')
          .from('users')
          .select('id, email')
          .eq('email', normalizedEmail)
          .maybeSingle();

        if (authUser?.id) {
          targetUserId = authUser.id;
          try {
            await supabaseAdmin.from('profiles').upsert([{ id: authUser.id, email: authUser.email }]);
          } catch {}
        }
      } catch {
        // Fallback for environments where auth schema query is unavailable
        const { data: userData } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 50 });
        const match = userData?.users?.find(u => u.email?.toLowerCase() === normalizedEmail);
        if (match) {
          targetUserId = match.id;
          try {
            await supabaseAdmin.from('profiles').upsert([{ id: match.id, email: match.email }]);
          } catch {}
        }
      }
    }
      
    if (!targetUserId) {
      return NextResponse.json({ error: 'User not found. They must sign up first.' }, { status: 404 });
    }
    
    const { data: newMember, error: insertError } = await supabase
      .from('organization_members')
      .insert([
        {
          organization_id: organizationId,
          user_id: targetUserId,
          role
        }
      ])
      .select()
      .single();

    if (insertError) {
      return NextResponse.json({ error: insertError.message }, { status: 500 });
    }

    return NextResponse.json(newMember, { status: 201 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Internal server error' }, { status: 500 });
  }
}
