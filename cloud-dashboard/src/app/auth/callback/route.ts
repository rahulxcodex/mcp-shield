import { NextResponse } from 'next/server'
import { createClient } from '@/utils/supabase/server'

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
  const code = searchParams.get('code')
  const next = searchParams.get('next') || '/console'
  
  if (code) {
    const supabase = await createClient()
    const { error } = await supabase.auth.exchangeCodeForSession(code)
    if (!error) {
      const target = next.startsWith('/') ? next : '/console'
      return NextResponse.redirect(`${origin}${target}`)
    }
  }

  // return the user to an error page with instructions
  return NextResponse.redirect(`${origin}/login?error=auth_callback_failed`)
}
