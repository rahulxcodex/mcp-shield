import { createClient } from '@supabase/supabase-js';
import { appConfig } from './config';

export const supabase = createClient(appConfig.supabaseUrl, appConfig.supabaseAnonKey || appConfig.supabaseServiceKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
});

export const createSessionClient = (jwt: string) => {
  return createClient(appConfig.supabaseUrl, appConfig.supabaseAnonKey || appConfig.supabaseServiceKey, {
    global: {
      headers: {
        Authorization: `Bearer ${jwt}`,
      },
    },
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
};

export const createAdminSupabaseClient = () => {
  return createClient(appConfig.supabaseUrl, appConfig.supabaseServiceKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
};
