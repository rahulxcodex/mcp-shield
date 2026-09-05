import { createClient } from '@supabase/supabase-js';
import { appConfig } from './config';

export const supabase = createClient(appConfig.supabaseUrl, appConfig.supabaseServiceKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
});

export const createAdminSupabaseClient = () => {
  return createClient(appConfig.supabaseUrl, appConfig.supabaseServiceKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
};
