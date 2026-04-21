import { createClient, type SupabaseClient } from "@supabase/supabase-js";

function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

export function isSupabaseConfigured(): boolean {
  return Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY);
}

export function getSupabaseUrl(): string {
  return getRequiredEnv("SUPABASE_URL");
}

export function createSupabaseAnonClient(): SupabaseClient {
  const url = getSupabaseUrl();
  const anonKey = getRequiredEnv("SUPABASE_ANON_KEY");

  return createClient(url, anonKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
}

export function createSupabaseServiceClient(): SupabaseClient {
  const url = getSupabaseUrl();
  const serviceKey = getRequiredEnv("SUPABASE_SERVICE_ROLE_KEY");

  return createClient(url, serviceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
}

export type SupabaseJwtPayload = {
  sub: string;
  email?: string;
  role?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  aud?: string | string[];
  app_metadata?: unknown;
  user_metadata?: unknown;
};

/**
 * Verifies a Supabase access token by asking Supabase Auth.
 * This avoids relying on local JWT verification details (HS256 vs JWKS).
 */
export async function verifySupabaseAccessToken(token: string): Promise<SupabaseJwtPayload> {
  const supabase = createSupabaseAnonClient();
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) {
    throw new Error(error?.message || "Invalid Supabase token");
  }

  return {
    sub: data.user.id,
    email: data.user.email ?? undefined,
    role: (data.user.user_metadata as any)?.role ?? undefined,
    app_metadata: data.user.app_metadata,
    user_metadata: data.user.user_metadata,
  };
}
