import { defineConfig } from "drizzle-kit";

// For Supabase: prefer DIRECT_URL for migrations (port 5432, no pgbouncer),
// then fall back to DATABASE_URL (can be pooled for runtime).
const databaseUrl = process.env.DIRECT_URL || process.env.DATABASE_URL || "file:./app.db";

// Determine dialect based on DATABASE_URL
const isPostgres = databaseUrl.startsWith("postgresql://");
const dialect = isPostgres ? "postgresql" : "sqlite";

export default defineConfig({
  out: "./migrations",
  schema: "./server/unified-schema.ts",
  dialect: dialect,
  dbCredentials: isPostgres
    ? { url: databaseUrl }
    : { url: databaseUrl },
});
