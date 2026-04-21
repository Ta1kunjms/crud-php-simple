import { Request, Response, NextFunction } from "express";
import { verifyToken, JWTPayload, createErrorResponse, ErrorCodes } from "./auth";
import { verifySupabaseAccessToken, isSupabaseConfigured } from "./supabase";
import { storage } from "./storage";
import { adminsTable, employersTable, usersTable } from "./unified-schema";
import { eq } from "drizzle-orm";

// ============ EXTEND EXPRESS REQUEST TYPE ============

import type { User } from "@shared/schema";
declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

// ============ AUTH MIDDLEWARE ============

export async function authMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json(
        createErrorResponse(
          ErrorCodes.UNAUTHORIZED,
          "Missing authentication token"
        )
      );
    }

    // 1) Legacy JWT (existing system)
    const legacyPayload = verifyToken(token);
    if (legacyPayload) {
      req.user = legacyPayload as unknown as User;
      return next();
    }

    // 2) Supabase access token (new system)
    if (!isSupabaseConfigured()) {
      return res.status(401).json(
        createErrorResponse(
          ErrorCodes.UNAUTHORIZED,
          "Invalid or expired authentication token"
        )
      );
    }

    const supabasePayload = await verifySupabaseAccessToken(token);
    const authUserId = supabasePayload.sub;
    if (!authUserId) {
      return res.status(401).json(
        createErrorResponse(
          ErrorCodes.UNAUTHORIZED,
          "Invalid authentication token"
        )
      );
    }

    const db = await storage.getDb();

    // Resolve role+profile from our application tables.
    const admin = await db
      .select({ id: adminsTable.id, email: adminsTable.email, name: adminsTable.name })
      .from(adminsTable)
      .where(eq(adminsTable.id, authUserId))
      .limit(1)
      .then((rows: any[]) => rows[0]);
    if (admin) {
      req.user = {
        id: admin.id,
        email: admin.email,
        name: admin.name,
        role: "admin",
      } as unknown as User;
      return next();
    }

    const employer = await db
      .select({
        id: employersTable.id,
        email: employersTable.email,
        name: employersTable.name,
        establishmentName: employersTable.establishmentName,
      })
      .from(employersTable)
      .where(eq(employersTable.id, authUserId))
      .limit(1)
      .then((rows: any[]) => rows[0]);
    if (employer) {
      req.user = {
        id: employer.id,
        email: employer.email,
        name: employer.name || employer.establishmentName || "Employer",
        role: "employer",
        company: employer.establishmentName || undefined,
      } as unknown as User;
      return next();
    }

    const user = await db
      .select({
        id: usersTable.id,
        email: usersTable.email,
        firstName: usersTable.firstName,
        surname: usersTable.surname,
        role: usersTable.role,
        profileImage: usersTable.profileImage,
      })
      .from(usersTable)
      .where(eq(usersTable.id, authUserId))
      .limit(1)
      .then((rows: any[]) => rows[0]);
    if (user) {
      const fullName = `${user.firstName || ""} ${user.surname || ""}`.trim() || user.email;
      req.user = {
        id: user.id,
        email: user.email,
        name: fullName,
        role: (user.role as any) || "jobseeker",
        profileImage: user.profileImage ?? null,
      } as unknown as User;
      return next();
    }

    return res.status(401).json(
      createErrorResponse(
        ErrorCodes.UNAUTHORIZED,
        "User profile not found for this token"
      )
    );
  } catch (error) {
    return res.status(500).json(
      createErrorResponse(
        ErrorCodes.INTERNAL_SERVER_ERROR,
        "Authentication verification failed"
      )
    );
  }
}

// ============ ROLE MIDDLEWARE ============

export function roleMiddleware(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as import("@shared/schema").User;
    if (!user) {
      return res.status(401).json(
        createErrorResponse(
          ErrorCodes.UNAUTHORIZED,
          "User not authenticated"
        )
      );
    }

    if (!user || !allowedRoles.includes(user.role)) {
      return res.status(403).json(
        createErrorResponse(
          ErrorCodes.FORBIDDEN,
          `This endpoint requires one of these roles: ${allowedRoles.join(", ")}`
        )
      );
    }

    next();
  };
}

// ============ ADMIN ONLY MIDDLEWARE ============

export function adminOnly(req: Request, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json(
      createErrorResponse(
        ErrorCodes.UNAUTHORIZED,
        "User not authenticated"
      )
    );
  }

  const user = req.user as import("@shared/schema").User;
  if (!user || user.role !== "admin") {
    return res.status(403).json(
      createErrorResponse(
        ErrorCodes.FORBIDDEN,
        "This endpoint is restricted to administrators only"
      )
    );
  }

  next();
}

// ============ ERROR HANDLER MIDDLEWARE ============

export interface CustomError extends Error {
  status?: number;
  code?: string;
  field?: string;
}

export function errorHandler(
  err: CustomError,
  req: Request,
  res: Response,
  next: NextFunction
) {
  const isDev = process.env.NODE_ENV === "development";
  const status = err.status || 500;
  const code = err.code || ErrorCodes.INTERNAL_SERVER_ERROR;
  const message = err.message || "An unexpected error occurred";

  console.error(`[${status}] ${code}:`, {
    message,
    stack: isDev ? err.stack : undefined,
    method: req.method,
    path: req.path,
  });

  const response = createErrorResponse(code, message, err.field);

  if (isDev) {
    (response as any).stack = err.stack;
  }

  res.status(status).json(response);
}

// ============ REQUEST LOGGING MIDDLEWARE ============

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();
  const originalSend = res.send;

  res.send = function (data) {
    const duration = Date.now() - start;
    const logEntry = {
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      user: (req.user as import("@shared/schema").User)?.id || "anonymous",
      role: (req.user as import("@shared/schema").User)?.role || "none",
    };

    // Log important events
    if (req.path.includes("/api/auth")) {
      console.log("[AUTH]", logEntry);
    } else if (req.path.includes("/api/admin")) {
      console.log("[ADMIN]", logEntry);
    } else if (res.statusCode >= 400) {
      console.log("[ERROR]", logEntry);
    }

    return originalSend.call(this, data);
  };

  next();
}

// ============ VALIDATION ERROR MIDDLEWARE ============

export function validationErrorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) {
  // Handle Zod validation errors
  if (err.name === "ZodError") {
    const firstError = err.errors[0];
    return res.status(400).json(
      createErrorResponse(
        ErrorCodes.MISSING_FIELD,
        `${firstError.path.join(".")} - ${firstError.message}`,
        firstError.path[0]
      )
    );
  }

  next(err);
}
