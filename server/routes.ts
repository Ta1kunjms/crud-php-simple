// ...existing code...

// Place this after app is defined:
// app.get("/api/reports/skills", async (req: Request, res: Response) => {
//   try {
//     const data = await storage.getSkillsReport();
//     res.json(data);
//   } catch (error) {
//     res.status(500).json({ error: "Failed to fetch skills report" });
//   }
// });
import express, { Request, Response, NextFunction } from "express";
import { randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import { eq, and, or, sql, inArray, desc } from "drizzle-orm";
import { z } from "zod";
import {
  usersTable,
  employersTable,
  jobsTable,
  applicationsTable,
  messagesTable,
  adminsTable,
  notificationsTable,
  notesTable,
  referralsTable,
  adminAccessRequestsTable,
  skillSuggestionsTable,
} from "./unified-schema";
import { storage, classifyEmploymentStatus } from "./storage";
import { authMiddleware, adminOnly, roleMiddleware } from "./middleware";
import { 
  APPLICATION_STATUS, 
  canTransitionStatus, 
  mapApplicationToReferralStatus, 
  mapApplicationToEmploymentStatus 
} from "./constants";
import {
  authSettingsSchema,
  adminAccessRequestSchema,
  applicantSchema,
  applicantCreateSchema,
  applicantFilterSchema,
  employerSchema,
  employerCreateSchema,
  referralFiltersSchema,
  notesFiltersSchema,
  jobCreateSchema,
  jobVacancyFiltersSchema,
  adminCreateSchema,
  adminRoleSchema,
  loginSchema,
  changePasswordSchema,
  industryCodes,
  generalSettingsSchema,
} from "@shared/schema";
import type { AuthSettings, AuthProvider } from "@shared/schema";
import {
  createErrorResponse,
  ErrorCodes,
  generateToken,
  hashPassword,
  validateEmail,
  validatePassword,
  verifyPassword,
  passport,
  DEFAULT_GOOGLE_CALLBACK_URL,
} from "./auth";
import { computeProfileCompleteness } from "./utils/status";
import { uploadEmployerDocs, formatEmployerDocMetadata } from "./fileUpload";
import path from "path";
import { createSupabaseAnonClient, isSupabaseConfigured } from "./supabase";

type JobseekerAccount = {
  id: string;
  email: string;
  passwordHash: string;
  role: "jobseeker" | "freelancer";
  name: string;
};

type EmployerAccount = {
  id: string;
  email: string;
  passwordHash: string;
  role: "employer";
  name: string;
};

function sendError(res: Response, error: unknown, status = 500) {
  const message = error instanceof Error ? error.message : String(error);
  // Log server-side errors to aid debugging unexpected 500 responses
  console.error("[API ERROR]", error);
  return res
    .status(status)
    .json(createErrorResponse(ErrorCodes.INTERNAL_SERVER_ERROR, message));
}

type ValidationAlert = {
  id: string;
  message: string;
  field?: string;
  route: string;
  method: string;
  timestamp: string;
};

const VALIDATION_ALERT_LIMIT = 50;
const validationAlerts: ValidationAlert[] = [];

const messageCreateSchema = z.object({
  receiverId: z.string().min(1, "receiverId is required"),
  receiverRole: z.enum(["employer", "jobseeker", "admin", "freelancer"]).optional(),
  subject: z.string().max(200).nullable().optional(),
  content: z.string().min(1, "content is required").max(5000),
});

const jobApplicationPayloadSchema = z.object({
  coverLetter: z.string().max(5000).optional(),
});

const allowedEmployerApplicationStatuses = new Set([
  "pending",
  "shortlisted",
  "accepted",
  "rejected",
  "hired",
  "interview",
  "in-review",
  "needs-feedback",
  "on-hold",
]);

const employerApplicationUpdateSchema = z.object({
  status: z
    .string()
    .min(1)
    .max(50)
    .transform((v) => v.trim().toLowerCase())
    .refine((v) => allowedEmployerApplicationStatuses.has(v), "Invalid status"),
  notes: z.string().max(2000).optional(),
}).superRefine((val, ctx) => {
  if (val.status === "rejected") {
    const notes = (val.notes || "").trim();
    if (!notes) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["notes"],
        message: "Notes are required when rejecting an application",
      });
    }
  }
});

const adminJobUpdateSchema = jobCreateSchema.partial().extend({
  status: z.string().optional(),
  archived: z.boolean().optional(),
  archivedAt: z.union([z.string(), z.date(), z.null()]).optional(),
});

const applicantUpdateSchema = applicantSchema.partial();

const notificationReadSchema = z.object({
  id: z.string().min(1, "id is required"),
});

const skillSuggestionQuerySchema = z.object({
  q: z.string().optional(),
  limit: z
    .string()
    .optional()
    .transform((v) => (v ? Number.parseInt(v, 10) : undefined))
    .refine((v) => v === undefined || (Number.isFinite(v) && v > 0 && v <= 500), "Invalid limit"),
});

const skillSuggestionCreateSchema = z
  .object({
    name: z.string().min(1).max(120),
  })
  .or(
    z.object({
      names: z.array(z.string().min(1).max(120)).min(1).max(50),
    })
  );

function normalizeSkillSuggestionName(raw: string) {
  const trimmed = raw.trim().replace(/\s+/g, " ");
  const normalized = trimmed.toLowerCase();
  return { trimmed, normalized };
}

const SKILL_SUGGESTION_SEEDS = [
  "Auto Mechanic",
  "Beautician",
  "Carpentry Work",
  "Computer Literate",
  "Domestic Chores",
  "Driver",
  "Electrician",
  "Embroidery",
  "Gardening",
  "Masonry",
  "Painter/Artist",
  "Painting Jobs",
  "Photography",
  "Plumbing",
  "Sewing Dresses",
  "Stenography",
  "Tailoring",
] as const;

let skillSuggestionsSeedPromise: Promise<void> | null = null;

async function ensureSkillSuggestionsSeeded() {
  if (skillSuggestionsSeedPromise) return skillSuggestionsSeedPromise;
  skillSuggestionsSeedPromise = (async () => {
    const db = await storage.getDb();

    const existing = (await db
      .select({ normalizedName: skillSuggestionsTable.normalizedName })
      .from(skillSuggestionsTable)
      .limit(10000)) as Array<{ normalizedName: string }>;

    const existingSet = new Set(existing.map((r: { normalizedName: string }) => r.normalizedName));

    for (const name of SKILL_SUGGESTION_SEEDS) {
      const { trimmed, normalized } = normalizeSkillSuggestionName(name);
      if (!trimmed) continue;
      if (existingSet.has(normalized)) continue;
      await db.insert(skillSuggestionsTable).values({
        name: trimmed,
        normalizedName: normalized,
      } as any);
      existingSet.add(normalized);
    }
  })();
  return skillSuggestionsSeedPromise;
}

const DEFAULT_GENERAL_SETTINGS = generalSettingsSchema.parse({
  siteName: "GensanWorks",
  siteDescription: "Official Job Assistance Platform of PESO � General Santos City",
  contactEmail: "admin@gensanworks.com",
  contactPhone: "+63 283 889 5200",
  address: "General Santos City, South Cotabato",
  heroHeadline: "Connecting jobseekers and employers in General Santos City",
  heroSubheadline: "A single window for opportunities, referrals, and PESO services",
  primaryCTA: "Browse Jobs",
  secondaryCTA: "Post a Vacancy",
  aboutTitle: "Why GensanWorks",
  aboutBody: "PESO-led platform for job matching, referrals, and analytics across the city.",
  heroBackgroundImage: "https://images.unsplash.com/photo-1521791136064-7986c2920216?auto=format&fit=crop&w=1600&q=80",
  seoKeywords: "peso gensan jobs, job portal gensan, peso referrals",
});

function recordValidationAlert(res: Response, message: string, field?: string) {
  const req = res.req as Request | undefined;
  const route = req?.originalUrl || req?.url || "unknown";
  const method = req?.method || "UNKNOWN";
  validationAlerts.unshift({
    id: `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    message,
    field,
    route,
    method,
    timestamp: new Date().toISOString(),
  });
  if (validationAlerts.length > VALIDATION_ALERT_LIMIT) {
    validationAlerts.length = VALIDATION_ALERT_LIMIT;
  }
}

function sendValidationError(res: Response, message: string, field?: string) {
  recordValidationAlert(res, message, field);
  // Use MISSING_FIELD if message indicates missing/required, else INVALID_FORMAT
  const code = /required|missing|All fields/i.test(message)
    ? ErrorCodes.MISSING_FIELD
    : ErrorCodes.INVALID_FORMAT;
  return res
    .status(400)
    .json(createErrorResponse(code, message, field));
}

async function initStorageWithDatabase() {
  await storage.getDb();
}

async function getJobseekerByEmailWithPassword(email: string): Promise<JobseekerAccount | null> {
  const db = await storage.getDb();
  const normalizedEmail = email.trim().toLowerCase();
  const applicant = await db
    .select({
      id: usersTable.id,
      email: usersTable.email,
      passwordHash: usersTable.passwordHash,
      role: usersTable.role,
      firstName: usersTable.firstName,
      surname: usersTable.surname,
    })
    .from(usersTable)
    // Case-insensitive match to avoid login failures when stored email casing differs.
    .where(sql`lower(${usersTable.email}) = ${normalizedEmail}`)
    .limit(1)
    .then((rows: any[]) => rows[0]);
  if (!applicant || !applicant.passwordHash) {
    return null;
  }
  const nameParts = [applicant.firstName, applicant.surname].filter(Boolean);
  return {
    id: applicant.id,
    email: applicant.email,
    passwordHash: applicant.passwordHash,
    role: (applicant.role as "jobseeker" | "freelancer") || "jobseeker",
    name: nameParts.join(" ").trim() || applicant.email,
  };
}

async function getEmployerByEmailWithPassword(email: string): Promise<EmployerAccount | null> {
  const db = await storage.getDb();
  const normalizedEmail = email.trim().toLowerCase();
  const employer = await db.query.employersTable.findFirst({
    where: (table: typeof employersTable) => sql`lower(${table.email}) = ${normalizedEmail}`,
  });
  if (!employer || !employer.passwordHash) {
    return null;
  }
  return {
    id: employer.id,
    email: employer.email,
    passwordHash: employer.passwordHash,
    role: "employer",
    name: employer.establishmentName || employer.email,
  };
}

// Get admin by email (real)
async function getAdminByEmailWithPassword(email: string) {
  const db = await storage.getDb();
  const normalizedEmail = email.trim().toLowerCase();
  const result = await db
    .select()
    .from(adminsTable)
    .where(sql`lower(${adminsTable.email}) = ${normalizedEmail}`)
    .limit(1);
  return result[0] ?? null;
}


function formatJobTimestamps(job: any): any {
  if (!job) return job;

  const toIso = (value: unknown) => {
    if (!value) return undefined;
    const parsedValue = value instanceof Date
      ? value
      : new Date(typeof value === "number" ? value : String(value));
    if (Number.isNaN(parsedValue.getTime())) {
      return undefined;
    }
    return parsedValue.toISOString();
  };

  return {
    ...job,
    createdAt: toIso(job.createdAt) || new Date().toISOString(),
    updatedAt: toIso(job.updatedAt),
  };
}

function serializeJob(job: any) {
  const withTimestamps = formatJobTimestamps(job);
  const derivedTitle =
    withTimestamps.title ||
    withTimestamps.positionTitle ||
    withTimestamps.jobTitle ||
    withTimestamps.establishmentName ||
    "Untitled Job";
  const derivedLocation =
    withTimestamps.location ||
    withTimestamps.barangay ||
    withTimestamps.municipality ||
    withTimestamps.province;

  return {
    ...withTimestamps,
    title: derivedTitle,
    positionTitle: withTimestamps.positionTitle || derivedTitle,
    location: derivedLocation,
  };
}

const safeJson = <T = any>(value: unknown, fallback: T): T => {
  if (!value) return fallback;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  if (Array.isArray(value) || typeof value === "object") {
    return value as T;
  }
  return fallback;
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value) && !(value instanceof Date);

const DATE_KEY_PATTERN = /(date|timestamp|_at|At|_on|On|deadline)$/i;

const formatDateValue = (value: unknown): string | undefined => {
  if (value === null || value === undefined) return undefined;
  if (value instanceof Date) {
    const time = value.getTime();
    return Number.isNaN(time) ? undefined : value.toISOString();
  }
  if (typeof value === "string" || typeof value === "number") {
    const parsed = new Date(value as any);
    return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
  }
  return undefined;
};

const normalizeDateFields = (input: any): any => {
  if (Array.isArray(input)) {
    return input.map(normalizeDateFields);
  }
  if (input instanceof Date) {
    return formatDateValue(input);
  }
  if (isPlainObject(input)) {
    const normalized: Record<string, unknown> = {};
    Object.entries(input).forEach(([key, value]) => {
      if (DATE_KEY_PATTERN.test(key)) {
        const formatted = formatDateValue(value);
        normalized[key] = formatted ?? value;
      } else {
        normalized[key] = normalizeDateFields(value);
      }
    });
    return normalized;
  }
  return input;
};

const toIsoString = (value: unknown): string | undefined => formatDateValue(value);

const mapApplicantToProfileShape = (row: any) => {
  const raw = { ...(row || {}) };

  // Never expose sensitive fields
  delete (raw as any).passwordHash;
  delete (raw as any).password_hash;

  const normalizeArray = <T>(value: unknown, fallback: T[] = []): T[] => {
    const parsed = safeJson<unknown>(value, fallback);
    if (Array.isArray(parsed)) return parsed as T[];
    if (typeof parsed === "string") {
      const trimmed = parsed.trim();
      return trimmed ? ([trimmed] as unknown as T[]) : fallback;
    }
    return fallback;
  };

  // Ensure the fields used by the Jobseeker NSRP editor match Applicant schema expectations
  const profile = {
    ...raw,
    profileImage: raw.profileImage || raw.profile_image || null,

    // Normalize booleans (db may store 0/1)
    isOFW: Boolean(raw.isOFW ?? raw.isOfw ?? raw.is_ofw),
    isFormerOFW: Boolean(raw.isFormerOFW ?? raw.isFormerOfw ?? raw.is_former_ofw),
    is4PSBeneficiary: Boolean(raw.is4PSBeneficiary ?? raw.is4psBeneficiary ?? raw.is_4ps_beneficiary),

    // JSON fields expected as arrays/objects in the Applicant schema
    education: normalizeArray(raw.education, []),
    technicalTraining: normalizeArray(raw.technicalTraining ?? raw.technical_training, []),
    professionalLicenses: normalizeArray(raw.professionalLicenses ?? raw.professional_licenses, []),
    languageProficiency: normalizeArray(raw.languageProficiency ?? raw.language_proficiency, []),
    workExperience: normalizeArray(raw.workExperience ?? raw.work_experience, []),
    familyMembers: normalizeArray(raw.familyMembers, []),
    dependents: normalizeArray(raw.dependents, []),
    references: normalizeArray(raw.references, []),
    documentRequirements: normalizeArray(raw.documentRequirements, []),
    additionalAddresses: normalizeArray(raw.additionalAddresses, []),
    preferredOccupations: normalizeArray(raw.preferredOccupations, []),
    preferredLocations: normalizeArray(raw.preferredLocations, []),
    preferredOverseasCountries: normalizeArray(raw.preferredOverseasCountries, []),

    // Skills in table views may be a string; profile editing expects arrays
    skills: normalizeArray<string>(raw.skills, []),
    otherSkills: normalizeArray<string>(raw.otherSkills ?? raw.other_skills, []),
    otherSkillsTraining: normalizeArray<string>(raw.otherSkillsTraining ?? raw.other_skills_training, []),
  };

  return normalizeDateFields(profile);
};

const mapApplicantToTableShape = (app: any) => {
  const birthDate = app.dateOfBirth || app.birthDate || app.birth_date || "";
  const sexValue = app.sex || app.gender || "";
  const education = safeJson<any[]>(app.education, []);
  const firstEducation = education[0] || {};
  const skills = safeJson<string[] | string>(app.skills, []);
  const skillsList = Array.isArray(skills)
    ? skills
    : typeof skills === "string" && skills.length
      ? [skills]
      : [];
  const otherSkills = safeJson<string[] | string>(app.otherSkills, []);
  const otherSkillsList = Array.isArray(otherSkills)
    ? otherSkills
    : typeof otherSkills === "string" && otherSkills.length
      ? [otherSkills]
      : [];
  const address = app.address || [app.houseStreetVillage, app.barangay, app.municipality, app.province]
    .filter(Boolean)
    .join(", ");
  return {
    id: app.id,
    // Flat table-friendly fields
    first_name: app.firstName || app.first_name || app.first_name || "",
    middle_name: app.middleName || app.middle_name || "",
    last_name: app.lastName || app.last_name || app.surname || "",
    suffix: app.suffix || "None",
    birth_date: birthDate,
    gender: sexValue || "Other",
    sex: sexValue || "Other",
    civil_status: app.civilStatus || app.civil_status || "Single",
    religion: app.religion || "",
    height: app.height || "",
    weight: app.weight || "",
    blood_type: app.bloodType || "",
    nationality: app.nationality || "",
    citizenship: app.citizenship || "",
    place_of_birth: app.placeOfBirth || "",
    email: app.email || "",
    phone: app.contactNumber || app.phone || "",
    address,
    education_level: firstEducation.level || app.educationLevel || app.education_level || "",
    course: firstEducation.course || app.course || "",
    skills: [...skillsList, ...otherSkillsList].filter(Boolean).join(", "),
    employment_status: app.employmentStatus || app.employment_status || "Unemployed",
    registration_date:
      toIsoString(app.registrationDate || app.registeredAt || app.registration_date || app.createdAt || app.created_at) || "",
    nsrp_registration_no: app.nsrpRegistrationNo || app.nsrp_registration_no || app.nsrpNumber || "",
    profile_image: app.profileImage || app.profile_image || "",
    created_at: toIsoString(app.createdAt || app.created_at) || "",
    updated_at: toIsoString(app.updatedAt || app.updated_at) || "",
    archived: Boolean(app.archived),
    employment_status_detail: app.employmentStatusDetail || app.employment_status_detail || "",
    self_employed_category: app.selfEmployedCategory || app.self_employed_category || "",
    self_employed_category_other: app.selfEmployedCategoryOther || app.self_employed_category_other || "",
    unemployed_reason: app.unemployedReason || app.unemployed_reason || "",
    unemployed_reason_other: app.unemployedReasonOther || app.unemployed_reason_other || "",
    unemployed_abroad_country: app.unemployedAbroadCountry || app.unemployed_abroad_country || "",
    employment_type: app.employmentType || app.employment_type || "",
    months_unemployed: app.monthsUnemployed ?? app.months_unemployed ?? null,
    is_ofw: Boolean(app.isOfw ?? app.isOFW),
    is_former_ofw: Boolean(app.isFormerOfw ?? app.isFormerOFW),
    is_4ps_beneficiary: Boolean(app.is4psBeneficiary ?? app.is4PSBeneficiary),
    is_pwd: Boolean(app.isPwd ?? app.isPWD ?? app.isPersonWithDisability),
    is_solo_parent: Boolean(app.isSoloParent ?? app.soloParent),
    house_street_village: app.houseStreetVillage || app.house_street_village || "",
    barangay: app.barangay || "",
    municipality: app.municipality || "",
    province: app.province || "",
    education: education,
    technical_training: safeJson<any[]>(app.technicalTraining, []),
    professional_licenses: safeJson<any[]>(app.professionalLicenses, []),
    language_proficiency: safeJson<any[]>(app.languageProficiency, []),
    work_experience: safeJson<any[]>(app.workExperience, []),
    other_skills: otherSkillsList,
    other_skills_specify: app.otherSkillsSpecify || "",
    other_skills_training: app.otherSkillsTraining || "",

    // Legacy camelCase aliases for compatibility
    firstName: app.firstName || app.first_name || "",
    middleName: app.middleName || app.middle_name || "",
    surname: app.surname || app.last_name || "",
    lastName: app.lastName || app.surname || "",
    birthDate,
    dateOfBirth: birthDate,
    bloodType: app.bloodType || "",
    placeOfBirth: app.placeOfBirth || "",
    civilStatus: app.civilStatus || app.civil_status || "Single",
    contactNumber: app.contactNumber || app.phone || "",
    employmentStatus: app.employmentStatus || app.employment_status || "Unemployed",
    employmentStatusDetail: app.employmentStatusDetail || app.employment_status_detail || "",
    selfEmployedCategory: app.selfEmployedCategory || app.self_employed_category || "",
    selfEmployedCategoryOther: app.selfEmployedCategoryOther || app.self_employed_category_other || "",
    unemployedReason: app.unemployedReason || app.unemployed_reason || "",
    unemployedReasonOther: app.unemployedReasonOther || app.unemployed_reason_other || "",
    unemployedAbroadCountry: app.unemployedAbroadCountry || app.unemployed_abroad_country || "",
    employmentType: app.employmentType || app.employment_type || "",
    monthsUnemployed: app.monthsUnemployed ?? app.months_unemployed,
    isOfw: Boolean(app.isOfw ?? app.isOFW),
    isOFW: Boolean(app.isOfw ?? app.isOFW),
    isFormerOfw: Boolean(app.isFormerOfw ?? app.isFormerOFW),
    isFormerOFW: Boolean(app.isFormerOfw ?? app.isFormerOFW),
    is4psBeneficiary: Boolean(app.is4psBeneficiary ?? app.is4PSBeneficiary),
    is4PSBeneficiary: Boolean(app.is4psBeneficiary ?? app.is4PSBeneficiary),
    isPwd: Boolean(app.isPwd ?? app.isPWD ?? app.isPersonWithDisability),
    isPWD: Boolean(app.isPwd ?? app.isPWD ?? app.isPersonWithDisability),
    isSoloParent: Boolean(app.isSoloParent ?? app.soloParent),
    houseStreetVillage: app.houseStreetVillage || app.house_street_village || "",
    registrationDate: toIsoString(app.registrationDate || app.registeredAt || app.registration_date || app.createdAt || app.created_at) || "",
    nsrpRegistrationNo: app.nsrpRegistrationNo || app.nsrp_registration_no || app.nsrpNumber || "",
    profileImage: app.profileImage || app.profile_image || "",
  };
};

const deriveCompanySize = (count?: number | null) => {
  if (typeof count !== "number") return "Micro";
  if (count <= 10) return "Micro";
  if (count <= 50) return "Small";
  if (count <= 250) return "Medium";
  return "Large";
};

const mapEmployerToTableShape = (employer: any) => {
  const contact = safeJson<any>(employer.contactPerson, {});
  const status = employer.archived ? "inactive" : employer.status || "active";
  const address = employer.completeAddress ||
    [employer.houseStreetVillage, employer.barangay, employer.municipality, employer.province]
      .filter(Boolean)
      .join(", ");
  const industry = safeJson<any>(employer.industryType, employer.companyIndustry || employer.industryCodes || []);
  const industryLabel = Array.isArray(industry) ? (industry[0]?.subSector || industry[0] || "") : industry?.subSector || industry || "";
  return {
    id: employer.id,
    name: employer.name || employer.establishmentName || "",
    email: employer.email || "",
    phone: employer.phone || employer.contactNumber || "",
    address,
    company_name: employer.company_name || employer.tradeName || employer.establishmentName || "",
    company_type: employer.company_type || employer.companyType || "Private",
    company_industry: industryLabel || employer.company_industry || employer.companyIndustry || "Others",
    company_size: employer.company_size || employer.companySize || deriveCompanySize(employer.numberOfPaidEmployees),
    company_registration_no:
      employer.company_registration_no || employer.companyRegistrationNo || employer.companyTin || employer.companyTaxIdNumber || "",
    company_description: employer.company_description || employer.companyDescription || employer.remarks || "",
    contact_person: contact.name || employer.contact_person || "",
    contact_position: contact.designation || employer.contact_position || "",
    contact_email: contact.email || employer.contact_email || "",
    contact_phone: contact.phone || employer.contact_phone || "",
    status: employer.status || status,
    created_at: toIsoString(employer.createdAt || employer.created_at) || "",
    updated_at: toIsoString(employer.updatedAt || employer.updated_at) || "",
    archived: Boolean(employer.archived),
    profile_image: employer.profile_image || employer.profileImage || "",
    // Legacy camelCase aliases
    establishmentName: employer.establishmentName,
    tradeName: employer.tradeName,
    contactNumber: employer.contactNumber || employer.phone,
    createdAt: toIsoString(employer.createdAt || employer.created_at) || "",
    updatedAt: toIsoString(employer.updatedAt || employer.updated_at) || "",
  };
};

const mapJobStatus = (job: any) => {
  if (job.archived) return "archived";
  const status = (job.status || job.jobStatus || "open").toLowerCase();
  if (status === "active" || status === "approved") return "open";
  if (status === "closed") return "closed";
  if (status === "draft" || status === "pending") return "draft";
  return status;
};

const deriveExperienceLevel = (years?: number | null) => {
  if (typeof years !== "number") return "Entry";
  if (years <= 1) return "Entry";
  if (years <= 4) return "Mid";
  if (years <= 7) return "Senior";
  if (years <= 10) return "Managerial";
  return "Executive";
};

const mapJobToTableShape = (job: any) => {
  const base = { ...job };
  const salary = safeJson<any>(job.salary, {});
  const requirements = safeJson<any[]>(job.requirements, []);
  const contact = safeJson<any>(job.contact, {});
  const salaryPeriodRaw = salary.frequency || job.salaryPeriod;
  const salaryPeriod = salaryPeriodRaw
    ? {
        monthly: "Monthly",
        week: "Weekly",
        weekly: "Weekly",
        daily: "Daily",
        day: "Daily",
        hourly: "Hourly",
      }[String(salaryPeriodRaw).toLowerCase()] || "Monthly"
    : "Monthly";
  const salaryMin = job.salaryMin ?? salary.min ?? salary.from ?? null;
  const salaryMax = job.salaryMax ?? salary.max ?? salary.to ?? null;
  const location = job.location || [job.barangay, job.municipality, job.province].filter(Boolean).join(", ");
  const establishmentName =
    job.establishmentName ||
    job.establishment_name ||
    job.companyName ||
    job.company_name ||
    job.company ||
    job.employerName ||
    job.employer_name ||
    job.tradeName ||
    contact.person ||
    "";
  const requirementText = requirements
    .map((r: any) => r.label || r.name || r)
    .filter(Boolean)
    .join("; ");
  const experienceYears = job.yearsOfExperienceRequired ?? job.yearsExperience ?? job.years_of_experience;
  const industryCodes = safeJson<any[]>(job.industryCodes, []);
  const jobCategory = Array.isArray(industryCodes) && industryCodes.length
    ? industryCodes[0].description || industryCodes[0].code || ""
    : job.job_category || job.jobCategory || "";

  const preparedByName = job.preparedByName || contact.person || job.jobContactPerson || job.job_contact_person || "";
  const preparedByDesignation = job.preparedByDesignation || "";
  const preparedByContact = job.preparedByContact || contact.phone || job.jobContactPhone || job.job_contact_phone || "";

  return {
    ...base,
    id: job.id,
    position_title: job.positionTitle || job.title || "",
    description: job.description || "",
    establishmentName,
    companyName: job.companyName || job.company_name || establishmentName,
    employerName: job.employerName || establishmentName,
    employer_id: job.employerId || job.employer_id || "",
    status: job.status || mapJobStatus(job),
    employment_type: job.employment_type || job.employmentType || "Full-time",
    salary_min: salaryMin,
    salary_max: salaryMax,
    salary_period: job.salary_period || salaryPeriod,
    location,
    qualifications: job.qualifications || requirementText,
    responsibilities: job.responsibilities || job.description || "",
    created_at: toIsoString(job.createdAt || job.created_at) || "",
    updated_at: toIsoString(job.updatedAt || job.updated_at) || "",
    archived: Boolean(job.archived),
    vacancies: job.vacancies || job.vacantPositions || job.openings || job.paidEmployees || 0,
    job_category: job.job_category || jobCategory || "Others",
    nsrp_job_code: job.nsrp_job_code || job.nsrpJobCode || job.jobStatus || "",
    job_compensation_type: job.job_compensation_type || job.salaryType || salary.type || "Salary",
    job_compensation_details: job.job_compensation_details || salary.details || JSON.stringify(salary || {}),
    job_benefits: job.job_benefits || job.jobBenefits || "",
    job_requirements: job.job_requirements || requirementText,
    job_experience_level: job.job_experience_level || job.jobExperienceLevel || deriveExperienceLevel(experienceYears),
    job_education_level: job.job_education_level || job.jobEducationLevel || job.minimumEducationRequired || "",
    job_shift: job.job_shift || job.jobShift || contact.officeHours || "Day",
    job_schedule: job.job_schedule || job.jobSchedule || "Regular",
    job_application_deadline: toIsoString(job.job_application_deadline || job.jobApplicationDeadline) || "",
    job_contact_person: job.job_contact_person || job.jobContactPerson || contact.person || preparedByName || "",
    job_contact_email: job.job_contact_email || job.jobContactEmail || contact.email || "",
    job_contact_phone: job.job_contact_phone || job.jobContactPhone || contact.phone || preparedByContact || "",

    // Preserve and normalize commonly used structured fields
    barangay: job.barangay || "",
    municipality: job.municipality || "",
    province: job.province || "",
    industryCodes: Array.isArray(industryCodes) ? industryCodes.map((v) => String((v as any)?.code ?? v)) : [],
    minimumEducationRequired: job.minimumEducationRequired || job.jobEducationLevel || "",
    mainSkillOrSpecialization: job.mainSkillOrSpecialization || job.skills || "",
    yearsOfExperienceRequired: typeof experienceYears === "number" ? experienceYears : normalizeNumber(experienceYears, 0),
    agePreference: job.agePreference || "",
    vacantPositions: normalizeNumber(job.vacantPositions ?? job.vacancies ?? job.openings, 0),
    paidEmployees: normalizeNumber(job.paidEmployees, 0),
    preparedByName,
    preparedByDesignation,
    preparedByContact,
    dateAccomplished: job.dateAccomplished || "",

    // Legacy camelCase aliases for compatibility
    positionTitle: job.positionTitle || job.title || "",
    employerId: job.employerId || job.employer_id || "",
    salaryMin: salaryMin,
    salaryMax: salaryMax,
    salaryPeriod: job.salary_period || salaryPeriod,
    jobCategory: job.job_category || jobCategory || "Others",
    jobStatus: job.status || mapJobStatus(job),
    openings: job.vacancies || job.vacantPositions || job.openings || 0,
    createdAt: toIsoString(job.createdAt || job.created_at) || "",
    updatedAt: toIsoString(job.updatedAt || job.updated_at) || "",
  };
};

const employerJobUpdateSchema = jobCreateSchema
  .omit({ employerId: true, status: true })
  .partial();
const allowedJobStatuses = new Set(["pending", "active", "draft", "closed", "rejected"]);
const employerUpdateSchema = employerSchema.partial();

const parseIso = (value: unknown) => {
  if (!value) return undefined;
  if (value instanceof Date) {
    const ts = value.getTime();
    return Number.isNaN(ts) ? undefined : value.toISOString();
  }
  if (typeof value === "number") {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }
  if (typeof value === "string") {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }
  return undefined;
};

const normalizeNumber = (value: unknown, fallback = 0) => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }
  return fallback;
};

const normalizeBoolean = (value: unknown) => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return ["true", "1", "yes", "on"].includes(normalized);
  }
  if (typeof value === "number") return value !== 0;
  return Boolean(value);
};

const serializeApplicantForAdmin = (applicant: any) => {
  const createdAtIso = parseIso(applicant?.createdAt) ?? parseIso(applicant?.created_at);
  const updatedAtIso = parseIso(applicant?.updatedAt) ?? parseIso(applicant?.updated_at);
  const registrationDate =
    parseIso(applicant?.registrationDate) ??
    createdAtIso ??
    parseIso(applicant?.dateAccomplished) ??
    parseIso(applicant?.date_accomplished);
  const employmentStatus = applicant?.employmentStatus ?? applicant?.employment_status ?? null;
  const employmentType = applicant?.employmentType ?? applicant?.employment_type ?? null;

  return {
    ...applicant,
    employmentStatus,
    employmentType,
    createdAt: createdAtIso ?? null,
    updatedAt: updatedAtIso ?? null,
    registrationDate: registrationDate ?? null,
  };
};

const normalizeIndustryType = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.map((v) => String(v)).filter(Boolean);
  }
  if (typeof value === "string" && value.trim() !== "") {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) {
        return parsed.map((v) => String(v)).filter(Boolean);
      }
    } catch (error) {
      // fall back to comma separated parsing below
    }
    return value
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
  }
  return [];
};

const validIndustryCodes = new Set(industryCodes.map((entry) => (typeof entry === "string" ? entry : entry.code)));

const normalizeIndustryCodes = (value: unknown): string[] => {
  const list = normalizeIndustryType(value);
  return list.filter((code) => validIndustryCodes.has(code));
};

const normalizeEmployerInput = (input: any = {}) => ({
  ...input,
  numberOfPaidEmployees: normalizeNumber(input.numberOfPaidEmployees),
  numberOfVacantPositions: normalizeNumber(input.numberOfVacantPositions),
  industryType: normalizeIndustryType(input.industryType ?? input.industryCodes),
  industryCodes: normalizeIndustryCodes(input.industryCodes ?? input.industryType),
  srsSubscriber: normalizeBoolean(input.srsSubscriber),
  isManpowerAgency: normalizeBoolean(input.isManpowerAgency),
  additionalEstablishments: Array.isArray(input.additionalEstablishments)
    ? input.additionalEstablishments.map((est: any) => ({
        ...est,
        numberOfPaidEmployees: normalizeNumber(est.numberOfPaidEmployees),
        numberOfVacantPositions: normalizeNumber(est.numberOfVacantPositions),
        industryType: normalizeIndustryType(est.industryType ?? est.industryCodes),
        industryCodes: normalizeIndustryCodes(est.industryCodes ?? est.industryType),
        srsSubscriber: normalizeBoolean(est.srsSubscriber),
        isManpowerAgency: normalizeBoolean(est.isManpowerAgency),
      }))
    : undefined,
});

const deepNormalizeStrings = (obj: any): any => {
  // Preserve arrays/objects as-is while removing nullish values; avoid coercing to strings
  if (Array.isArray(obj)) {
    return obj.map(deepNormalizeStrings);
  }
  if (obj && typeof obj === "object") {
    const normalized: Record<string, any> = {};
    Object.entries(obj).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        normalized[key] = undefined;
      } else if (typeof value === "object") {
        normalized[key] = deepNormalizeStrings(value);
      } else {
        normalized[key] = value;
      }
    });
    return normalized;
  }
  return obj;
};

const ensureEmployerContactPerson = (payload: any) => {
  const fallbackName = payload.preparedByName || payload.contactPerson?.personName || payload.establishmentName || payload.tradeName || "Unspecified Contact";
  const fallbackDesignation = payload.preparedByDesignation || payload.contactPerson?.designation || "";
  const fallbackContact = payload.preparedByContact || payload.contactNumber || payload.contactPerson?.contactNumber || "";
  const fallbackEmail = payload.contactEmail || payload.email || payload.contactPerson?.email || "";

  if (!payload.contactPerson || typeof payload.contactPerson !== "object") {
    return {
      personName: fallbackName,
      designation: fallbackDesignation,
      contactNumber: fallbackContact,
      email: fallbackEmail,
    };
  }

  return {
    personName: payload.contactPerson.personName || fallbackName,
    designation: payload.contactPerson.designation || fallbackDesignation,
    contactNumber: payload.contactPerson.contactNumber || fallbackContact,
    email: payload.contactPerson.email || fallbackEmail,
  };
};

const prepareEmployerPayload = (input: any, existing?: any) => {
  const base = existing ? serializeEmployerRow(existing) : {};
  const normalizedInput = normalizeEmployerInput(input);
  const merged = {
    ...base,
    ...normalizedInput,
  };
  const safe = deepNormalizeStrings(merged);
  safe.contactPerson = ensureEmployerContactPerson({
    ...base,
    ...normalizedInput,
    contactPerson: safe.contactPerson,
  });

  const stringifyFileMetadata = (value: any) => {
    if (value === null || value === undefined) return undefined;
    if (typeof value === "string") return value;
    if (typeof value === "object") {
      try {
        return JSON.stringify(value);
      } catch {
        return undefined;
      }
    }
    return String(value);
  };

  // These fields are stored as JSON strings in DB but may be parsed into objects when serialized.
  const fileFields = [
    "srsFormFile",
    "businessPermitFile",
    "bir2303File",
    "companyProfileFile",
    "doleCertificationFile",
  ] as const;

  fileFields.forEach((field) => {
    if (field in safe) {
      (safe as any)[field] = stringifyFileMetadata((safe as any)[field]);
    }
  });

  if (Array.isArray((safe as any).additionalEstablishments)) {
    (safe as any).additionalEstablishments = (safe as any).additionalEstablishments.map((est: any) => {
      if (!est || typeof est !== "object") return est;
      const next = { ...est };
      fileFields.forEach((field) => {
        if (field in next) {
          (next as any)[field] = stringifyFileMetadata((next as any)[field]);
        }
      });
      return next;
    });
  }

  const resolvedExistingDate = (base as any)?.dateAccomplished;
  const incomingDate = (safe as any)?.dateAccomplished;
  if (!String(incomingDate ?? "").trim()) {
    safe.dateAccomplished = resolvedExistingDate ?? new Date().toISOString().slice(0, 10);
  }

  return safe;
};

const sanitizeTin = (value?: string | null) => {
  if (!value) return undefined;
  const digits = value.replace(/[^0-9]/g, "");
  return digits || undefined;
};

const getUrlFromFileMetadata = (value: any): string | undefined => {
  if (!value) return undefined;
  if (typeof value === "string") return value;
  if (typeof value === "object") {
    return value.path || value.url || value.fileUrl || value.file;
  }
  return undefined;
};

const deriveEmployerRequirements = (serializedEmployer: any) => {
  const businessPermitUrl = getUrlFromFileMetadata(serializedEmployer?.businessPermitFile);
  const bir2303Url = getUrlFromFileMetadata(serializedEmployer?.bir2303File);
  const companyProfileUrl = getUrlFromFileMetadata(serializedEmployer?.companyProfileFile);
  const doleUrl = getUrlFromFileMetadata(serializedEmployer?.doleCertificationFile);

  return {
    businessPermit: {
      label: "Business Permit",
      required: true,
      submitted: Boolean(businessPermitUrl),
      fileUrl: businessPermitUrl,
    },
    birForm2303: {
      label: "BIR Form 2303",
      required: true,
      submitted: Boolean(bir2303Url),
      fileUrl: bir2303Url,
    },
    companyProfile: {
      label: "Company Profile",
      required: true,
      submitted: Boolean(companyProfileUrl),
      fileUrl: companyProfileUrl,
    },
    doleAccreditation: {
      label: "DOLE Accreditation",
      required: true,
      submitted: Boolean(doleUrl),
      fileUrl: doleUrl,
    },
  };
};

const mergeEmployerRequirements = (existing: any, derived: any) => {
  const base = existing && typeof existing === "object" ? existing : {};
  const next: Record<string, any> = { ...base };

  (Object.entries(derived || {}) as Array<[string, any]>).forEach(([key, value]) => {
    const existingItem = next[key];
    if (!existingItem || typeof existingItem !== "object") {
      next[key] = value;
      return;
    }

    next[key] = {
      ...value,
      ...existingItem,
      // Prefer a real uploaded file URL if present
      fileUrl: existingItem.fileUrl || existingItem.url || value.fileUrl,
      // If any source indicates submitted, keep it submitted
      submitted: Boolean(existingItem.submitted) || Boolean(value.submitted),
      required: existingItem.required !== undefined ? Boolean(existingItem.required) : Boolean(value.required),
      label: existingItem.label || value.label,
    };
  });

  return next;
};

const serializeEmployerRow = (row: any) => {
  if (!row) return null;
  const companyTin = sanitizeTin(row.companyTin || row.companyTIN);
  const serialized: any = {
    id: row.id,
    establishmentName: row.establishmentName,
    tradeName: row.tradeName,
    houseStreetVillage: row.houseStreetVillage,
    barangay: row.barangay,
    municipality: row.municipality,
    province: row.province,
    completeAddress: row.completeAddress,
    addressDetails: row.addressDetails,
    contactNumber: row.contactNumber,
    contactEmail: row.contactEmail,
    email: row.email,
    contactPerson: row.contactPerson || null,
    // Expose Google profile image if present (from contactPerson or root)
    profileImage: (row.profileImage || row.profile_image || row.contactPerson?.profileImage || row.contactPerson?.profile_image || null),
    alternateContacts: Array.isArray(row.alternateContacts)
      ? row.alternateContacts
      : row.alternateContacts
        ? [row.alternateContacts]
        : [],
    numberOfPaidEmployees: normalizeNumber(row.numberOfPaidEmployees ?? 0, 0),
    numberOfVacantPositions: normalizeNumber(row.numberOfVacantPositions ?? 0, 0),
    industryType: normalizeIndustryType(row.industryType),
    industryCodes: normalizeIndustryCodes(row.industryCodes ?? row.industryType),
    srsSubscriber: Boolean(row.srsSubscriber),
    subscriptionStatus: row.subscriptionStatus || null,
    companyTIN: companyTin,
    companyTin,
    companyTaxIdNumber: row.companyTaxIdNumber,
    businessPermitNumber: row.businessPermitNumber,
    bir2303Number: row.bir2303Number,
    chairpersonName: row.chairpersonName,
    chairpersonContact: row.chairpersonContact,
    secretaryName: row.secretaryName,
    secretaryContact: row.secretaryContact,
    barangayChairperson: row.barangayChairperson,
    barangaySecretary: row.barangaySecretary,
    geographicIdentification: row.geographicIdentification,
    preparedByName: row.preparedByName,
    preparedByDesignation: row.preparedByDesignation,
    preparedByContact: row.preparedByContact,
    dateAccomplished: row.dateAccomplished,
    remarks: row.remarks,
    isManpowerAgency: Boolean(row.isManpowerAgency),
    doleCertificationNumber: row.doleCertificationNumber,
    requirements: row.requirements,
    attachments: row.attachments,
    // Parse file metadata from JSON strings
    srsFormFile: parseFileMetadata(row.srsFormFile),
    businessPermitFile: parseFileMetadata(row.businessPermitFile),
    bir2303File: parseFileMetadata(row.bir2303File),
    companyProfileFile: parseFileMetadata(row.companyProfileFile),
    doleCertificationFile: parseFileMetadata(row.doleCertificationFile),
    geographicCode: row.geographicCode,
    telNumber: row.telNumber,
    chairpersonTelNumber: row.chairpersonTelNumber,
    secretaryTelNumber: row.secretaryTelNumber,
    archived: Boolean(row.archived),
    archivedAt: parseIso(row.archivedAt) || null,
    // Account status fields
    accountStatus: row.accountStatus || row.account_status || "pending",
    createdBy: row.createdBy || row.created_by || "self",
    reviewedBy: row.reviewedBy || row.reviewed_by || null,
    reviewedAt: parseIso(row.reviewedAt || row.reviewed_at) || null,
    rejectionReason: row.rejectionReason || row.rejection_reason || null,
    createdAt: parseIso(row.createdAt),
    updatedAt: parseIso(row.updatedAt),
  };

  return serialized;
};

// Helper to parse file metadata from JSON string
const parseFileMetadata = (fileData: any) => {
  if (!fileData) return null;
  if (typeof fileData === "string") {
    try {
      return JSON.parse(fileData);
    } catch {
      return null;
    }
  }
  return fileData;
};

const buildEmployerInsert = (payload: any) => {
  const now = new Date();
  const companyTin = sanitizeTin(payload.companyTIN || payload.companyTin);
  return {
    id: payload.id || `employer_${Date.now()}`,
    establishmentName: payload.establishmentName,
    houseStreetVillage: payload.houseStreetVillage,
    barangay: payload.barangay,
    municipality: payload.municipality,
    province: payload.province,
    geographicCode: payload.geographicCode,
    telNumber: payload.telNumber,
    contactNumber: payload.contactNumber,
    email: payload.email,
     contactPerson: payload.contactPerson,
     alternateContacts: payload.alternateContacts,
    numberOfPaidEmployees: payload.numberOfPaidEmployees ?? 0,
    numberOfVacantPositions: payload.numberOfVacantPositions ?? 0,
    industryType: payload.industryType ?? [],
     industryCodes: payload.industryCodes ?? [],
    srsSubscriber: payload.srsSubscriber ?? false,
    companyTin,
    businessPermitNumber: payload.businessPermitNumber,
    bir2303Number: payload.bir2303Number,
    chairpersonName: payload.chairpersonName,
    chairpersonContact: payload.chairpersonContact,
    secretaryName: payload.secretaryName,
    secretaryContact: payload.secretaryContact,
    barangayChairperson: payload.barangayChairperson,
    chairpersonTelNumber: payload.chairpersonTelNumber,
    barangaySecretary: payload.barangaySecretary,
    secretaryTelNumber: payload.secretaryTelNumber,
    preparedByName: payload.preparedByName,
    preparedByDesignation: payload.preparedByDesignation,
    preparedByContact: payload.preparedByContact,
    dateAccomplished: payload.dateAccomplished,
    remarks: payload.remarks,
    isManpowerAgency: payload.isManpowerAgency ?? false,
    doleCertificationNumber: payload.doleCertificationNumber,
    // File attachments (stored as JSON strings with metadata)
    srsFormFile: payload.srsFormFile,
    businessPermitFile: payload.businessPermitFile,
    bir2303File: payload.bir2303File,
    companyProfileFile: payload.companyProfileFile,
    doleCertificationFile: payload.doleCertificationFile,
    // Account status fields
    accountStatus: payload.accountStatus || "pending",
    createdBy: payload.createdBy || "self",
    archived: false,
    archivedAt: null,
    createdAt: now,
    updatedAt: now,
  };
};

const buildEmployerUpdate = (payload: any) => {
  const companyTin = sanitizeTin(payload.companyTIN || payload.companyTin);
  const update: Record<string, any> = { updatedAt: new Date() };
  const directFields: Record<string, string> = {
    establishmentName: "establishmentName",
    tradeName: "tradeName",
    houseStreetVillage: "houseStreetVillage",
    barangay: "barangay",
    municipality: "municipality",
    province: "province",
    completeAddress: "completeAddress",
    contactNumber: "contactNumber",
    contactEmail: "contactEmail",
    email: "email",
    numberOfPaidEmployees: "numberOfPaidEmployees",
    numberOfVacantPositions: "numberOfVacantPositions",
    industryType: "industryType",
    industryCodes: "industryCodes",
    srsSubscriber: "srsSubscriber",
    subscriptionStatus: "subscriptionStatus",
    businessPermitNumber: "businessPermitNumber",
    bir2303Number: "bir2303Number",
    chairpersonName: "chairpersonName",
    chairpersonContact: "chairpersonContact",
    secretaryName: "secretaryName",
    secretaryContact: "secretaryContact",
    preparedByName: "preparedByName",
    preparedByDesignation: "preparedByDesignation",
    preparedByContact: "preparedByContact",
    dateAccomplished: "dateAccomplished",
    remarks: "remarks",
    isManpowerAgency: "isManpowerAgency",
    doleCertificationNumber: "doleCertificationNumber",
    companyTaxIdNumber: "companyTaxIdNumber",
    barangayChairperson: "barangayChairperson",
    barangaySecretary: "barangaySecretary",
    geographicCode: "geographicCode",
    telNumber: "telNumber",
    chairpersonTelNumber: "chairpersonTelNumber",
    secretaryTelNumber: "secretaryTelNumber",
    srsFormFile: "srsFormFile",
    businessPermitFile: "businessPermitFile",
    bir2303File: "bir2303File",
    companyProfileFile: "companyProfileFile",
    doleCertificationFile: "doleCertificationFile",
  };

  Object.entries(directFields).forEach(([payloadKey, column]) => {
    if (payload[payloadKey] !== undefined) {
      update[column] = payload[payloadKey];
    }
  });

  const jsonFields: string[] = [
    "contactPerson",
    "alternateContacts",
    "geographicIdentification",
    "addressDetails",
    "requirements",
    "attachments",
    "additionalEstablishments",
  ];

  jsonFields.forEach((field) => {
    if (payload[field] !== undefined) {
      update[field] = payload[field];
    }
  });

  if (companyTin !== undefined) {
    update.companyTin = companyTin;
  }

  return update;
};

const sanitizeAuthSettingsForPublic = (settings: AuthSettings): AuthSettings => {
  const sanitizedProviders: AuthProvider[] = settings.providers.map((provider) => {
    if (provider.id === "google") {
      return {
        id: "google",
        enabled: provider.enabled,
        config: {
          clientId: provider.config?.clientId,
          callbackUrl: provider.config?.callbackUrl,
        },
      };
    }
    if (provider.id === "custom") {
      return {
        id: "custom",
        enabled: provider.enabled,
        config: {
          displayName: provider.config?.displayName,
          issuer: provider.config?.issuer,
          clientId: provider.config?.clientId,
        },
      };
    }
    return provider;
  });

  return { providers: sanitizedProviders };
};

type OAuthRole = "admin" | "employer" | "jobseeker" | "freelancer";
const OAUTH_DEFAULT_ROLE: OAuthRole = "jobseeker";
const OAUTH_DEFAULT_REDIRECT = "/oauth-callback";
const roleLoginFallback: Record<OAuthRole, string> = {
  admin: "/admin/login",
  employer: "/employer/login",
  jobseeker: "/jobseeker/login",
  freelancer: "/jobseeker/login",
};

const normalizeRole = (value: unknown): OAuthRole => {
  if (typeof value === "string") {
    const lower = value.trim().toLowerCase();
    if (lower === "admin" || lower === "employer" || lower === "jobseeker" || lower === "freelancer") {
      return lower as OAuthRole;
    }
  }
  return OAUTH_DEFAULT_ROLE;
};

const sanitizeRedirectPath = (value: unknown, fallback = OAUTH_DEFAULT_REDIRECT) => {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  if (!trimmed.startsWith("/")) return fallback;
  return trimmed || fallback;
};

const generateOAuthPasswordHash = async () => {
  const randomSecret = randomBytes(32).toString("hex");
  return hashPassword(randomSecret);
};

const encodeStateToken = (state: { role: OAuthRole; redirect: string }) => {
  const json = JSON.stringify(state);
  return Buffer.from(json, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const decodeStateToken = (token?: string) => {
  if (!token || typeof token !== "string") {
    return { role: OAUTH_DEFAULT_ROLE, redirect: OAUTH_DEFAULT_REDIRECT };
  }
  try {
    const padded = token.length % 4 === 0 ? token : token + "=".repeat(4 - (token.length % 4));
    const normalized = padded.replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(normalized, "base64").toString("utf8");
    const parsed = JSON.parse(json) as { role?: OAuthRole; redirect?: string };
    return {
      role: normalizeRole(parsed.role),
      redirect: sanitizeRedirectPath(parsed.redirect, OAUTH_DEFAULT_REDIRECT),
    };
  } catch {
    return { role: OAUTH_DEFAULT_ROLE, redirect: OAUTH_DEFAULT_REDIRECT };
  }
};

const buildRedirectUrl = (basePath: string, params?: Record<string, string | undefined>) => {
  const safeBase = sanitizeRedirectPath(basePath, OAUTH_DEFAULT_REDIRECT);
  const query = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        query.append(key, value);
      }
    });
  }
  const queryString = query.toString();
  if (!queryString) return safeBase;
  return `${safeBase}${safeBase.includes("?") ? "&" : "?"}${queryString}`;
};

const getRoleLoginRedirect = (role: OAuthRole, errorCode?: string) => {
  const base = roleLoginFallback[role] || roleLoginFallback[OAUTH_DEFAULT_ROLE];
  return buildRedirectUrl(base, errorCode ? { error: errorCode } : undefined);
};

type GoogleAuthProvider = Extract<AuthProvider, { id: "google" }>;

const FALLBACK_GOOGLE_CALLBACK_PATH = "/auth/google/callback";
const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1"]);

const trimTrailingSlash = (value?: string | null): string | undefined => {
  if (!value) return undefined;
  return value.replace(/\/+$|\s+$/g, "");
};

const ensureLeadingSlash = (value: string) => (value.startsWith("/") ? value : `/${value}`);

const firstHeaderValue = (value?: string | string[]) => {
  if (!value) return undefined;
  if (Array.isArray(value)) {
    return value[0];
  }
  const [first] = value.split(",");
  return first?.trim();
};

const stripPort = (host: string) => {
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end > 0 ? host.slice(1, end) : host;
  }
  return host.split(":")[0];
};

const isLocalHostname = (host?: string) => {
  if (!host) return false;
  return LOCAL_HOSTNAMES.has(stripPort(host).toLowerCase());
};

const safeParseUrl = (value?: string | null) => {
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
};

const extractCallbackPath = (value?: string) => {
  if (!value) return FALLBACK_GOOGLE_CALLBACK_PATH;
  const parsed = safeParseUrl(value);
  if (parsed) {
    const pathname = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : FALLBACK_GOOGLE_CALLBACK_PATH;
    return ensureLeadingSlash(pathname) + (parsed.search || "") + (parsed.hash || "");
  }
  if (value.startsWith("/")) {
    return value;
  }
  return FALLBACK_GOOGLE_CALLBACK_PATH;
};

const getOriginFromUrl = (value?: string) => {
  const parsed = safeParseUrl(value);
  if (!parsed) return undefined;
  return `${parsed.protocol}//${parsed.host}`;
};

const DEFAULT_CALLBACK_PATH = extractCallbackPath(DEFAULT_GOOGLE_CALLBACK_URL) || FALLBACK_GOOGLE_CALLBACK_PATH;
const DEFAULT_CALLBACK_ORIGIN = getOriginFromUrl(DEFAULT_GOOGLE_CALLBACK_URL);
const PUBLIC_BASE_URL = trimTrailingSlash(process.env.PUBLIC_BASE_URL ?? undefined);

const resolveExternalBaseUrl = (req: Request): string | undefined => {
  if (PUBLIC_BASE_URL) {
    return PUBLIC_BASE_URL;
  }

  const forwardedHost = firstHeaderValue(req.headers["x-forwarded-host"]);
  if (forwardedHost) {
    const forwardedProto = firstHeaderValue(req.headers["x-forwarded-proto"]);
    const forwardedPort = firstHeaderValue(req.headers["x-forwarded-port"]);
    const hostHasPort = forwardedHost.includes(":") || forwardedHost.startsWith("[");
    const hostWithPort = hostHasPort ? forwardedHost : forwardedPort ? `${forwardedHost}:${forwardedPort}` : forwardedHost;
    const proto = (forwardedProto || "").toLowerCase();
    const scheme = proto === "http" ? "http" : proto === "https" ? "https" : isLocalHostname(forwardedHost) ? "http" : "https";
    return trimTrailingSlash(`${scheme}://${hostWithPort}`);
  }

  const host = req.headers.host;
  if (!host) return undefined;
  const isSecure = (req as any).secure === true || req.protocol === "https";
  const protocol = isSecure ? "https" : "http";
  return trimTrailingSlash(`${protocol}://${host}`);
};

const getGoogleProviderConfig = async (): Promise<GoogleAuthProvider | null> => {
  if (!storage.getAuthSettings) return null;
  try {
    const settings = await storage.getAuthSettings();
    const parsed = authSettingsSchema.parse(settings);
    const provider = parsed.providers.find((p): p is GoogleAuthProvider => p.id === "google");
    return provider ?? null;
  } catch (error) {
    console.error("[GoogleAuth] Failed to read auth settings:", error);
    return null;
  }
};

const buildGoogleCallbackUrl = (req: Request, provider?: GoogleAuthProvider | null) => {
  const configuredCallback = provider?.config?.callbackUrl;
  const parsedConfigured = safeParseUrl(configuredCallback);
  const callbackPath = extractCallbackPath(configuredCallback) || DEFAULT_CALLBACK_PATH;
  const configuredOrigin = getOriginFromUrl(configuredCallback);
  const dynamicBase = resolveExternalBaseUrl(req);
  const shouldOverrideHost = !parsedConfigured || isLocalHostname(parsedConfigured.hostname);

  const base = PUBLIC_BASE_URL
    || (shouldOverrideHost ? dynamicBase : undefined)
    || configuredOrigin
    || dynamicBase
    || DEFAULT_CALLBACK_ORIGIN
    || "http://localhost:5000";

  const sanitizedBase = trimTrailingSlash(base) || "http://localhost:5000";
  const normalizedPath = callbackPath.startsWith("/") ? callbackPath : ensureLeadingSlash(callbackPath);
  return `${sanitizedBase}${normalizedPath}`;
};

export function registerRoutes(app: express.Express) {
  // All route definitions from the file go here, in order, using the app parameter

  // Normalize all API date/timestamp fields to ISO 8601 before sending responses
  app.use((req, res, next) => {
    if (!req.path.startsWith("/api")) {
      return next();
    }
    const originalJson = res.json.bind(res);
    res.json = (body?: any) => originalJson(normalizeDateFields(body));
    next();
  });

  app.get("/api/health", (_req: Request, res: Response) => {
    res.json({ status: "ok" });
  });

  // ========== SKILL SUGGESTIONS (SHARED) ROUTES ==========
  app.get("/api/skills/suggestions", async (req: Request, res: Response) => {
    try {
      await ensureSkillSuggestionsSeeded();

      const parsed = skillSuggestionQuerySchema.parse({
        q: typeof req.query.q === "string" ? req.query.q : undefined,
        limit: typeof req.query.limit === "string" ? req.query.limit : undefined,
      });

      const q = parsed.q ? normalizeSkillSuggestionName(parsed.q).normalized : "";
      const limit = parsed.limit ?? 100;

      const db = await storage.getDb();
      const rows = (await db
        .select({
          name: skillSuggestionsTable.name,
          normalizedName: skillSuggestionsTable.normalizedName,
        })
        .from(skillSuggestionsTable)
        .orderBy(desc(skillSuggestionsTable.updatedAt))
        .limit(2000)) as Array<{ name: string; normalizedName: string }>;

      const filtered = (q ? rows.filter((r: { normalizedName: string }) => r.normalizedName.includes(q)) : rows)
        .map((r: { name: string }) => r.name)
        .filter(Boolean);

      if (!q) {
        return res.json(filtered.slice(0, limit));
      }

      const ranked = filtered
        .map((name: string) => {
          const n = normalizeSkillSuggestionName(name).normalized;
          return { name, score: n.startsWith(q) ? 0 : n.includes(q) ? 1 : 2 };
        })
        .filter((x: { score: number }) => x.score !== 2)
        .sort((a: { score: number; name: string }, b: { score: number; name: string }) => a.score - b.score || a.name.localeCompare(b.name))
        .slice(0, limit)
        .map((x: { name: string }) => x.name);

      return res.json(ranked);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(res, issue?.message || "Invalid query", issue?.path?.[0]?.toString());
      }
      return sendError(res, error);
    }
  });

  app.post("/api/skills/suggestions", authMiddleware, async (req: Request, res: Response) => {
    try {
      await ensureSkillSuggestionsSeeded();

      const payload = skillSuggestionCreateSchema.parse(req.body);
      const names = "name" in payload ? [payload.name] : payload.names;

      const db = await storage.getDb();

      const inserted: string[] = [];
      const skipped: string[] = [];

      for (const raw of names) {
        const { trimmed, normalized } = normalizeSkillSuggestionName(raw);
        if (!trimmed) continue;

        const existing = await db
          .select({ id: skillSuggestionsTable.id })
          .from(skillSuggestionsTable)
          .where(eq(skillSuggestionsTable.normalizedName, normalized))
          .limit(1)
          .then((r: any[]) => r[0]);

        if (existing) {
          skipped.push(trimmed);
          continue;
        }

        await db.insert(skillSuggestionsTable).values({
          name: trimmed,
          normalizedName: normalized,
          updatedAt: new Date(),
        } as any);

        inserted.push(trimmed);
      }

      return res.json({ inserted, skipped });
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(res, issue?.message || "Invalid payload", issue?.path?.[0]?.toString());
      }
      return sendError(res, error);
    }
  });

  // ========== GENERAL SETTINGS ROUTES ==========
  app.get("/api/settings/general/public", async (_req: Request, res: Response) => {
    try {
      if (!storage.getGeneralSettings) {
        return res.json(DEFAULT_GENERAL_SETTINGS);
      }
      const settings = await storage.getGeneralSettings();
      return res.json(generalSettingsSchema.parse(settings));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid general settings payload",
          issue?.path?.[0]?.toString()
        );
      }
      return sendError(res, error);
    }
  });

  app.get("/api/settings/general", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    try {
      if (!storage.getGeneralSettings) {
        return res.json(DEFAULT_GENERAL_SETTINGS);
      }
      const settings = await storage.getGeneralSettings();
      return res.json(generalSettingsSchema.parse(settings));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid general settings payload",
          issue?.path?.[0]?.toString()
        );
      }
      return sendError(res, error);
    }
  });

  app.put("/api/settings/general", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const payload = generalSettingsSchema.parse(req.body);
      if (!storage.updateGeneralSettings) {
        return res.status(501).json(
          createErrorResponse(
            ErrorCodes.NOT_IMPLEMENTED,
            "General settings persistence is not configured"
          )
        );
      }
      const saved = await storage.updateGeneralSettings(payload);
      return res.json(generalSettingsSchema.parse(saved));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid general settings payload",
          issue?.path?.[0]?.toString()
        );
      }
      return sendError(res, error);
    }
  });

  // ========== AUTH SETTINGS ROUTES ==========
  app.get("/api/settings/auth/public", async (_req: Request, res: Response) => {
    try {
      if (!storage.getAuthSettings) {
        return res.json({ providers: [] });
      }
      const settings = await storage.getAuthSettings();
      const parsed = authSettingsSchema.parse(settings);
      return res.json(sanitizeAuthSettingsForPublic(parsed));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid auth settings payload",
          issue?.path?.[0]?.toString()
        );
      }
      return sendError(res, error);
    }
  });

  app.get("/api/settings/auth", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    try {
      if (!storage.getAuthSettings) {
        const fallback = authSettingsSchema.parse({ providers: [] });
        return res.json(fallback);
      }
      const settings = await storage.getAuthSettings();
      return res.json(authSettingsSchema.parse(settings));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid auth settings payload",
          issue?.path?.[0]?.toString()
        );
      }
      return sendError(res, error);
    }
  });

  app.put("/api/settings/auth", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const payload = authSettingsSchema.parse(req.body);
      if (!storage.updateAuthSettings) {
        return res.status(501).json(
          createErrorResponse(
            ErrorCodes.NOT_IMPLEMENTED,
            "Auth settings persistence is not configured"
          )
        );
      }
      const saved = await storage.updateAuthSettings(payload);
      return res.json(authSettingsSchema.parse(saved));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const issue = error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid auth settings payload",
          issue?.path?.[0]?.toString()
        );
      }
      return sendError(res, error);
    }
  });

  // ========== GOOGLE OAUTH ROUTES ==========
  app.get("/auth/google", async (req: Request, res: Response, next: NextFunction) => {
    try {
      const provider = await getGoogleProviderConfig();
      if (!provider?.enabled) {
        return res.redirect(getRoleLoginRedirect(normalizeRole(req.query.role), "google-disabled"));
      }

      const role = normalizeRole(req.query.role);
      const redirectPath = sanitizeRedirectPath(req.query.redirect, OAUTH_DEFAULT_REDIRECT);
      const prompt = typeof req.query.prompt === "string" ? req.query.prompt : undefined;
      const stateToken = encodeStateToken({ role, redirect: redirectPath });
      const callbackURL = buildGoogleCallbackUrl(req, provider);

      const handler = passport.authenticate("google", {
        scope: ["profile", "email"],
        session: false,
        prompt,
        state: stateToken,
        callbackURL,
      } as any);
      handler(req, res, next);
    } catch (error) {
      console.error("[GoogleAuth] Failed to initiate OAuth:", error);
      res.redirect(getRoleLoginRedirect(normalizeRole(req.query.role), "google-auth-error"));
    }
  });

  app.get("/auth/google/callback", (req: Request, res: Response, next: NextFunction) => {
    const authCallback = passport.authenticate("google", { session: false }, async (err: unknown, profile: any) => {
      if (err || !profile) {
        console.error("[GoogleAuth] Strategy error:", err);
        return res.redirect(getRoleLoginRedirect(OAUTH_DEFAULT_ROLE, "google-auth-error"));
      }

      const state = decodeStateToken(typeof req.query.state === "string" ? req.query.state : undefined);
      const role = normalizeRole(state.role);
      const redirectPath = sanitizeRedirectPath(state.redirect, OAUTH_DEFAULT_REDIRECT);

      const email = (profile.email || profile.profile?.emails?.[0]?.value || "").trim().toLowerCase();
      const displayName = profile.name || profile.profile?.displayName || profile.profile?.name?.givenName;

      if (!email) {
        console.error("[GoogleAuth] Missing email in Google profile");
        return res.redirect(getRoleLoginRedirect(role, "missing-email"));
      }

      try {
        const db = await storage.getDb();

        if (role === "admin") {
          const admin = await db.query.adminsTable.findFirst({
            where: (table: typeof adminsTable) => eq(table.email, email),
          });
          if (!admin) {
            return res.redirect(getRoleLoginRedirect("admin", "no-admin-account"));
          }

          const token = generateToken({
            id: admin.id,
            email: admin.email,
            name: admin.name || admin.email,
            role: "admin",
          });

          return res.redirect(
            buildRedirectUrl(redirectPath, {
              token,
              email: admin.email,
              name: admin.name || admin.email,
              role: "admin",
            })
          );
        }

        if (role === "employer") {
          let employer = await db.query.employersTable.findFirst({
            where: (table: typeof employersTable) => eq(table.email, email),
          });

          if (!employer) {
            const derivedName = (() => {
              if (typeof displayName === "string" && displayName.trim()) {
                return displayName.trim();
              }
              const [localPart] = email.split("@");
              return localPart ? localPart.replace(/[^a-zA-Z0-9 ]/g, " ").trim() || "New Employer" : "New Employer";
            })();

            const profilePhoto =
              profile.photo ||
              profile.photos?.[0]?.value ||
              profile.profile?.photos?.[0]?.value ||
              profile.profile?.picture;

            const now = new Date();
            try {
              await db.insert(employersTable).values({
                establishmentName: derivedName,
                tradeName: derivedName,
                email,
                contactEmail: email,
                contactPerson: {
                  name: derivedName,
                  email,
                  profileImage: profilePhoto,
                },
                hasAccount: true,
                accountStatus: "pending",
                createdBy: "self",
                createdAt: now,
                updatedAt: now,
              });

              employer = await db.query.employersTable.findFirst({
                where: (table: typeof employersTable) => eq(table.email, email),
              });
            } catch (creationError) {
              console.error("[GoogleAuth] Failed to auto-create employer:", creationError);
              return res.redirect(getRoleLoginRedirect("employer", "employer-create-failed"));
            }
          }

          if (!employer) {
            return res.redirect(getRoleLoginRedirect("employer", "no-employer-account"));
          }

          const employerName = employer.establishmentName || employer.email || displayName || email;
          const token = generateToken({
            id: employer.id,
            email: employer.email || email,
            name: employerName,
            role: "employer",
          });

          return res.redirect(
            buildRedirectUrl(redirectPath, {
              token,
              email: employer.email || email,
              name: employerName,
              role: "employer",
              employerId: employer.id,
            })
          );
        }

        // Jobseeker / freelancer flow
        const targetRole: OAuthRole = role === "freelancer" ? "freelancer" : "jobseeker";
        const now = new Date();
         // Extract Google profile photo
         const profilePhoto =
           profile.photo ||
           profile.photos?.[0]?.value ||
           profile.profile?.photos?.[0]?.value ||
           profile.profile?.picture;
        let applicant = await db.query.usersTable.findFirst({
          where: (table: typeof usersTable) => eq(table.email, email),
        });

        if (!applicant) {
          let firstName = "Google";
          let surname = "User";
          if (typeof displayName === "string" && displayName.trim()) {
            const nameParts = displayName.trim().split(/\s+/).filter(Boolean);
            if (nameParts.length === 1) {
              firstName = nameParts[0];
              surname = "User";
            } else if (nameParts.length > 1) {
              firstName = nameParts[0];
              surname = nameParts.slice(1).join(" ");
            }
          } else if (email) {
            firstName = email.split("@")[0];
            surname = "User";
          }
          const passwordHash = await generateOAuthPasswordHash();

            await db.insert(usersTable).values({
              firstName,
              surname,
              email,
              role: targetRole,
              hasAccount: true,
              registrationDate: now,
              createdAt: now,
              updatedAt: now,
              profile_image: profilePhoto,
              passwordHash,
            });

          applicant = await db.query.usersTable.findFirst({
            where: (table: typeof usersTable) => eq(table.email, email),
          });
        } else {
          const updatePayload: Record<string, any> = {};

          if (!applicant.registrationDate) {
            // registrationDate is a timestamp column, use Date
            updatePayload.registrationDate = now;
          }

          if (profilePhoto) {
            updatePayload.profile_image = profilePhoto;
          }

          if (!applicant.passwordHash) {
            updatePayload.passwordHash = await generateOAuthPasswordHash();
          }

          if (Object.keys(updatePayload).length > 0) {
            updatePayload.updatedAt = now;
            await db
              .update(usersTable)
              .set(updatePayload)
              .where(eq(usersTable.id, applicant.id));

            applicant = await db.query.usersTable.findFirst({
              where: (table: typeof usersTable) => eq(table.email, email),
            });
          }
        }

        if (!applicant) {
          throw new Error("Failed to create applicant for Google user");
        }

        const applicantRole = (applicant.role as OAuthRole) || targetRole;
        const applicantName = [applicant.firstName, applicant.surname].filter(Boolean).join(" ") || email;
        const token = generateToken({
          id: applicant.id,
          email: applicant.email || email,
          name: applicantName,
          role: applicantRole,
        });

        return res.redirect(
          buildRedirectUrl(redirectPath, {
            token,
            email: applicant.email || email,
            name: applicantName,
            role: applicantRole,
            applicantId: applicant.id,
          })
        );
      } catch (callbackError) {
        console.error("[GoogleAuth] Callback processing error:", callbackError);
        return res.redirect(getRoleLoginRedirect(role, "google-auth-error"));
      }
    });

    authCallback(req, res, next);
  });

  // ========== MESSAGE ROUTES ========== 
  const enrichMessagesWithNames = async (db: any, msgs: any[]) => {
    if (!msgs.length) return [] as any[];

    const allIds = new Set<string>();
    msgs.forEach((msg) => {
      if (msg.senderId) allIds.add(msg.senderId);
      if (msg.receiverId) allIds.add(msg.receiverId);
    });

    const idsArray = Array.from(allIds);

    const employerNameMap = new Map<string, string>();
    const applicantNameMap = new Map<string, string>();

    if (idsArray.length > 0) {
      // Fetch employers that match any id
      const employerRows = await db
        .select({ id: employersTable.id, establishmentName: employersTable.establishmentName, name: employersTable.name })
        .from(employersTable)
        .where(inArray(employersTable.id, idsArray));

      employerRows.forEach((row: any) => {
        employerNameMap.set(row.id, row.establishmentName || row.name || "Employer");
      });

      // Fetch applicants that match any id
      const applicantRows = await db
        .select({
          id: usersTable.id,
          firstName: usersTable.firstName,
          surname: usersTable.surname,
          name: usersTable.name,
          email: usersTable.email,
        })
        .from(usersTable)
        .where(inArray(usersTable.id, idsArray));

      applicantRows.forEach((row: any) => {
        const fullName = [row.firstName, row.surname].filter(Boolean).join(" ").trim();
        applicantNameMap.set(row.id, fullName || row.name || row.email || "Applicant");
      });
    }

    const resolveName = (id?: string | null, role?: string | null) => {
      if (!id) return undefined;
      if (role === "employer" && employerNameMap.has(id)) return employerNameMap.get(id);
      if ((role === "jobseeker" || role === "freelancer") && applicantNameMap.has(id)) return applicantNameMap.get(id);
      // Fallback: if role missing, try employer then applicant
      return employerNameMap.get(id) || applicantNameMap.get(id);
    };

    return msgs.map((msg) => ({
      ...msg,
      senderName: resolveName(msg.senderId, msg.senderRole),
      receiverName: resolveName(msg.receiverId, msg.receiverRole),
    }));
  };

  // GET /api/messages - Get messages for current user (inbox/sent)
  app.get("/api/messages", authMiddleware, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const type = req.query.type || 'inbox'; // inbox | sent | all

      const db = await storage.getDb();
      const { messagesTable } = await import("./unified-schema");
      
      let messages: any[] = [];

      if (type === 'inbox') {
        messages = await db.select().from(messagesTable).where(eq(messagesTable.receiverId, userId));
      } else if (type === 'sent') {
        messages = await db.select().from(messagesTable).where(eq(messagesTable.senderId, userId));
      } else {
        // Get all messages (both sent and received)
        const received = await db.select().from(messagesTable).where(eq(messagesTable.receiverId, userId));
        const sent = await db.select().from(messagesTable).where(eq(messagesTable.senderId, userId));
        messages = [...received, ...sent];
      }

      // Sort by most recent first
      messages.sort((a, b) => {
        const timeA = a.createdAt instanceof Date ? a.createdAt.getTime() : new Date(a.createdAt).getTime();
        const timeB = b.createdAt instanceof Date ? b.createdAt.getTime() : new Date(b.createdAt).getTime();
        return timeB - timeA;
      });

      const enriched = await enrichMessagesWithNames(db, messages);

      const currentUserId = userId;
      const withPeer = enriched.map((msg) => {
        const peerId = msg.senderId === currentUserId ? msg.receiverId : msg.senderId;
        const peerName = msg.senderId === currentUserId ? msg.receiverName : msg.senderName;
        return { ...msg, peerId, peerName };
      });

      res.json(withPeer);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/messages/conversation/:userId - Get conversation with a specific user
  app.get("/api/messages/conversation/:userId", authMiddleware, async (req: Request, res: Response) => {
    try {
      const otherUserId = req.params.userId;

      const db = await storage.getDb();
      const { messagesTable } = await import("./unified-schema");

      // Get all messages between these two users
      const messages = await db.select().from(messagesTable).where(
        and(
          eq(messagesTable.senderId, (req.user as any)?.id),
          eq(messagesTable.receiverId, otherUserId)
        )
      );

      const messages2 = await db.select().from(messagesTable).where(
        and(
          eq(messagesTable.senderId, otherUserId),
          eq(messagesTable.receiverId, (req.user as any)?.id)
        )
      );

      const allMessages = [...messages, ...messages2];

      // Sort by oldest first (chronological order for conversations)
      allMessages.sort((a, b) => {
        const timeA = a.createdAt instanceof Date ? a.createdAt.getTime() : new Date(a.createdAt).getTime();
        const timeB = b.createdAt instanceof Date ? b.createdAt.getTime() : new Date(b.createdAt).getTime();
        return timeA - timeB;
      });

      const enriched = await enrichMessagesWithNames(db, allMessages);

      const currentUserId = (req.user as any)?.id;
      const withPeer = enriched.map((msg) => {
        const peerId = msg.senderId === currentUserId ? msg.receiverId : msg.senderId;
        const peerName = msg.senderId === currentUserId ? msg.receiverName : msg.senderName;
        return { ...msg, peerId, peerName };
      });

      res.json(withPeer);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/messages/conversation/:userId - Delete all messages between current user and another user
  app.delete("/api/messages/conversation/:userId", authMiddleware, async (req: Request, res: Response) => {
    try {
      const otherUserId = req.params.userId;
      const currentUserId = (req.user as any)?.id;

      if (!currentUserId) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const db = await storage.getDb();
      const { messagesTable } = await import("./unified-schema");

      await db.delete(messagesTable).where(
        or(
          and(eq(messagesTable.senderId, currentUserId), eq(messagesTable.receiverId, otherUserId)),
          and(eq(messagesTable.senderId, otherUserId), eq(messagesTable.receiverId, currentUserId))
        )
      );

      return res.json({ success: true });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/messages - Send a new message
  app.post("/api/messages", authMiddleware, async (req: Request, res: Response) => {
    try {
      const parsed = messageCreateSchema.safeParse(req.body || {});
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        return sendValidationError(res, issue?.message || "Invalid message payload", issue?.path?.[0] as string | undefined);
      }

      const senderId = (req.user as any)?.id;
      const senderRole = (req.user as any)?.role;
      const payload = parsed.data;

      const db = await storage.getDb();
      const { messagesTable } = await import("./unified-schema");

      const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date();

      const [newMessage] = await db.insert(messagesTable).values({
        id: messageId,
        senderId,
        senderRole,
        receiverId: payload.receiverId,
        receiverRole: payload.receiverRole || 'employer',
        subject: payload.subject || null,
        content: payload.content,
        isRead: false,
        createdAt: now,
        updatedAt: now,
      }).returning();

      // Notify recipient via WebSocket
      const { notifyNewMessage } = await import("./websocket");
      notifyNewMessage(payload.receiverId, newMessage);

      res.status(201).json(newMessage);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PATCH /api/messages/:id/read - Mark message as read
  app.patch("/api/messages/:id/read", authMiddleware, async (req: Request, res: Response) => {
    try {
      const messageId = req.params.id;
      const userId = (req.user as any)?.id;

      const db = await storage.getDb();
      const { messagesTable } = await import("./unified-schema");

      // Only allow receiver to mark as read
      const message = await db.select().from(messagesTable).where(eq(messagesTable.id, messageId));
      
      if (!message || message.length === 0) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Message not found"));
      }

      if (message[0].receiverId !== userId) {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Not authorized to mark this message as read"));
      }

      await db.update(messagesTable)
        .set({ isRead: true, updatedAt: new Date() })
        .where(eq(messagesTable.id, messageId));

      // Notify sender via WebSocket
      const { notifyMessageRead } = await import("./websocket");
      notifyMessageRead(message[0].senderId, messageId);

      res.json({ success: true, message: "Message marked as read" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/messages/unread/count - Get unread message count
  app.get("/api/messages/unread/count", authMiddleware, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;

      const db = await storage.getDb();
      const { messagesTable } = await import("./unified-schema");

      const unreadMessages = await db.select().from(messagesTable).where(
        and(
          eq(messagesTable.receiverId, userId),
          eq(messagesTable.isRead, false)
        )
      );

      res.json({ count: unreadMessages.length });
    } catch (error) {
      return sendError(res, error);
    }
  });


  // POST /api/auth/signup/jobseeker
  app.post("/api/auth/signup/jobseeker", async (req: Request, res: Response) => {
    try {
      // If Supabase is configured, use Supabase Auth for identity and keep DB as the profile store.
      if (isSupabaseConfigured()) {
        const payload = req.body || {};
        const rawName = typeof payload.name === "string" ? payload.name.trim() : "";
        const derivedFirst = payload.firstName?.trim() || rawName.split(" ")[0];
        const derivedLast = payload.lastName?.trim() || rawName.split(" ").slice(1).join(" ").trim();
        const { email, password } = payload;
        const userRole = payload.role || "jobseeker";

        if (!derivedFirst || !derivedLast || !email || !password) {
          return sendValidationError(res, "All fields are required");
        }

        const trimmedEmail = String(email).trim().toLowerCase();
        if (!validateEmail(trimmedEmail)) {
          return sendValidationError(res, "Invalid email format", "email");
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
          return res
            .status(400)
            .json(createErrorResponse(ErrorCodes.MISSING_FIELD, passwordValidation.errors.join("; "), "password"));
        }

        const supabase = createSupabaseAnonClient();

        const signUpResult = await supabase.auth.signUp({
          email: trimmedEmail,
          password,
          options: {
            data: {
              role: userRole,
              firstName: derivedFirst,
              lastName: derivedLast,
            },
          },
        });

        if (signUpResult.error) {
          return res
            .status(400)
            .json(createErrorResponse(ErrorCodes.INVALID_FORMAT, signUpResult.error.message));
        }

        // Immediately sign-in to obtain an access token.
        const signInResult = await supabase.auth.signInWithPassword({ email: trimmedEmail, password });
        if (signInResult.error || !signInResult.data.session) {
          return res
            .status(400)
            .json(createErrorResponse(
              ErrorCodes.INVALID_CREDENTIALS,
              signInResult.error?.message || "Unable to create session. If Supabase email confirmation is enabled, disable it for password signup flows."
            ));
        }

        const session = signInResult.data.session;
        const authUserId = session.user.id;
        const now = new Date();

        const db = await storage.getDb();
        const existing = await db
          .select({ id: usersTable.id, hasAccount: usersTable.hasAccount })
          .from(usersTable)
          .where(eq(usersTable.email, trimmedEmail))
          .limit(1)
          .then((rows: any[]) => rows[0]);

        // To keep IDs consistent with Supabase, we require the profile row to use the Supabase UUID.
        if (existing && existing.id !== authUserId) {
          return res.status(400).json(
            createErrorResponse(
              ErrorCodes.DUPLICATE_EMAIL,
              "Email already exists in local profiles with a different id. Clear/migrate your database before switching to Supabase Auth.",
              "email"
            )
          );
        }

        if (existing) {
          await db
            .update(usersTable)
            .set({
              firstName: derivedFirst,
              surname: derivedLast,
              email: trimmedEmail,
              role: userRole as any,
              hasAccount: true,
              updatedAt: now,
            })
            .where(eq(usersTable.id, existing.id));
        } else {
          await db.insert(usersTable).values({
            id: authUserId,
            firstName: derivedFirst,
            surname: derivedLast,
            email: trimmedEmail,
            passwordHash: "", // Supabase stores credentials; keep empty to avoid local password usage.
            role: userRole as any,
            hasAccount: true,
            registrationDate: now,
            createdAt: now,
            updatedAt: now,
          });
        }

        const fullName = `${derivedFirst} ${derivedLast}`.trim();
        return res.json({
          token: session.access_token,
          user: {
            id: authUserId,
            name: fullName,
            email: trimmedEmail,
            role: userRole,
          },
        });
      }

      const payload = req.body || {};
      const rawName = typeof payload.name === "string" ? payload.name.trim() : "";
      const derivedFirst = payload.firstName?.trim() || rawName.split(" ")[0];
      const derivedLast = payload.lastName?.trim() || rawName.split(" ").slice(1).join(" ").trim();
      const { email, password } = payload;
      const userRole = payload.role || "jobseeker";

      if (!derivedFirst || !derivedLast || !email || !password) {
        return sendValidationError(res, "All fields are required");
      }

      const trimmedEmail = email.trim();
      if (!validateEmail(trimmedEmail)) {
        return sendValidationError(res, "Invalid email format", "email");
      }

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        return res
          .status(400)
          .json(createErrorResponse(ErrorCodes.MISSING_FIELD, passwordValidation.errors.join("; "), "password"));
      }

      const db = await storage.getDb();
      const existingApplicant = await db
        .select({
          id: usersTable.id,
          hasAccount: usersTable.hasAccount,
          registrationDate: usersTable.registrationDate,
          createdAt: usersTable.createdAt,
          updatedAt: usersTable.updatedAt,
        })
        .from(usersTable)
        .where(eq(usersTable.email, trimmedEmail))
        .limit(1)
        .then((rows: any[]) => rows[0])
        .catch((err: any) => {
          console.error("Jobseeker signup lookup failed:", err);
          throw err;
        });
      if (existingApplicant?.hasAccount) {
        return res
          .status(400)
          .json(createErrorResponse(ErrorCodes.DUPLICATE_EMAIL, "Email already registered", "email"));
      }

      const hash = await hashPassword(password);
      const fullName = `${derivedFirst} ${derivedLast}`.trim();
      const now = new Date();
      let applicantId: string;
      const updates = {
        // Avoid touching a possibly missing legacy `name` column; use first/surname instead
        firstName: derivedFirst,
        surname: derivedLast,
        email: trimmedEmail,
        passwordHash: hash,
        role: userRole as "jobseeker" | "freelancer",
        hasAccount: true,
        registrationDate: now,
        updatedAt: now,
      };

      if (existingApplicant) {
        applicantId = existingApplicant.id;
        await db
          .update(usersTable)
          .set({
            ...updates,
            registrationDate: existingApplicant.registrationDate ?? now,
            createdAt: existingApplicant.createdAt || now,
          })
          .where(eq(usersTable.id, existingApplicant.id))
          .catch((err: any) => {
            console.error("Jobseeker signup update failed:", err);
            throw err;
          });
      } else {
        applicantId = `applicant_${Date.now()}`;
        const [created] = await db
          .insert(usersTable)
          .values({
            id: applicantId,
            firstName: derivedFirst,
            surname: derivedLast,
            email: trimmedEmail,
            passwordHash: hash,
            role: userRole as "jobseeker" | "freelancer",
            hasAccount: true,
            registrationDate: now,
            createdAt: now,
            updatedAt: now,
          })
          .returning({ id: usersTable.id })
          .catch((err: any) => {
            console.error("Jobseeker signup insert failed:", err);
            throw err;
          });
        applicantId = created?.id || applicantId;
      }

      const token = generateToken({
        id: applicantId,
        email: trimmedEmail,
        role: userRole as any,
        name: fullName,
      });

      res.json({
        token,
        user: {
          id: applicantId,
          name: fullName,
          email: trimmedEmail,
          role: userRole,
        },
      });
    } catch (error: any) {
      console.error("Jobseeker signup error:", error);
      return sendError(res, error);
    }
  });

  // POST /api/auth/signup/employer
  app.post("/api/auth/signup/employer", async (req: Request, res: Response) => {
    try {
      if (isSupabaseConfigured()) {
        const { name, email, password, company } = req.body;

        if (!name || !email || !password || !company) {
          return sendValidationError(res, "Name, email, password, and company are required");
        }

        const trimmedEmail = String(email).trim().toLowerCase();
        if (!validateEmail(trimmedEmail)) {
          return sendValidationError(res, "Invalid email format", "email");
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
          return sendValidationError(res, passwordValidation.errors.join("; "), "password");
        }

        const supabase = createSupabaseAnonClient();
        const signUpResult = await supabase.auth.signUp({
          email: trimmedEmail,
          password,
          options: {
            data: {
              role: "employer",
              name,
              company,
            },
          },
        });
        if (signUpResult.error) {
          return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, signUpResult.error.message));
        }

        const signInResult = await supabase.auth.signInWithPassword({ email: trimmedEmail, password });
        if (signInResult.error || !signInResult.data.session) {
          return res
            .status(400)
            .json(createErrorResponse(
              ErrorCodes.INVALID_CREDENTIALS,
              signInResult.error?.message || "Unable to create session. If Supabase email confirmation is enabled, disable it for password signup flows."
            ));
        }

        const session = signInResult.data.session;
        const authUserId = session.user.id;
        const now = new Date();

        const db = await storage.getDb();
        const existing = await db
          .select({ id: employersTable.id })
          .from(employersTable)
          .where(sql`lower(${employersTable.email}) = ${trimmedEmail}`)
          .limit(1)
          .then((rows: any[]) => rows[0]);
        if (existing && existing.id !== authUserId) {
          return res.status(400).json(
            createErrorResponse(
              ErrorCodes.DUPLICATE_EMAIL,
              "Email already exists in local employer profiles with a different id. Clear/migrate your database before switching to Supabase Auth.",
              "email"
            )
          );
        }

        if (existing) {
          await db
            .update(employersTable)
            .set({
              establishmentName: company,
              name,
              email: trimmedEmail,
              hasAccount: true,
              accountStatus: "pending",
              updatedAt: now,
            })
            .where(eq(employersTable.id, existing.id));
        } else {
          await db.insert(employersTable).values({
            id: authUserId,
            establishmentName: company,
            name,
            email: trimmedEmail,
            passwordHash: "",
            hasAccount: true,
            accountStatus: "pending",
            createdBy: "self",
            createdAt: now,
            updatedAt: now,
          });
        }

        return res.json({
          token: session.access_token,
          user: {
            id: authUserId,
            name,
            email: trimmedEmail,
            role: "employer",
          },
        });
      }

      const { name, email, password, company } = req.body;

      if (!name || !email || !password || !company) {
        return sendValidationError(res, "Name, email, password, and company are required");
      }

      // Normalize email to lowercase to avoid case-sensitive login/duplicate issues
      const trimmedEmail = typeof email === "string" ? email.trim() : "";
      const normalizedEmail = trimmedEmail.toLowerCase();

      if (!validateEmail(normalizedEmail)) {
        return sendValidationError(res, "Invalid email format", "email");
      }

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        return sendValidationError(res, passwordValidation.errors.join("; "), "password");
      }

      // Check if email already exists
      const db = await storage.getDb();
      const existingEmployer = await db.query.employersTable.findFirst({
        where: (table: any) => sql`lower(${table.email}) = ${normalizedEmail}`,
      });

      if (existingEmployer) {
        return res.status(400).json(createErrorResponse(ErrorCodes.DUPLICATE_EMAIL, "Email already registered", "email"));
      }

      const hash = await hashPassword(password);
      
      // Create employer account directly in employers table
      const employerId = `EMP-${Date.now()}`;
      
      await db.insert(employersTable).values({
        id: employerId,
        establishmentName: company,
        email: normalizedEmail,
        passwordHash: hash,
        hasAccount: true,
        accountStatus: "pending",
        createdBy: "self",
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const token = generateToken({
        id: employerId,
        email: normalizedEmail,
        role: "employer",
        name: name,
      });

      res.json({
        token,
        user: {
          id: employerId,
          name: name,
          email: normalizedEmail,
          role: "employer",
        },
      });
    } catch (error: any) {
      console.error("Employer signup error:", error);
      return sendError(res, error);
    }
  });

  // POST /api/auth/signup/admin (controlled - for setup only)
  app.post("/api/auth/signup/admin", async (req: Request, res: Response) => {
    try {
      if (isSupabaseConfigured()) {
        const payload = adminCreateSchema.parse(req.body);

        if (!validateEmail(payload.email)) {
          return sendValidationError(res, "Invalid email format", "email");
        }

        const passwordValidation = validatePassword(payload.password);
        if (!passwordValidation.isValid) {
          return sendValidationError(res, passwordValidation.errors.join("; "), "password");
        }

        const normalizedEmail = payload.email.trim().toLowerCase();
        const supabase = createSupabaseAnonClient();

        const signUpResult = await supabase.auth.signUp({
          email: normalizedEmail,
          password: payload.password,
          options: {
            data: {
              role: "admin",
              name: payload.name,
            },
          },
        });
        if (signUpResult.error) {
          return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, signUpResult.error.message));
        }

        const signInResult = await supabase.auth.signInWithPassword({ email: normalizedEmail, password: payload.password });
        if (signInResult.error || !signInResult.data.session) {
          return res
            .status(400)
            .json(createErrorResponse(
              ErrorCodes.INVALID_CREDENTIALS,
              signInResult.error?.message || "Unable to create session. If Supabase email confirmation is enabled, disable it for password signup flows."
            ));
        }

        const session = signInResult.data.session;
        const authUserId = session.user.id;
        const now = new Date();

        const db = await storage.getDb();
        const existing = await db
          .select({ id: adminsTable.id, email: adminsTable.email })
          .from(adminsTable)
          .where(eq(adminsTable.email, normalizedEmail))
          .limit(1)
          .then((rows: any[]) => rows[0]);
        if (existing && existing.id !== authUserId) {
          return res.status(400).json(
            createErrorResponse(
              ErrorCodes.DUPLICATE_EMAIL,
              "Email already exists in local admin profiles with a different id. Clear/migrate your database before switching to Supabase Auth.",
              "email"
            )
          );
        }

        if (existing) {
          await db
            .update(adminsTable)
            .set({ name: payload.name, email: normalizedEmail, updatedAt: now })
            .where(eq(adminsTable.id, existing.id));
        } else {
          await db.insert(adminsTable).values({
            id: authUserId,
            name: payload.name,
            email: normalizedEmail,
            passwordHash: "",
            role: "admin",
            createdAt: now,
            updatedAt: now,
          });
        }

        return res.json({
          token: session.access_token,
          user: {
            id: authUserId,
            name: payload.name,
            email: normalizedEmail,
            role: "admin",
          },
        });
      }

      const payload = adminCreateSchema.parse(req.body);

      if (!validateEmail(payload.email)) {
        return sendValidationError(res, "Invalid email format", "email");
      }

      const passwordValidation = validatePassword(payload.password);
      if (!passwordValidation.isValid) {
        return sendValidationError(
          res,
          passwordValidation.errors.join("; "),
          "password"
        );
      }

      const hash = await hashPassword(payload.password);
      const created = await storage.addAdmin({
        name: payload.name,
        email: payload.email,
        passwordHash: hash,
        role: payload.role ?? "admin",
      });

      const token = generateToken({
        id: created.id,
        email: created.email,
        role: "admin",
        name: created.name,
      });

      res.json({
        token,
        user: {
          id: created.id,
          name: created.name,
          email: created.email,
          role: "admin",
        },
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/auth/login - Universal login endpoint
  app.post("/api/auth/login", async (req: Request, res: Response) => {
    try {
      if (isSupabaseConfigured()) {
        const payload = loginSchema.parse(req.body);

        if (!payload.email || !payload.password) {
          return sendValidationError(res, "Email and password are required", "email");
        }

        const email = payload.email.trim().toLowerCase();
        const supabase = createSupabaseAnonClient();
        const signInResult = await supabase.auth.signInWithPassword({
          email,
          password: payload.password,
        });

        if (signInResult.error || !signInResult.data.session) {
          return res
            .status(401)
            .json(createErrorResponse(ErrorCodes.INVALID_CREDENTIALS, "Invalid email or password"));
        }

        const session = signInResult.data.session;
        const authUserId = session.user.id;

        // Resolve the profile from our tables so the app keeps the same role routing.
        const db = await storage.getDb();

        const admin = await db
          .select({ id: adminsTable.id, email: adminsTable.email, name: adminsTable.name })
          .from(adminsTable)
          .where(eq(adminsTable.id, authUserId))
          .limit(1)
          .then((rows: any[]) => rows[0]);
        if (admin) {
          return res.json({
            token: session.access_token,
            user: { id: admin.id, name: admin.name, email: admin.email, role: "admin" },
          });
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
          return res.json({
            token: session.access_token,
            user: {
              id: employer.id,
              name: employer.name || employer.establishmentName || "Employer",
              email: employer.email,
              role: "employer",
            },
          });
        }

        const user = await db
          .select({ id: usersTable.id, email: usersTable.email, firstName: usersTable.firstName, surname: usersTable.surname, role: usersTable.role })
          .from(usersTable)
          .where(eq(usersTable.id, authUserId))
          .limit(1)
          .then((rows: any[]) => rows[0]);
        if (user) {
          const fullName = `${user.firstName || ""} ${user.surname || ""}`.trim() || user.email;
          return res.json({
            token: session.access_token,
            user: {
              id: user.id,
              name: fullName,
              email: user.email,
              role: (user.role as any) || "jobseeker",
            },
          });
        }

        return res
          .status(401)
          .json(createErrorResponse(ErrorCodes.UNAUTHORIZED, "User profile not found. Please sign up again."));
      }

      const payload = loginSchema.parse(req.body);

      if (!payload.email || !payload.password) {
        return sendValidationError(
          res,
          "Email and password are required",
          "email"
        );
      }

      // Initialize database connection
      await initStorageWithDatabase();


      // Try jobseeker login first
      const jobseeker = await getJobseekerByEmailWithPassword(payload.email);
      if (jobseeker && jobseeker.passwordHash) {
        const isValid = await verifyPassword(
          payload.password,
          jobseeker.passwordHash
        );
        if (isValid) {
          const token = generateToken({
            id: jobseeker.id,
            email: jobseeker.email,
            role: jobseeker.role,
            name: jobseeker.name,
          });
          return res.json({
            token,
            user: {
              id: jobseeker.id,
              name: jobseeker.name,
              email: jobseeker.email,
              role: jobseeker.role,
            },
          });
        }
      }

      // Try employer login
      const employer = await getEmployerByEmailWithPassword(payload.email);
      if (employer && employer.passwordHash) {
        const isValid = await verifyPassword(
          payload.password,
          employer.passwordHash
        );
        if (isValid) {
          const token = generateToken({
            id: employer.id,
            email: employer.email,
            role: "employer",
            name: employer.name,
          });
          return res.json({
            token,
            user: {
              id: employer.id,
              name: employer.name,
              email: employer.email,
              role: "employer",
            },
          });
        }
      }

      // Try admin login
      const admin = await getAdminByEmailWithPassword(payload.email) as {
        id: string;
        email: string;
        password_hash?: string;
        passwordHash?: string;
        role: string;
        name: string;
      } | null;
      const adminPassword = admin?.password_hash || admin?.passwordHash;
      if (admin && adminPassword !== undefined) {
        const isValid = await bcrypt.compare(payload.password, adminPassword);
        if (isValid) {
          const token = generateToken({
            id: admin.id,
            email: admin.email,
            role: "admin",
            name: admin.name,
          });
          return res.json({
            token,
            user: {
              id: admin.id,
              name: admin.name,
              email: admin.email,
              role: "admin",
            },
          });
        }
      }
      return res.status(401).json(createErrorResponse(ErrorCodes.INVALID_CREDENTIALS, "Invalid email or password"));
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/auth/me - Get current user info (requires token)
  app.get("/api/auth/me", authMiddleware, async (req: any, res: Response) => {
    try {
      res.json({
        user: {
          id: req.user.id,
          email: req.user.email,
          name: req.user.name,
          role: req.user.role,
        },
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/auth/logout
  app.post("/api/auth/logout", (_req: Request, res: Response) => {
    res.json({ message: "Logged out successfully" });
  });

  // POST /api/admin/create-admin-user - issue credentials or refresh an approved admin request
  app.post(
    "/api/admin/create-admin-user",
    authMiddleware,
    adminOnly,
    async (req: Request, res: Response) => {
      try {
        const normalizedEmail =
          typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
        const normalizedName =
          typeof req.body.name === "string" && req.body.name.trim().length > 0
            ? req.body.name.trim()
            : normalizedEmail;
        const normalizedRole = typeof req.body.role === "string" ? req.body.role : undefined;

        const parsedPayload = adminCreateSchema.safeParse({
          name: normalizedName,
          email: normalizedEmail,
          password: req.body.password,
          role: normalizedRole,
        });

        if (!parsedPayload.success) {
          const firstIssue = parsedPayload.error.issues[0];
          return sendValidationError(
            res,
            firstIssue?.message || "Invalid admin payload",
            (firstIssue?.path?.[0] as string | undefined) ?? undefined
          );
        }

        if (!validateEmail(parsedPayload.data.email)) {
          return sendValidationError(res, "Invalid email format", "email");
        }

        const passwordValidation = validatePassword(parsedPayload.data.password);
        if (!passwordValidation.isValid) {
          return sendValidationError(
            res,
            passwordValidation.errors.join("; "),
            "password"
          );
        }

        const db = await storage.getDb();
        const allAdmins = await db.select().from(adminsTable);
        const normalizedInputEmail = parsedPayload.data.email.trim().toLowerCase();
        console.log('[ADMIN UPDATE DEBUG] Input email:', parsedPayload.data.email);
        console.log('[ADMIN UPDATE DEBUG] Normalized input:', normalizedInputEmail);
        console.log('[ADMIN UPDATE DEBUG] All admin emails in DB:', allAdmins.map((a: any) => a.email));
        let matchedAdmin = null;
        for (const admin of allAdmins) {
          const dbEmail = typeof admin?.email === "string" ? admin.email.trim().toLowerCase() : "";
          console.log('[ADMIN UPDATE DEBUG] Comparing:', dbEmail, 'vs', normalizedInputEmail);
          if (dbEmail === normalizedInputEmail) {
            matchedAdmin = admin;
            console.log('[ADMIN UPDATE DEBUG] Found match:', admin);
            break;
          }
        }
        const existingAdmin = matchedAdmin;

        const passwordHash = await hashPassword(parsedPayload.data.password);
        const requestId = typeof req.body.requestId === "string" ? req.body.requestId : undefined;
        const now = new Date();
        const desiredRole = parsedPayload.data.role ?? existingAdmin?.role ?? "admin";

        if (existingAdmin) {
          const [updated] = await db
            .update(adminsTable)
            .set({ passwordHash, role: desiredRole, updatedAt: now })
            .where(eq(adminsTable.id, existingAdmin.id))
            .returning();

          if (requestId) {
            await db
              .update(adminAccessRequestsTable)
              .set({ updatedAt: now })
              .where(eq(adminAccessRequestsTable.id, requestId));
          }

          return res.json({
            message: "Admin credentials updated successfully",
            admin: {
              id: updated?.id ?? existingAdmin.id,
              name: updated?.name ?? existingAdmin.name,
              email: updated?.email ?? existingAdmin.email,
              role: updated?.role ?? desiredRole,
              createdAt: (updated?.createdAt || existingAdmin.createdAt)?.toISOString?.() || existingAdmin.createdAt,
              updatedAt: now.toISOString(),
            },
            action: "updated",
          });
        } else {
          const createdAdmin = await storage.addAdmin({
            name: parsedPayload.data.name,
            email: parsedPayload.data.email,
            passwordHash,
            role: desiredRole,
          });

          if (requestId) {
            await db
              .update(adminAccessRequestsTable)
              .set({ updatedAt: now })
              .where(eq(adminAccessRequestsTable.id, requestId));
          }

          return res.status(201).json({
            message: "Admin user created successfully",
            admin: createdAdmin,
            action: "created",
          });
        }
      } catch (error: any) {
        const dbErrorCode = error?.code;
        if (dbErrorCode === "SQLITE_CONSTRAINT" || dbErrorCode === "23505") {
          return res
            .status(409)
            .json(
              createErrorResponse(
                ErrorCodes.DUPLICATE_EMAIL,
                "Admin user with this email already exists",
                "email"
              )
            );
        }
        return sendError(res, error);
      }
    }
  );

  // ============ ADMIN ROUTES ============
  // GET /api/admin/stats
  app.get("/api/admin/stats", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const jobseekers = await db.select().from(usersTable).where(
        and(eq(usersTable.hasAccount, true), eq(usersTable.role, "jobseeker"))
      );
      const employers = await db.select().from(employersTable).where(eq(employersTable.hasAccount, true));
      const jobs = await db.query.jobsTable.findMany();
      const applications = await db.query.applicationsTable.findMany();
      // FIX: Exclude archived jobs from count
      const activeJobs = jobs.filter((j: any) => !j.archived);
      res.json({
        totalJobseekers: jobseekers.length,
        totalEmployers: employers.length,
        totalJobs: activeJobs.length,
        totalApplications: applications.length,
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/admin/users
  app.get("/api/admin/users", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const role = req.query.role as string | undefined;
      const db = await storage.getDb();
      const jobseekers = await db.select().from(usersTable).where(
        and(eq(usersTable.hasAccount, true), eq(usersTable.role, "jobseeker"))
      );
      const employers = await db.select().from(employersTable).where(eq(employersTable.hasAccount, true));

      let users: any[] = [];
      if (!role || role === "jobseeker") {
        users = users.concat(
          jobseekers.map((j: any) => ({
            ...j,
            type: "jobseeker",
          }))
        );
      }
      if (!role || role === "employer") {
        users = users.concat(
          employers.map((e: any) => ({
            ...e,
            type: "employer",
          }))
        );
      }

      res.json(users);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PUT /api/admin/users/:id
  app.put("/api/admin/users/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      // Implementation for updating user by admin
      res.json({ message: "User updated" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/admin/users/:id
  app.delete("/api/admin/users/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      // Implementation for deleting user by admin
      res.json({ message: "User deleted" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/admin/jobs
  app.get("/api/admin/jobs", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const jobs = await db.select().from(jobsTable);
      const normalizedJobs = (jobs || [])
        .map((job: any) => ({
          ...serializeJob(job),
          archived: Boolean(job.archived),
          type: "job",
        }))
        .map(mapJobToTableShape);
      const sorted = normalizedJobs.sort((a: any, b: any) => {
        const dateA = new Date(a.createdAt).getTime();
        const dateB = new Date(b.createdAt).getTime();
        return dateB - dateA;
      });

      res.json(sorted);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/admin/jobs/:id
  app.get("/api/admin/jobs/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.id;
      const db = await storage.getDb();
      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!job) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found"));
      }

      const normalized = mapJobToTableShape({
        ...serializeJob(job),
        archived: Boolean((job as any).archived),
        type: "job",
      });

      res.json(normalized);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/admin/jobs - allow admins to create jobs on behalf of employers
  app.post("/api/admin/jobs", authMiddleware, adminOnly, async (req: any, res: Response) => {
    try {
      const db = await storage.getDb();

      const payload = jobCreateSchema.parse({
        ...req.body,
        employerId: req.body.employerId,
        status: req.body.status ?? "active",
      });

      if (!payload.employerId) {
        return sendValidationError(res, "employerId is required", "employerId");
      }

      const employer = await db.query.employersTable.findFirst({
        where: (table: typeof employersTable) => eq(table.id, payload.employerId),
      });

      if (!employer) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }

      const establishmentLabel =
        req.body.establishmentName ||
        employer.establishmentName ||
        employer.companyName ||
        employer.contactPerson ||
        employer.name ||
        "";

      const locationParts = [
        payload.barangay ?? employer.barangay,
        payload.municipality ?? employer.municipality,
        payload.province ?? employer.province,
      ].filter(Boolean) as string[];
      const normalizedLocation = payload.location?.trim()
        ? payload.location
        : locationParts.join(", ");

      const derivedPreparedByName = payload.preparedByName ?? employer.preparedByName ?? null;
      const derivedPreparedByDesignation = payload.preparedByDesignation ?? employer.preparedByDesignation ?? null;
      const derivedPreparedByContact = payload.preparedByContact ?? employer.preparedByContact ?? null;
      const derivedDateAccomplished = payload.dateAccomplished ?? employer.dateAccomplished ?? null;
      const derivedIndustryCodes = payload.industryCodes ?? (employer.industryCodes as string[] | undefined) ?? [];
      const derivedVacantPositions = payload.vacantPositions ?? employer.numberOfVacantPositions ?? null;
      const derivedPaidEmployees = payload.paidEmployees ?? employer.numberOfPaidEmployees ?? null;
      const derivedSkills = payload.skills ?? null;

      const now = new Date();
      const [created] = await db
        .insert(jobsTable)
        .values({
          employerId: payload.employerId,
          establishmentName: establishmentLabel,
          positionTitle: payload.positionTitle,
          description: payload.description,
          location: normalizedLocation,
          salaryMin: payload.salaryMin,
          salaryMax: payload.salaryMax,
          salaryPeriod: payload.salaryPeriod,
          salaryAmount: payload.salaryAmount,
          salaryType: payload.salaryType,
          startingSalaryOrWage: payload.salaryAmount ?? payload.salaryMin ?? payload.salaryMax ?? null,
          jobStatus: payload.jobStatus,
          minimumEducationRequired: payload.minimumEducation,
          yearsOfExperienceRequired: payload.yearsOfExperience,
          agePreference: payload.agePreference,
          industryCodes: derivedIndustryCodes,
          vacantPositions: derivedVacantPositions,
          paidEmployees: derivedPaidEmployees,
          mainSkillOrSpecialization: derivedSkills,
          skills: derivedSkills,
          preparedByName: derivedPreparedByName,
          preparedByDesignation: derivedPreparedByDesignation,
          preparedByContact: derivedPreparedByContact,
          dateAccomplished: derivedDateAccomplished,
          barangay: payload.barangay ?? employer.barangay,
          municipality: payload.municipality ?? employer.municipality,
          province: payload.province ?? employer.province,
          status: payload.status ?? "active",
          archived: false,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      return res.status(201).json({
        message: payload.status === "active" ? "Job published" : "Job saved",
        job: formatJobTimestamps(created),
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PUT /api/admin/jobs/:id
  app.put("/api/admin/jobs/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.id;
      const parsed = adminJobUpdateSchema.safeParse(req.body || {});
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        return sendValidationError(res, issue?.message || "Invalid job payload", issue?.path?.[0] as string | undefined);
      }

      const db = await storage.getDb();
      const [existing] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!existing) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found"));
      }

      const updates: Record<string, unknown> = {};
      const add = (key: string, value: unknown) => {
        if (value !== undefined) updates[key] = value;
      };

      // Direct column matches
      add("positionTitle", (parsed.data as any).positionTitle);
      add("description", (parsed.data as any).description);
      add("location", (parsed.data as any).location);
      add("barangay", (parsed.data as any).barangay);
      add("municipality", (parsed.data as any).municipality);
      add("province", (parsed.data as any).province);
      add("salaryMin", (parsed.data as any).salaryMin);
      add("salaryMax", (parsed.data as any).salaryMax);
      add("salaryAmount", (parsed.data as any).salaryAmount);
      add("salaryPeriod", (parsed.data as any).salaryPeriod);
      add("salaryType", (parsed.data as any).salaryType);
      add("jobStatus", (parsed.data as any).jobStatus);
      add("agePreference", (parsed.data as any).agePreference);
      add("industryCodes", (parsed.data as any).industryCodes);
      add("vacantPositions", (parsed.data as any).vacantPositions);
      add("paidEmployees", (parsed.data as any).paidEmployees);
      add("preparedByName", (parsed.data as any).preparedByName);
      add("preparedByDesignation", (parsed.data as any).preparedByDesignation);
      add("preparedByContact", (parsed.data as any).preparedByContact);
      add("dateAccomplished", (parsed.data as any).dateAccomplished);

      // Map schema fields -> column names
      add("minimumEducationRequired", (parsed.data as any).minimumEducation);
      add("yearsOfExperienceRequired", (parsed.data as any).yearsOfExperience);

      // Skills: keep both columns consistent
      if ((parsed.data as any).skills !== undefined) {
        add("skills", (parsed.data as any).skills);
        add("mainSkillOrSpecialization", (parsed.data as any).skills);
      }

      // Admin-only fields
      add("status", (parsed.data as any).status);
      add("archived", (parsed.data as any).archived);
      add("archivedAt", (parsed.data as any).archivedAt);

      const salaryForLegacy =
        (parsed.data as any).salaryAmount ?? (parsed.data as any).salaryMin ?? (parsed.data as any).salaryMax;
      if (salaryForLegacy !== undefined) {
        add("startingSalaryOrWage", salaryForLegacy);
      }

      if (Object.keys(updates).length === 0) {
        return sendValidationError(res, "No changes supplied");
      }

      updates.updatedAt = new Date();

      await db.update(jobsTable).set(updates as any).where(eq(jobsTable.id, jobId));
      const [updated] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));

      res.json({ message: "Job updated", job: formatJobTimestamps(updated) });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/admin/jobs/:id
  app.delete("/api/admin/jobs/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.id;
      const db = await storage.getDb();
      
      // Check if job exists
      const existing = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!existing || existing.length === 0) {
        return res.status(404).json({ error: "Job not found" });
      }
      
      // Delete the job permanently
      await db.delete(jobsTable).where(eq(jobsTable.id, jobId));
      
      res.json({ message: "Job deleted successfully" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PATCH /api/admin/jobs/:id/status - Admin approves or updates job status
  app.patch(
    "/api/admin/jobs/:id/status",
    authMiddleware,
    adminOnly,
    async (req: Request, res: Response) => {
      try {
        const jobId = req.params.id;
        const requestedStatus = String(req.body?.status || "").toLowerCase();

        if (!requestedStatus) {
          return sendValidationError(res, "Status is required", "status");
        }

        if (!allowedJobStatuses.has(requestedStatus)) {
          return sendValidationError(res, "Invalid job status", "status");
        }

        const db = await storage.getDb();
        const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
        if (!job) {
          return res.status(404).json(
            createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found")
          );
        }

        const now = new Date();
        try {
          await db
            .update(jobsTable)
            .set({
              status: requestedStatus,
              jobStatus: requestedStatus,
              updatedAt: now,
            })
            .where(eq(jobsTable.id, jobId));
        } catch (err: any) {
          console.error("[PATCH /api/admin/jobs/:id/status] update error", err);
          if (err instanceof Error && err.message.includes("getTime")) {
            const fallback = new Date();
            await db
              .update(jobsTable)
              .set({ status: requestedStatus, jobStatus: requestedStatus, updatedAt: fallback })
              .where(eq(jobsTable.id, jobId));
          } else {
            throw err;
          }
        }

        const [updatedJob] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));

        // Send notification to employer if job is approved
        if (requestedStatus === "active" && job.employerId) {
          // Try to get employer email or userId; do not fail the request if notification insert fails
          try {
            const [employer] = await db.select().from(employersTable).where(eq(employersTable.id, job.employerId));
            if (employer) {
              const notif = {
                id: `notif_${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
                userId: employer.id,
                role: 'employer',
                type: 'job',
                message: `Your job post "${job.positionTitle || job.title || 'Job'}" has been approved and is now visible to jobseekers!`,
                read: false,
                createdAt: now,
                updatedAt: now,
              };
              await db.insert(notificationsTable).values(notif as any);
            }
          } catch (notifyErr) {
            console.warn("[PATCH /api/admin/jobs/:id/status] notification insert skipped", notifyErr);
          }
        }

        const message = requestedStatus === "active"
          ? "Job approved and published"
          : "Job status updated";

        return res.json({
          message,
          job: formatJobTimestamps(updatedJob),
        });
      } catch (error) {
        return sendError(res, error);
      }
    }
  );


  // GET /api/admin/access-requests - Fetch all or filtered admin access requests
  app.get(
    "/api/admin/access-requests",
    authMiddleware,
    adminOnly,
    async (req: Request, res: Response) => {
      try {
        const status = req.query.status as string | undefined;
        let requests = await (storage as any).getAdminAccessRequests?.();
        if (status) {
          requests = (requests || []).filter((r: any) => r.status === status);
        }
        res.json(requests || []);
      } catch (error) {
        return sendError(res, error);
      }
    }
  );

  // POST /api/admin/access-requests - Submit a new admin access request
  app.post(
    "/api/admin/access-requests",
    async (req: Request, res: Response) => {
      try {
        // Validate input
        const payload = adminAccessRequestSchema.omit({ id: true, status: true, createdAt: true }).parse(req.body);
        const created = await (storage as any).addAdminAccessRequest?.(payload);
        return res.status(201).json(created);
      } catch (error) {
        // Always return standardized error
        if (error instanceof Error) {
          return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, error.message));
        }
        return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, "Unknown error"));
      }
    }
  );

  // POST /api/admin/access-requests/:id/approve - Approve an admin access request and create admin if needed
  app.post(
    "/api/admin/access-requests/:id/approve",
    authMiddleware,
    adminOnly,
    async (req: Request, res: Response) => {
      try {
        const { id } = req.params;
        const updated = await (storage as any).updateAdminAccessRequest?.(id, { status: "approved" });
        if (!updated) return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Request not found"));

        // Create admin account if not exists
        const db = await (storage as any).getDb();
        const { email, name } = updated;
        const existing = await db.select().from(adminsTable).where(eq(adminsTable.email, email));
        let temporaryPassword: string | undefined;
        if (!existing || existing.length === 0) {
          temporaryPassword = Math.random().toString(36).slice(-8) + "A1!";
          const passwordHash = await bcrypt.hash(temporaryPassword, 10);
          await db.insert(adminsTable).values({
            id: `admin_${Date.now()}`,
            name: name || email,
            email,
            passwordHash,
            role: "admin",
            createdAt: new Date(),
            updatedAt: new Date(),
          });
        }

        res.json({ ...updated, temporaryPassword });
      } catch (error) {
        // Enhanced error logging for debugging
        console.error('[Admin Approval Error]', error);
        if (error && typeof error === 'object' && 'message' in error) {
          return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, (error as any).message));
        }
        return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, JSON.stringify(error)));
      }
    }
  );

  // POST /api/admin/access-requests/:id/reject - Reject an admin access request
  app.post(
    "/api/admin/access-requests/:id/reject",
    authMiddleware,
    adminOnly,
    async (req: Request, res: Response) => {
      try {
        const { id } = req.params;
        const updated = await (storage as any).updateAdminAccessRequest?.(id, { status: "rejected" });
        if (!updated) return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Request not found"));
        res.json(updated);
      } catch (error) {
        return res.status(400).json({ error: error instanceof Error ? error.message : "Unknown error" });
      }
    }
  );

  // GET /api/admin/applications
  app.get(
    "/api/admin/applications",
    authMiddleware,
    adminOnly,
    async (_req: Request, res: Response) => {
      try {
        const db = await storage.getDb();
        const applications = await db.query.applicationsTable.findMany();
        res.json(applications);
      } catch (error) {
        return sendError(res, error);
      }
    }
  );

  // GET /api/reports/skills � returns top 20 skills and expected skills shortage
  app.get("/api/reports/skills", async (req: Request, res: Response) => {
    try {
      if (!storage.getSkillsReport) {
        return res.json({ topSkills: [], expectedSkillsShortage: [] });
      }

      const normalizeDateParam = (value: unknown) => {
        if (typeof value !== "string") return undefined;
        return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : undefined;
      };

      const startDate = normalizeDateParam(req.query.startDate);
      const endDate = normalizeDateParam(req.query.endDate);

      const data = await storage.getSkillsReport(startDate, endDate);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch skills report" });
    }
  });

  // GET /api/job-vacancies - List job vacancies with filters and pagination
  app.get("/api/job-vacancies", async (req: Request, res: Response) => {
    try {
      const parseNumber = (value: unknown) => {
        if (typeof value === "string" && value.trim() !== "") {
          const parsed = Number(value);
          return Number.isFinite(parsed) ? parsed : undefined;
        }
        return typeof value === "number" && Number.isFinite(value) ? value : undefined;
      };

      const rawFilters = {
        search: typeof req.query.search === "string" ? req.query.search : undefined,
        minSalary: parseNumber(req.query.minSalary),
        maxSalary: parseNumber(req.query.maxSalary),
        educationLevel: typeof req.query.educationLevel === "string" ? req.query.educationLevel : undefined,
        minExperience: parseNumber(req.query.minExperience),
        maxExperience: parseNumber(req.query.maxExperience),
        industry: typeof req.query.industry === "string" ? req.query.industry : undefined,
        jobStatus: typeof req.query.jobStatus === "string" ? req.query.jobStatus : undefined,
        salaryType: typeof req.query.salaryType === "string" ? req.query.salaryType : undefined,
        sortBy: typeof req.query.sortBy === "string" ? (req.query.sortBy as "date" | "salary" | "relevance") : undefined,
        sortOrder: typeof req.query.sortOrder === "string" ? (req.query.sortOrder as "asc" | "desc") : undefined,
        limit: parseNumber(req.query.limit),
        offset: parseNumber(req.query.offset),
      };

      const parsedFilters = jobVacancyFiltersSchema.safeParse(rawFilters);
      if (!parsedFilters.success) {
        const firstIssue = parsedFilters.error.issues[0];
        return sendValidationError(res, firstIssue?.message || "Invalid filters", firstIssue?.path?.[0] as string | undefined);
      }

      const filters = parsedFilters.data;
      const db = await storage.getDb();
      const jobs = await db.select().from(jobsTable);

      const employerIds: string[] = Array.from(
        new Set(
          (jobs || [])
            .map((job: any) => job.employerId)
            .filter((id: string | null | undefined): id is string => Boolean(id))
        )
      );

      let employerMap = new Map<string, any>();
      if (employerIds.length > 0) {
        const employerRows = await db
          .select()
          .from(employersTable)
          .where(inArray(employersTable.id, employerIds));
        employerMap = new Map(
          employerRows.map((row: any) => [row.id, row])
        );
      }

      const normalizedJobs = (jobs || [])
        .filter((job: any) => {
          const status = String(job.status || "pending").toLowerCase();
          if (status !== "active") return false;
          if (job.archived) return false;
          return true;
        })
        .filter((job: any) => {
          if (filters.search) {
            const haystack = [
              job.positionTitle,
              job.description,
              job.establishmentName,
              job.location,
              job.municipality,
              job.province,
            ]
              .map((value) => (value ? String(value).toLowerCase() : ""))
              .join(" ");
            if (!haystack.includes(filters.search.toLowerCase())) {
              return false;
            }
          }

          if (filters.industry) {
            const industries = Array.isArray(job.industryCodes)
              ? job.industryCodes
              : typeof job.industryCodes === "string"
                ? [job.industryCodes]
                : [];
            const match = industries.some((code: string) =>
              code?.toLowerCase().includes(filters.industry!.toLowerCase())
            );
            if (!match) return false;
          }

          if (filters.jobStatus) {
            const jobStatus = String(job.jobStatus || job.status || "").toLowerCase();
            if (jobStatus !== filters.jobStatus.toLowerCase()) {
              return false;
            }
          }

          const minSalary = job.salaryMin ?? job.startingSalaryOrWage ?? job.salaryAmount;
          const maxSalary = job.salaryMax ?? job.salaryAmount;
          if (filters.minSalary && (minSalary ?? 0) < filters.minSalary) return false;
          if (filters.maxSalary && (maxSalary ?? 0) > filters.maxSalary) return false;

          if (filters.educationLevel) {
            const education =
              job.minimumEducationRequired || job.minimumEducation || "";
            if (!education.toLowerCase().includes(filters.educationLevel.toLowerCase())) {
              return false;
            }
          }

          if (filters.minExperience) {
            const experience = job.yearsOfExperienceRequired ?? job.yearsOfExperience ?? 0;
            if (experience < filters.minExperience) return false;
          }

          if (filters.maxExperience) {
            const experience = job.yearsOfExperienceRequired ?? job.yearsOfExperience ?? 0;
            if (experience > filters.maxExperience) return false;
          }

          if (filters.salaryType) {
            const salaryPeriod = String(job.salaryPeriod || job.salary?.period || "monthly").toLowerCase();
            if (salaryPeriod !== filters.salaryType.toLowerCase()) {
              return false;
            }
          }

          return true;
        })
        .map((job: any) => {
          const employer = job.employerId ? employerMap.get(job.employerId) : null;
          const timestamps = formatJobTimestamps(job);
          const salaryFloor = job.salaryMin ?? job.startingSalaryOrWage ?? job.salaryAmount;
          return {
            id: job.id,
            employerId: job.employerId,
            establishmentName:
              job.establishmentName || employer?.establishmentName || employer?.company || employer?.name || "",
            positionTitle: job.positionTitle,
            description: job.description,
            minimumEducationRequired: job.minimumEducationRequired || job.minimumEducation || "",
            mainSkillOrSpecialization: job.mainSkillOrSpecialization || job.skills || "",
            yearsOfExperienceRequired: job.yearsOfExperienceRequired ?? job.yearsOfExperience ?? 0,
            salary: job.salary,
            startingSalaryOrWage: salaryFloor || null,
            vacantPositions: job.vacantPositions ?? 1,
            paidEmployees: job.paidEmployees,
            jobStatus: job.jobStatus || job.status || "active",
            contact: job.contact,
            location: job.location || job.municipality || job.province || "",
            requirements: job.requirements,
            archived: Boolean(job.archived),
            createdAt: timestamps.createdAt,
            updatedAt: timestamps.updatedAt,
          };
        });

      const sortBy = filters.sortBy || "date";
      const sortOrder = filters.sortOrder || "desc";
      normalizedJobs.sort((a: any, b: any) => {
        if (sortBy === "salary") {
          const salaryA = a.startingSalaryOrWage || 0;
          const salaryB = b.startingSalaryOrWage || 0;
          return sortOrder === "asc" ? salaryA - salaryB : salaryB - salaryA;
        }
        const dateA = new Date(a.createdAt || 0).getTime();
        const dateB = new Date(b.createdAt || 0).getTime();
        return sortOrder === "asc" ? dateA - dateB : dateB - dateA;
      });

      const limit = filters.limit ?? normalizedJobs.length;
      const offset = filters.offset ?? 0;
      const paginated = normalizedJobs.slice(offset, offset + limit);

      return res.json({
        vacancies: paginated,
        total: normalizedJobs.length,
        limit,
        offset,
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/applicants - Create a new applicant (admin only)
  app.post("/api/applicants", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      if (!req.body || typeof req.body !== "object") {
        return sendValidationError(res, "Invalid applicant payload");
      }

      const parsed = applicantCreateSchema.safeParse(req.body);
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        return sendValidationError(res, issue?.message || "Invalid applicant payload", issue?.path?.[0] as string | undefined);
      }

      const payload = normalizeDateFields(parsed.data);
      const created = await storage.addApplicant(payload as any);

      return res.status(201).json(mapApplicantToTableShape(created));
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/applicants - List applicants for admin dashboards
  app.get("/api/applicants", authMiddleware, async (req: Request, res: Response) => {
    try {
      const toNumber = (value: unknown) => {
        if (typeof value === "string" && value.trim().length > 0) {
          const parsed = Number(value);
          return Number.isNaN(parsed) ? undefined : parsed;
        }
        if (Array.isArray(value) && value.length > 0) {
          return toNumber(value[0]);
        }
        return undefined;
      };

      const parsedFilters = applicantFilterSchema.safeParse({
        employmentStatus: typeof req.query.employmentStatus === "string" ? req.query.employmentStatus : undefined,
        barangay: typeof req.query.barangay === "string" ? req.query.barangay : undefined,
        search: typeof req.query.search === "string" ? req.query.search : undefined,
        limit: toNumber(req.query.limit),
        offset: toNumber(req.query.offset),
        startDate: typeof req.query.startDate === "string" ? req.query.startDate : undefined,
        endDate: typeof req.query.endDate === "string" ? req.query.endDate : undefined,
      });

      if (!parsedFilters.success) {
        const firstIssue = parsedFilters.error.issues[0];
        return sendValidationError(res, firstIssue?.message || "Invalid filters", firstIssue?.path?.[0] as string | undefined);
      }

      if (!storage.getApplicants) {
        return res.json([]);
      }

      const filters = parsedFilters.data;
      let applicants = await storage.getApplicants();

      const startDateFilter = filters.startDate ? new Date(filters.startDate) : undefined;
      const endDateFilter = filters.endDate ? new Date(filters.endDate) : undefined;
      if (endDateFilter) {
        endDateFilter.setHours(23, 59, 59, 999);
      }

      if (startDateFilter || endDateFilter) {
        applicants = applicants.filter((app: any) => {
          if (!app.createdAt) {
            return false;
          }
          const createdAt = new Date(app.createdAt);
          if (Number.isNaN(createdAt.getTime())) {
            return false;
          }
          if (startDateFilter && createdAt < startDateFilter) {
            return false;
          }
          if (endDateFilter && createdAt > endDateFilter) {
            return false;
          }
          return true;
        });
      }

      if (filters.employmentStatus) {
        const normalizeFilterValue = (value: unknown) =>
          typeof value === "string"
            ? value.trim().toLowerCase()
            : "";

        const target = normalizeFilterValue(filters.employmentStatus);
        applicants = applicants.filter((app: any) => {
          const statusValue = normalizeFilterValue(app.employmentStatus);
          const detailValue = normalizeFilterValue(app.employmentStatusDetail);
          const categoryValue = normalizeFilterValue(app.selfEmployedCategory);
          const reasonValue = normalizeFilterValue(app.unemployedReason);

          if (statusValue === target || detailValue === target || categoryValue === target || reasonValue === target) {
            return true;
          }

          // Allow legacy substring matches as a fallback (e.g., "terminated" filter)
          return target.length > 0 && statusValue.includes(target);
        });
      }

      if (filters.barangay) {
        const barangay = filters.barangay.toLowerCase();
        applicants = applicants.filter((app: any) => (app.barangay || "").toLowerCase() === barangay);
      }

      if (filters.search) {
        const search = filters.search.toLowerCase();
        applicants = applicants.filter((app: any) => {
          const haystack = [
            app.firstName,
            app.middleName,
            app.surname,
            app.email,
            app.contactNumber,
          ]
            .map((value) => (value ? String(value).toLowerCase() : ""))
            .join(" ");
          return haystack.includes(search);
        });
      }

      const offset = filters.offset ?? 0;
      const limit = typeof filters.limit === "number" ? filters.limit : undefined;
      if (offset || limit) {
        const start = Math.max(0, offset);
        const end = typeof limit === "number" ? start + limit : undefined;
        applicants = applicants.slice(start, end ?? applicants.length);
      }
      const normalized = applicants.map(mapApplicantToTableShape);
      return res.json(normalized);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // ============ EMPLOYER ROUTES ============

  // GET /api/applicants/:id - Get a single applicant by ID
  app.get("/api/applicants/:id", authMiddleware, async (req: Request, res: Response) => {
    try {
      const applicantId = req.params.id;
      const wantsProfile = String(req.query.view || "").toLowerCase() === "profile";
      const db = await storage.getDb();
      const [applicant] = await db.select().from(usersTable).where(eq(usersTable.id, applicantId));
      if (!applicant) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Applicant not found"));
      }

      if (wantsProfile) {
        const requester = req.user as any;
        const isAdmin = requester?.role === "admin";
        if (!isAdmin && requester?.id !== applicantId) {
          return res
            .status(403)
            .json(createErrorResponse(ErrorCodes.FORBIDDEN, "You can only view your own profile"));
        }

        return res.json(mapApplicantToProfileShape(applicant));
      }

      // Map snake_case to camelCase for frontend compatibility
      const mapped = {
        ...applicant,
        profileImage: applicant.profile_image,
      };
      res.json(mapApplicantToTableShape(mapped));
    } catch (error) {
      console.error("Error fetching applicant:", error);
      return sendError(res, error);
    }
  });

  // PUT /api/applicants/:id - Update applicant profile (self-service or admin)
  app.put("/api/applicants/:id", authMiddleware, async (req: Request, res: Response) => {
    try {
      const targetId = req.params.id;
      const requester = req.user as any;
      const isAdmin = requester?.role === "admin";

      if (!isAdmin && requester?.id !== targetId) {
        return res
          .status(403)
          .json(createErrorResponse(ErrorCodes.FORBIDDEN, "You can only update your own profile"));
      }

      if (!req.body || typeof req.body !== "object") {
        return sendValidationError(res, "Invalid payload");
      }

      // Clean optional enum fields so empty strings don't fail validation
      const payload = { ...req.body } as Record<string, unknown>;
      const enumFields = [
        "employmentType",
        "employmentStatusDetail",
        "selfEmployedCategory",
        "selfEmployedCategoryOther",
        "unemployedReason",
        "unemployedReasonOther",
      ];
      enumFields.forEach((field) => {
        if (field in payload && (payload as any)[field] === "") {
          delete (payload as any)[field];
        }
      });

      // Normalize array-expected fields: accept JSON strings, coerce scalars to []
      const arrayFields = [
        "education",
        "technicalTraining",
        "professionalLicenses",
        "languageProficiency",
        "workExperience",
        "otherSkills",
        "skills",
        "otherSkillsTraining",
        "preferredOccupations",
        "preferredLocations",
        "preferredOverseasCountries",
        "familyMembers",
        "dependents",
        "references",
        "documentRequirements",
        "additionalAddresses",
      ];

      arrayFields.forEach((field) => {
        if (!(field in payload)) return;
        const value = (payload as any)[field];
        if (Array.isArray(value)) return;
        if (typeof value === "string") {
          try {
            const parsed = JSON.parse(value);
            (payload as any)[field] = Array.isArray(parsed) ? parsed : [];
            return;
          } catch {
            // fall through
          }
        }
        // Any non-array value becomes an empty array to satisfy schema
        (payload as any)[field] = [];
      });

      const parsed = applicantUpdateSchema.safeParse(payload || {});
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        return sendValidationError(res, issue?.message || "Invalid applicant payload", issue?.path?.[0] as string | undefined);
      }

      const updates: Record<string, unknown> = { ...parsed.data };
      const disallowedFields = new Set([
        "id",
        "hasAccount",
        "role",
        "passwordHash",
        "createdAt",
        "updatedAt",
      ]);

      disallowedFields.forEach((field) => {
        if (field in updates) {
          delete updates[field];
        }
      });

      if (!isAdmin && "email" in updates) {
        delete updates.email;
      }

      // Normalize timestamp fields to Date objects to avoid driver getTime errors
      const timestampFields = ["registrationDate", "registeredAt", "lastLoginAt", "createdAt", "updatedAt"] as const;
      for (const field of timestampFields) {
        if (field in updates) {
          const raw = updates[field];
          const dt = raw ? new Date(raw as any) : null;
          if (dt && !Number.isNaN(dt.getTime())) {
            updates[field] = dt;
          } else {
            delete updates[field];
          }
        }
      }

      // Normalize birth dates to date-only strings (YYYY-MM-DD)
      const normalizeDateOnly = (value: unknown): string | undefined => {
        if (value === null || value === undefined) return undefined;
        if (typeof value === "string") {
          const trimmed = value.trim();
          if (!trimmed) return undefined;
          if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return trimmed;
        }
        const dt = new Date(value as any);
        if (Number.isNaN(dt.getTime())) return undefined;
        return dt.toISOString().slice(0, 10);
      };

      if ("dateOfBirth" in updates) {
        const dob = normalizeDateOnly(updates.dateOfBirth);
        if (dob) updates.dateOfBirth = dob;
        else delete updates.dateOfBirth;
      }
      if ("birthDate" in updates) {
        const bd = normalizeDateOnly((updates as any).birthDate);
        if (bd) (updates as any).birthDate = bd;
        else delete (updates as any).birthDate;
      }

      if (Object.keys(updates).length === 0) {
        return sendValidationError(res, "No allowed fields to update");
      }

      const updated = await storage.updateApplicant(targetId, normalizeDateFields(updates as any));
      if (!updated) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Applicant not found"));
      }

      // Return normalized shape so UI and admin views stay consistent
      res.json(mapApplicantToTableShape(updated));
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/applicants/:id - Remove a single applicant (admin only)
  app.delete("/api/applicants/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const applicantId = req.params.id;
      if (!applicantId) {
        return sendValidationError(res, "Applicant ID is required", "id");
      }

      await storage.deleteApplicant(applicantId);
      return res.json({ success: true, id: applicantId });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/applicants/bulk-delete - Remove multiple applicants (admin only)
  app.post("/api/applicants/bulk-delete", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const ids = Array.isArray(req.body?.ids)
        ? req.body.ids.filter((id: unknown) => typeof id === "string" && id.trim() !== "")
        : [];

      if (ids.length === 0) {
        return sendValidationError(res, "Provide at least one applicant ID", "ids");
      }

      await storage.deleteApplicants(ids);
      return res.json({ success: true, deleted: ids.length, ids });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/jobs - List all public jobs (approved/active only, excluding archived)
  app.get("/api/jobs", async (req: Request, res: Response) => {
    try {
      // Default: only approved/active jobs; allow explicit status query override for admin/tools
      const requestedStatus = String(req.query.status || "active").toLowerCase();
      const allowAllStatuses = requestedStatus === "all";

      const db = await storage.getDb();
      const jobs = allowAllStatuses
        ? await db.select().from(jobsTable)
        : await db
            .select()
            .from(jobsTable)
            .where(
              and(
                eq(jobsTable.archived, false),
                eq(jobsTable.status, "active")
              )
            );

      const activeJobs = (jobs || []).filter((j: any) => {
        const status = (j.status || "").toLowerCase();
        const jobStatus = (j.jobStatus || "").toLowerCase();
        const isApproved = status === "active" || jobStatus === "active";
        return !j.archived && (allowAllStatuses || isApproved);
      }).map((job: any) => ({
        ...formatJobTimestamps(job),
        archived: job.archived || false,
        type: 'job',
      }));
      // Sort by createdAt desc
      const allJobs = [...activeJobs].sort((a, b) => {
        const dateA = new Date(a.createdAt).getTime();
        const dateB = new Date(b.createdAt).getTime();
        return dateB - dateA;
      }).map(mapJobToTableShape);
      res.json(allJobs);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PATCH /api/jobs/:jobId/archive - Archive a job posting
  app.patch("/api/jobs/:jobId/archive", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.jobId;
      const db = await storage.getDb();

      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!job) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found"));
      }

      // Defensive: only use archivedAt if it's a valid non-empty string
      let archivedAt = new Date();
      if (req.body && typeof req.body.archivedAt === 'string' && req.body.archivedAt.trim().length > 0) {
        const parsed = new Date(req.body.archivedAt);
        archivedAt = isNaN(parsed.getTime()) ? new Date() : parsed;
      }

      await db
        .update(jobsTable)
        .set({ archived: true, archivedAt, updatedAt: archivedAt })
        .where(eq(jobsTable.id, jobId));

      const archivedJob = formatJobTimestamps({
        ...job,
        archived: true,
        archivedAt,
        updatedAt: archivedAt,
      });

      return res.json({
        message: "Job archived successfully",
        job: archivedJob,
      });
    } catch (error) {
      // Defensive: never call getTime on non-Date
      // Defensive: if ORM hit getTime on a non-date, coerce and retry once
      if (error instanceof Error && error.message.includes('getTime')) {
        try {
          const fallbackDate = new Date();
          await (await storage.getDb())
            .update(jobsTable)
            .set({ archived: true, archivedAt: fallbackDate, updatedAt: fallbackDate })
            .where(eq(jobsTable.id, req.params.jobId));
          const [jobRow] = await (await storage.getDb()).select().from(jobsTable).where(eq(jobsTable.id, req.params.jobId));
          return res.json({ message: "Job archived successfully", job: formatJobTimestamps(jobRow) });
        } catch (inner) {
          return sendError(res, inner);
        }
      }
      return sendError(res, error);
    }
  });

  // POST /api/jobs - Create a new job posting
  app.post("/api/jobs", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const payload = jobCreateSchema.parse(req.body);
      
      const db = await storage.getDb();
      const now = new Date();
      const result = await db.insert(jobsTable).values({
        positionTitle: payload.positionTitle,
        description: payload.description,
        location: payload.location,
        salaryMin: payload.salaryMin,
        salaryMax: payload.salaryMax,
        salaryPeriod: payload.salaryPeriod || "monthly",
        salaryAmount: payload.salaryAmount,
        status: payload.status || "active",
        employerId: payload.employerId,
        createdAt: now,
        updatedAt: now,
      }).returning();
      res.status(201).json({
        success: true,
        message: "Job posting created successfully",
        job: formatJobTimestamps(result[0]),
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/jobs/:jobId - Delete a job posting (permanent deletion from archive)
  app.delete("/api/jobs/:jobId", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.jobId;
      const db = await storage.getDb();
      const existing = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!existing || existing.length === 0) {
        return res.status(404).json({ error: "Job not found" });
      }
      await db.delete(jobsTable).where(eq(jobsTable.id, jobId));
      res.json({ message: "Job deleted successfully" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PUT /api/jobs/:jobId - Update an existing job posting
  app.put("/api/jobs/:jobId", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.jobId;
      const updateData = req.body;
      const db = await storage.getDb();
      const jobs = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!jobs || jobs.length === 0) {
        return res.status(404).json({ error: "Job not found" });
      }
      const job = jobs[0];
      const updatedJob = {
        ...job,
        ...updateData,
        id: jobId,
        createdAt: job.createdAt,
        updatedAt: new Date().toISOString(),
      };
      await db.update(jobsTable).set(updatedJob).where(eq(jobsTable.id, jobId));
      res.json({ message: "Job updated successfully", job: updatedJob });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // ===== Employer-managed job postings =====

  // GET /api/employer/profile - get employer profile
  app.get("/api/employer/profile", authMiddleware, roleMiddleware("employer"), async (req: Request, res: Response) => {
    try {
      const employerId = (req.user as import("@shared/schema").User | undefined)?.id;
      if (!employerId) {
        return res
          .status(401)
          .json(createErrorResponse(ErrorCodes.UNAUTHORIZED, "Employer account not found"));
      }

      const db = await storage.getDb();
      const employer = await db.query.employersTable.findFirst({
        where: (table: typeof employersTable) => eq(table.id, employerId),
      });

      if (!employer) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer profile not found"));
      }

      return res.json(serializeEmployerRow(employer));
    } catch (error) {
      console.error("[Employer] Failed to load profile", error);
      return sendError(res, error);
    }
  });

  // PUT /api/employer/profile - update employer profile
  app.put("/api/employer/profile", authMiddleware, roleMiddleware("employer"), async (req: Request, res: Response) => {
    try {
      const employerId = (req.user as import("@shared/schema").User | undefined)?.id;
      if (!employerId) {
        return res
          .status(401)
          .json(createErrorResponse(ErrorCodes.UNAUTHORIZED, "Employer account not found"));
      }

      const db = await storage.getDb();
      const existing = await db.query.employersTable.findFirst({
        where: (table: typeof employersTable) => eq(table.id, employerId),
      });

      if (!existing) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer profile not found"));
      }

      const normalized = normalizeEmployerInput(req.body);
      // Date accomplished is server-controlled.
      delete (normalized as any).dateAccomplished;

      const payload = employerUpdateSchema.parse(normalized);

      const buildDisplayValue = (value: any) => {
        if (value === null || value === undefined) return "";
        if (Array.isArray(value)) return value.map((v) => String(v)).filter(Boolean).join(", ");
        if (typeof value === "object") {
          try {
            return JSON.stringify(value);
          } catch {
            return "[object]";
          }
        }
        return String(value);
      };

      const truncate = (text: string, max = 60) => {
        const trimmed = text.trim();
        if (trimmed.length <= max) return trimmed;
        return `${trimmed.slice(0, max - 1)}…`;
      };

      const safeParseJson = (value: any) => {
        if (!value) return null;
        if (typeof value === "object") return value;
        if (typeof value === "string") {
          const s = value.trim();
          if (!s) return null;
          try {
            return JSON.parse(s);
          } catch {
            return value;
          }
        }
        return value;
      };

      const fileLabel: Record<string, string> = {
        businessPermitFile: "Business Permit",
        bir2303File: "BIR 2303",
        companyProfileFile: "Company Profile",
        doleCertificationFile: "DOLE Certification",
        srsFormFile: "SRS Form",
      };

      const diffParts: string[] = [];
      const compareField = (key: string, label: string, format?: (v: any) => string) => {
        if ((payload as any)[key] === undefined) return;
        const prevRaw = (existing as any)[key];
        const nextRaw = (payload as any)[key];
        const prev = truncate((format ? format(prevRaw) : buildDisplayValue(prevRaw)));
        const next = truncate((format ? format(nextRaw) : buildDisplayValue(nextRaw)));
        if (prev !== next) {
          diffParts.push(`${label}: ${prev || "(empty)"} → ${next || "(empty)"}`);
        }
      };

      // Flat fields
      compareField("establishmentName", "Establishment Name");
      compareField("tradeName", "Trade Name");
      compareField("contactEmail", "Contact Email");
      compareField("contactNumber", "Contact Number");
      compareField("houseStreetVillage", "Street/House/Village");
      compareField("barangay", "Barangay");
      compareField("municipality", "Municipality/City");
      compareField("province", "Province");
      compareField("geographicCode", "Geographic Code");
      compareField("telNumber", "Telephone");
      compareField("numberOfPaidEmployees", "Paid Employees", (v) => String(v ?? ""));
      compareField("numberOfVacantPositions", "Vacant Positions", (v) => String(v ?? ""));
      compareField("industryCodes", "Industry Codes", (v) => (Array.isArray(v) ? v.join(", ") : buildDisplayValue(v)));
      compareField("businessPermitNumber", "Business Permit No.");
      compareField("bir2303Number", "BIR 2303 No.");
      compareField("doleCertificationNumber", "DOLE Cert No.");
      compareField("companyTin", "Company TIN");
      compareField("remarks", "Remarks");
      compareField("preparedByName", "Prepared By (Name)");
      compareField("preparedByDesignation", "Prepared By (Designation)");
      compareField("preparedByContact", "Prepared By (Contact)");
      compareField("srsSubscriber", "SRS Subscriber", (v) => (v ? "Yes" : "No"));
      compareField("isManpowerAgency", "Manpower Agency", (v) => (v ? "Yes" : "No"));

      // Nested contact person
      if ((payload as any).contactPerson !== undefined) {
        const prevContact = safeParseJson((existing as any).contactPerson) || {};
        const nextContact = safeParseJson((payload as any).contactPerson) || {};
        const pick = (obj: any, key: string) => (obj && typeof obj === "object" ? String(obj[key] ?? "").trim() : "");

        const prevName = pick(prevContact, "personName");
        const nextName = pick(nextContact, "personName");
        if (prevName !== nextName) diffParts.push(`Contact Person: ${truncate(prevName) || "(empty)"} → ${truncate(nextName) || "(empty)"}`);

        const prevEmail = pick(prevContact, "email");
        const nextEmail = pick(nextContact, "email");
        if (prevEmail !== nextEmail) diffParts.push(`Contact Person Email: ${truncate(prevEmail) || "(empty)"} → ${truncate(nextEmail) || "(empty)"}`);

        const prevPhone = pick(prevContact, "contactNumber");
        const nextPhone = pick(nextContact, "contactNumber");
        if (prevPhone !== nextPhone) diffParts.push(`Contact Person Number: ${truncate(prevPhone) || "(empty)"} → ${truncate(nextPhone) || "(empty)"}`);
      }

      // Additional establishments (additional companies)
      if ((payload as any).additionalEstablishments !== undefined) {
        const prevAddl = Array.isArray((existing as any).additionalEstablishments)
          ? (existing as any).additionalEstablishments
          : safeParseJson((existing as any).additionalEstablishments);
        const nextAddl = Array.isArray((payload as any).additionalEstablishments)
          ? (payload as any).additionalEstablishments
          : safeParseJson((payload as any).additionalEstablishments);

        const prevCount = Array.isArray(prevAddl) ? prevAddl.length : 0;
        const nextCount = Array.isArray(nextAddl) ? nextAddl.length : 0;
        if (prevCount !== nextCount) {
          diffParts.push(`Additional Companies: ${prevCount} → ${nextCount}`);
        }
      }

      // File attachments (only note that it changed)
      (Object.keys(fileLabel) as Array<keyof typeof fileLabel>).forEach((key) => {
        if ((payload as any)[key] === undefined) return;
        const prev = safeParseJson((existing as any)[key]);
        const next = safeParseJson((payload as any)[key]);
        const prevStr = buildDisplayValue(prev);
        const nextStr = buildDisplayValue(next);
        if (prevStr !== nextStr) {
          diffParts.push(`${fileLabel[key]} Document: updated`);
        }
      });

      const preparedFields = ["preparedByName", "preparedByDesignation", "preparedByContact"] as const;
      const preparedByChanged = preparedFields.some((key) => {
        if (payload[key] === undefined) return false;
        const next = String(payload[key] ?? "").trim();
        const prev = String((existing as any)[key] ?? "").trim();
        return next !== prev;
      });

      if (preparedByChanged) {
        (payload as any).dateAccomplished = new Date().toISOString().slice(0, 10);
      } else {
        const hasAnyPreparedBy = preparedFields.some((key) => {
          const next = payload[key] !== undefined ? String(payload[key] ?? "").trim() : "";
          const prev = String((existing as any)[key] ?? "").trim();
          return Boolean(next || prev);
        });

        if (hasAnyPreparedBy && !String((existing as any)?.dateAccomplished ?? "").trim()) {
          (payload as any).dateAccomplished = new Date().toISOString().slice(0, 10);
        }
      }

      const update = buildEmployerUpdate(payload);
      // Strict mode: any employer-initiated profile change requires re-approval.
      update.accountStatus = "pending";
      update.reviewedBy = null;
      update.reviewedAt = null;
      update.rejectionReason = null;

      const [updated] = await db
        .update(employersTable)
        .set(update)
        .where(eq(employersTable.id, employerId))
        .returning();

      // Notify admins about employer self-updates (what changed).
      try {
        if (diffParts.length > 0) {
          const employerName =
            String((existing as any).establishmentName || (existing as any).tradeName || (req.user as any)?.name || employerId).trim();

          const now = new Date().toISOString();
          const message = `Employer ${employerName} updated My Account: ${diffParts.slice(0, 8).join("; ")}${diffParts.length > 8 ? "; …" : ""}`;
          const notif = {
            id: `notif_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
            role: "admin",
            userId: null,
            type: "system",
            message,
            read: false,
            createdAt: now,
            updatedAt: now,
          };
          await db.insert(notificationsTable).values(notif as any);
          broadcastNotification("new", notif);
        }
      } catch (notifyError) {
        console.warn("[Employer] Failed to create admin notification for profile update", notifyError);
      }

      if (!updated) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer profile not found"));
      }

      return res.json(serializeEmployerRow(updated));
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const message = error?.issues?.[0]?.message || error.message || "Invalid employer profile payload";
        return sendValidationError(res, message);
      }
      console.error("[Employer] Failed to update profile", error);
      return sendError(res, error);
    }
  });

  // GET /api/employer/jobs - list jobs owned by the authenticated employer
  app.get("/api/employer/jobs", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user?.role !== "employer") {
        return res
          .status(403)
          .json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can access their job postings"));
      }

      const db = await storage.getDb();
      const jobs = await db
        .select()
        .from(jobsTable)
        .where(eq(jobsTable.employerId, req.user.id));

      const formatted = jobs
        .map(serializeJob)
        .sort((a: any, b: any) => {
          const dateA = new Date(a.updatedAt || a.createdAt || 0).getTime();
          const dateB = new Date(b.updatedAt || b.createdAt || 0).getTime();
          return dateB - dateA;
        });

      return res.json(formatted);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/employer/jobs - submit a job for admin review or save as draft
  app.post("/api/employer/jobs", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user?.role !== "employer") {
        return res
          .status(403)
          .json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can create job postings"));
      }

      const db = await storage.getDb();
      const employer = await db.query.employersTable.findFirst({
        where: (table: typeof employersTable) => eq(table.id, req.user.id),
      });

      if (!employer) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer record not found"));
      }

      const employerAccountStatus = String((employer as any).accountStatus || (employer as any).account_status || "pending").toLowerCase();
      if (employerAccountStatus !== "active") {
        return res
          .status(403)
          .json(
            createErrorResponse(
              ErrorCodes.FORBIDDEN,
              employerAccountStatus === "rejected"
                ? "Your employer account was rejected. You cannot post job vacancies."
                : "Your employer account is pending approval. You cannot post job vacancies yet."
            )
          );
      }

      const derivedBarangay = (req.body?.barangay ?? employer.barangay) as string | undefined;
      const derivedMunicipality = (req.body?.municipality ?? employer.municipality) as string | undefined;
      const derivedProvince = (req.body?.province ?? employer.province) as string | undefined;

      const providedLocation = typeof req.body?.location === "string" ? req.body.location.trim() : "";
      const fallbackLocation = providedLocation || [
        derivedBarangay,
        derivedMunicipality,
        derivedProvince,
      ]
        .filter((part) => typeof part === "string" && part.trim().length > 0)
        .join(", ");

      if (!fallbackLocation) {
        return sendValidationError(res, "Location is required", "location");
      }

      const saveAsDraft = typeof req.body?.saveAsDraft === "boolean" ? req.body.saveAsDraft : false;
      const targetStatus: "pending" | "draft" = saveAsDraft ? "draft" : "pending";

      const parsedJob = jobCreateSchema.safeParse({
        ...req.body,
        location: fallbackLocation,
        employerId: req.user.id,
        status: targetStatus,
      });

      if (!parsedJob.success) {
        const issue = parsedJob.error.issues?.[0];
        return sendValidationError(
          res,
          issue?.message || "Invalid job payload",
          issue?.path?.[0]?.toString()
        );
      }

      const payload = parsedJob.data;

      const normalizedLocation = payload.location?.trim() || fallbackLocation;

      const derivedIndustryCodes = payload.industryCodes ?? (employer.industryCodes as string[] | undefined) ?? [];
      const derivedPreparedByName = payload.preparedByName ?? employer.preparedByName ?? null;
      const derivedPreparedByDesignation = payload.preparedByDesignation ?? employer.preparedByDesignation ?? null;
      const derivedPreparedByContact = payload.preparedByContact ?? employer.preparedByContact ?? null;
      const derivedDateAccomplished = new Date().toISOString().slice(0, 10);
      const derivedSkills = payload.skills ?? null;

      const now = new Date();
      const [created] = await db
        .insert(jobsTable)
        .values({
          employerId: payload.employerId,
          establishmentName:
            employer.establishmentName || employer.companyName || employer.name || employer.contactPerson || "",
          positionTitle: payload.positionTitle,
          description: payload.description,
          location: normalizedLocation,
          salaryMin: payload.salaryMin,
          salaryMax: payload.salaryMax,
          salaryAmount: payload.salaryAmount,
          salaryPeriod: payload.salaryPeriod || "monthly",
          salaryType: payload.salaryType,
          jobStatus: payload.jobStatus,
          minimumEducationRequired: payload.minimumEducation,
          yearsOfExperienceRequired: payload.yearsOfExperience,
          agePreference: payload.agePreference,
          industryCodes: derivedIndustryCodes,
          vacantPositions: payload.vacantPositions,
          paidEmployees: payload.paidEmployees,
          mainSkillOrSpecialization: derivedSkills,
          skills: derivedSkills,
          startingSalaryOrWage: payload.salaryAmount ?? payload.salaryMin ?? payload.salaryMax ?? null,
          preparedByName: derivedPreparedByName,
          preparedByDesignation: derivedPreparedByDesignation,
          preparedByContact: derivedPreparedByContact,
          dateAccomplished: derivedDateAccomplished,
          barangay: payload.barangay ?? employer.barangay,
          municipality: payload.municipality ?? employer.municipality,
          province: payload.province ?? employer.province,
          status: targetStatus,
          archived: false,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      return res.status(201).json({
        message: saveAsDraft ? "Job saved as draft" : "Job submitted for admin review",
        job: formatJobTimestamps(created),
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PUT /api/employer/jobs/:jobId - request updates (resets status to pending unless saved as draft)
  app.put("/api/employer/jobs/:jobId", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user?.role !== "employer") {
        return res
          .status(403)
          .json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can update their job postings"));
      }

      // Gate edits/submissions until employer account is approved
      const db = await storage.getDb();
      const employer = await db.query.employersTable.findFirst({
        where: (table: typeof employersTable) => eq(table.id, req.user.id),
      });

      if (!employer) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer record not found"));
      }

      const employerAccountStatus = String((employer as any).accountStatus || (employer as any).account_status || "pending").toLowerCase();
      if (employerAccountStatus !== "active") {
        return res
          .status(403)
          .json(
            createErrorResponse(
              ErrorCodes.FORBIDDEN,
              employerAccountStatus === "rejected"
                ? "Your employer account was rejected. You cannot update job vacancies."
                : "Your employer account is pending approval. You cannot update job vacancies yet."
            )
          );
      }

      const jobId = req.params.jobId;
      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));

      if (!job || job.employerId !== req.user.id) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found"));
      }

      const payload = employerJobUpdateSchema.parse(req.body || {});
      const saveAsDraft = typeof req.body?.saveAsDraft === "boolean" ? req.body.saveAsDraft : false;
      const targetStatus: "pending" | "draft" = saveAsDraft ? "draft" : "pending";
      const updates: Record<string, unknown> = {};
      const add = (key: string, value: unknown) => {
        if (value !== undefined) updates[key] = value;
      };

      add("positionTitle", (payload as any).positionTitle);
      add("description", (payload as any).description);

      // Location (support structured updates)
      const nextBarangay = (payload as any).barangay;
      const nextMunicipality = (payload as any).municipality;
      const nextProvince = (payload as any).province;
      add("barangay", nextBarangay);
      add("municipality", nextMunicipality);
      add("province", nextProvince);

      const explicitLocation = (payload as any).location;
      if (explicitLocation !== undefined) {
        add("location", explicitLocation);
      } else if (nextBarangay !== undefined || nextMunicipality !== undefined || nextProvince !== undefined) {
        const parts = [
          nextBarangay ?? (job as any).barangay,
          nextMunicipality ?? (job as any).municipality,
          nextProvince ?? (job as any).province,
        ].filter(Boolean);
        add("location", parts.join(", "));
      }

      // Salary
      add("salaryMin", (payload as any).salaryMin);
      add("salaryMax", (payload as any).salaryMax);
      add("salaryAmount", (payload as any).salaryAmount);
      add("salaryPeriod", (payload as any).salaryPeriod);
      add("salaryType", (payload as any).salaryType);
      const salaryForLegacy =
        (payload as any).salaryAmount ?? (payload as any).salaryMin ?? (payload as any).salaryMax;
      if (salaryForLegacy !== undefined) {
        add("startingSalaryOrWage", salaryForLegacy);
      }

      // Requirements
      add("minimumEducationRequired", (payload as any).minimumEducation);
      add("yearsOfExperienceRequired", (payload as any).yearsOfExperience);
      add("agePreference", (payload as any).agePreference);
      add("industryCodes", (payload as any).industryCodes);
      add("vacantPositions", (payload as any).vacantPositions);
      add("paidEmployees", (payload as any).paidEmployees);
      add("jobStatus", (payload as any).jobStatus);

      // Skills
      if ((payload as any).skills !== undefined) {
        add("skills", (payload as any).skills);
        add("mainSkillOrSpecialization", (payload as any).skills);
      }

      // Prepared by
      add("preparedByName", (payload as any).preparedByName);
      add("preparedByDesignation", (payload as any).preparedByDesignation);
      add("preparedByContact", (payload as any).preparedByContact);
      add("dateAccomplished", (payload as any).dateAccomplished);

      if (Object.keys(updates).length === 0) {
        return sendValidationError(res, "No changes supplied");
      }

      const now = new Date();
      updates.status = targetStatus;
      updates.updatedAt = now;

      const [updated] = await db
        .update(jobsTable)
        .set(updates)
        .where(eq(jobsTable.id, jobId))
        .returning();

      return res.json({
        message: saveAsDraft ? "Job saved as draft" : "Job update submitted for admin review",
        job: formatJobTimestamps(updated),
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/employer/jobs/:jobId - remove a draft/pending job
  app.delete("/api/employer/jobs/:jobId", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user?.role !== "employer") {
        return res
          .status(403)
          .json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can delete their job postings"));
      }

      const jobId = req.params.jobId;
      const db = await storage.getDb();
      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));

      if (!job || job.employerId !== req.user.id) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found"));
      }

      await db.delete(jobsTable).where(eq(jobsTable.id, jobId));

      return res.json({ message: "Job deleted successfully" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PATCH /api/employer/jobs/:jobId/archive - allow employers to archive/unarchive their own jobs
  app.patch("/api/employer/jobs/:jobId/archive", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user?.role !== "employer") {
        return res
          .status(403)
          .json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can archive their job postings"));
      }

      const jobId = req.params.jobId;
      const db = await storage.getDb();
      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));

      if (!job || job.employerId !== req.user.id) {
        return res
          .status(404)
          .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Job not found"));
      }

      const archivedFlag = typeof req.body?.archived === "boolean" ? req.body.archived : true;
      const nowIso = new Date().toISOString();

      const [updated] = await db
        .update(jobsTable)
        .set({
          archived: archivedFlag,
          archivedAt: archivedFlag ? nowIso : null,
          updatedAt: nowIso,
        })
        .where(eq(jobsTable.id, jobId))
        .returning();

      return res.json({
        message: archivedFlag ? "Job archived" : "Job unarchived",
        job: formatJobTimestamps(updated),
      });
    } catch (error) {
      return sendError(res, error);
    }
  });


  // GET /api/jobs/archived - Get all archived jobs (from jobsTable only)
  app.get("/api/jobs/archived", async (_req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      // Get archived jobs from jobsTable
      const archivedJobs = await db.select().from(jobsTable).where(eq(jobsTable.archived, true));
      const combinedArchived = (archivedJobs || []).map((j: any) => ({
        ...formatJobTimestamps(j),
        type: 'job',
        title: j.positionTitle,
        employerName: j.establishmentName || j.employerName || j.companyName || j.company || '',
        location: j.barangay || j.municipality || j.province || j.location || '',
      })).map(mapJobToTableShape);
      res.json({ jobs: combinedArchived });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/jobs/:jobId/match - AI-powered applicant matching for a job
  app.get("/api/jobs/:jobId/match", authMiddleware, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.jobId;
      const minScore = parseInt(req.query.minScore as string) || 50;
      const maxResults = parseInt(req.query.maxResults as string) || Infinity; // No limit - show all qualified
      const includeInsights = String(req.query.includeInsights).toLowerCase() === "true";

      const parseBool = (value: unknown) => {
        if (typeof value !== "string") return undefined;
        const normalized = value.trim().toLowerCase();
        if (["true", "1", "yes", "y", "on"].includes(normalized)) return true;
        if (["false", "0", "no", "n", "off"].includes(normalized)) return false;
        return undefined;
      };

      // Backward compatible default: if useAI isn't provided, keep legacy behavior
      // (AI only runs when includeInsights=true). Client can pass useAI=true to enable AI scoring.
      const useAIParam = parseBool(req.query.useAI);
      const useAI = typeof useAIParam === "boolean" ? useAIParam : includeInsights;

      const allowedWeightKeys = [
        "skillsMatch",
        "educationMatch",
        "locationMatch",
        "salaryMatch",
        "availabilityMatch",
        "experienceMatch",
        "demographicMatch",
      ] as const;

      const parseWeights = (value: unknown) => {
        if (typeof value !== "string" || value.trim() === "") return undefined;
        try {
          const parsed = JSON.parse(value);
          if (!parsed || typeof parsed !== "object") return undefined;
          const sanitized: Record<string, number> = {};
          for (const key of allowedWeightKeys) {
            const v = (parsed as any)[key];
            if (typeof v === "number" && Number.isFinite(v)) {
              sanitized[key] = v;
            }
          }
          return Object.keys(sanitized).length > 0 ? sanitized : undefined;
        } catch {
          return undefined;
        }
      };

      const weights = parseWeights(req.query.weights);

      const db = await storage.getDb();
      
      // Get job from jobsTable (unified jobs)
      console.log(`[GET /api/jobs/:jobId/match] requested id=`, jobId, `minScore=`, minScore, `maxResults=`, maxResults);
      let [jobRow] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      let job = jobRow ? serializeJob(jobRow) : undefined;
      let jobTitle = job?.title;

      if (!job) {
        console.warn(`[GET /api/jobs/:jobId/match] job not found:`, jobId);
        return res.status(404).json({ error: "Job not found" });
      }

      // Get all applicant accounts (exclude admins/employers and archived)
      const applicantRows = await db.select().from(usersTable);
      const applicants = (applicantRows || []).filter((row: any) => {
        const role = String(row?.role || "").toLowerCase();
        if (row?.archived) return false;
        return role === "jobseeker" || role === "freelancer";
      });
      
      const responseSkeleton = {
        jobId,
        jobTitle: jobTitle || job?.title || "Job",
        matches: [] as any[],
        total: 0,
        criteria: {
          minScore,
          maxResults: Number.isFinite(maxResults) ? maxResults : 0,
        },
      };

      if (!applicants || applicants.length === 0) {
        return res.json(responseSkeleton);
      }

      const { aiJobMatcher } = await import("./ai-job-matcher");
      const matches = await aiJobMatcher.matchApplicantsToJob(applicants as any, job as any, {
        minScore,
        maxResults,
        useAI,
        includeInsights,
        weights,
      });

      return res.json({
        ...responseSkeleton,
        matches,
        total: matches.length,
        criteria: {
          minScore,
          maxResults: Number.isFinite(maxResults) ? maxResults : matches.length,
        },
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/jobs/:jobId/applicant/:applicantId/ai-insights - Get AI insights for specific applicant
  app.get("/api/jobs/:jobId/applicant/:applicantId/ai-insights", authMiddleware, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.jobId;
      const applicantId = req.params.applicantId;

      // Simple in-memory cache to avoid repeated LLM calls on refresh/spam clicks
      const cacheKey = `${jobId}:${applicantId}`;
      const now = Date.now();
      (globalThis as any).__aiInsightsCache = (globalThis as any).__aiInsightsCache || new Map();
      const cache: Map<string, { expiresAt: number; data: any }> = (globalThis as any).__aiInsightsCache;
      const cached = cache.get(cacheKey);
      if (cached && cached.expiresAt > now) {
        return res.json(cached.data);
      }

      const db = await storage.getDb();
      
      // Get job details
      let [jobRow] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      let job = jobRow ? serializeJob(jobRow) : undefined;

      if (!job) {
        return res.status(404).json({ error: "Job not found" });
      }

      // Get applicant details
      const [applicant] = await db.select().from(usersTable).where(eq(usersTable.id, applicantId));
      
      if (!applicant) {
        return res.status(404).json({ error: "Applicant not found" });
      }

      // Import AI matcher and get insights
      const { aiJobMatcher } = await import("./ai-job-matcher");
      
      console.log(`[AI Insights] Generating for ${applicant.firstName} ${applicant.surname} ? ${job.title}`);
      
      const matchResult = await aiJobMatcher.matchApplicantsToJob(
        [applicant] as any,
        job as any,
        { minScore: 0, maxResults: 1, useAI: true, includeInsights: true }
      );

      if (matchResult.length === 0) {
        return res.status(404).json({ error: "No match result generated" });
      }

      const insights = {
        aiComment: matchResult[0].aiComment,
        whyQualified: matchResult[0].whyQualified,
        hiringRecommendation: matchResult[0].hiringRecommendation,
        potentialRole: matchResult[0].potentialRole,
        developmentAreas: matchResult[0].developmentAreas,
      };

      cache.set(cacheKey, { data: insights, expiresAt: now + 10 * 60 * 1000 });

      console.log(`[AI Insights] ? Generated insights for ${applicant.firstName}`);
      
      res.json(insights);
    } catch (error) {
      console.error("AI insights error:", error);
      return sendError(res, error);
    }
  });

  // POST /api/jobs/:jobId/shortlist - Shortlist applicants for a job
  app.post("/api/jobs/:jobId/shortlist", authMiddleware, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      
      // Only admin or employer can shortlist
      if (user?.role !== "admin" && user?.role !== "employer") {
        return res.status(403).json({ error: "Only admins and employers can shortlist applicants" });
      }

      const jobId = req.params.jobId;
      const { applicantIds } = req.body;

      if (!applicantIds || !Array.isArray(applicantIds) || applicantIds.length === 0) {
        return res.status(400).json({ error: "applicantIds array is required and must not be empty" });
      }

      const db = await storage.getDb();

      // Get job details for notifications
      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      
      if (!job) {
        return res.status(404).json({ error: "Job not found" });
      }

      // If employer, verify they own the job
      if (user?.role === "employer" && job.employerId !== user.id) {
        return res.status(403).json({ error: "You can only shortlist applicants for your own job postings" });
      }

      const now = new Date();
      const shortlistedApplicants: any[] = [];
      const errors: any[] = [];

      // Process each applicant
      for (const applicantId of applicantIds) {
        try {
          // Check if application exists
          const [existingApp] = await db
            .select()
            .from(applicationsTable)
            .where(
              and(
                eq(applicationsTable.jobId, jobId),
                eq(applicationsTable.applicantId, applicantId)
              )
            )
            .limit(1);

          if (!existingApp) {
            // Create application if it doesn't exist
            const [applicant] = await db.select().from(usersTable).where(eq(usersTable.id, applicantId));
            
            if (!applicant) {
              errors.push({ applicantId, error: "Applicant not found" });
              continue;
            }

            const applicantName = (
              (applicant as any)?.name ||
              `${(applicant as any)?.firstName ?? ""} ${(applicant as any)?.surname ?? ""}`.trim() ||
              "Applicant"
            ).trim();

            const [newApp] = await db
              .insert(applicationsTable)
              .values({
                jobId,
                employerId: job.employerId || null,
                applicantId,
                applicantName,
                status: "shortlisted",
                createdAt: now,
                updatedAt: now,
              })
              .returning();

            shortlistedApplicants.push({ applicantId, applicantName, action: "created" });

            // FIX: Use crypto UUID for notification ID to prevent collisions
            const { randomUUID } = await import('crypto');
            await db.insert(notificationsTable).values({
              id: `notif_${randomUUID()}`,
              userId: applicantId,
              role: null,
              type: "application",
              message: `?? Congratulations! You've been shortlisted for "${job.positionTitle}" at ${job.establishmentName || 'the company'}. Please visit the PESO office or request a referral slip to proceed with the next steps.`,
              read: false,
              createdAt: now,
              updatedAt: now,
            } as any);

          } else if (existingApp.status !== "shortlisted") {
            // Update existing application to shortlisted
            await db
              .update(applicationsTable)
              .set({ status: "shortlisted", updatedAt: now })
              .where(eq(applicationsTable.id, existingApp.id));

            shortlistedApplicants.push({ 
              applicantId, 
              applicantName: existingApp.applicantName, 
              action: "updated",
              previousStatus: existingApp.status 
            });

            // FIX: Only send notification when status actually changes
            const { randomUUID } = await import('crypto');
            await db.insert(notificationsTable).values({
              id: `notif_${randomUUID()}`,
              userId: applicantId,
              role: null,
              type: "application",
              message: `?? Congratulations! You've been shortlisted for "${job.positionTitle}" at ${job.establishmentName || 'the company'}. Please visit the PESO office or request a referral slip to proceed with the next steps.`,
              read: false,
              createdAt: now,
              updatedAt: now,
            } as any);

          } else {
            // FIX: Already shortlisted - don't send duplicate notification
            shortlistedApplicants.push({ 
              applicantId, 
              applicantName: existingApp.applicantName, 
              action: "already_shortlisted" 
            });
          }
        } catch (error: any) {
          errors.push({ applicantId, error: error.message || "Unknown error" });
        }
      }

      // Send notification to employer
      if (job.employerId) {
        const shortlistedCount = shortlistedApplicants.filter(
          a => a.action === "created" || a.action === "updated"
        ).length;

        if (shortlistedCount > 0) {
          // FIX: Truncate long applicant lists to prevent notification overflow
          const newlyShortlisted = shortlistedApplicants
            .filter(a => a.action === "created" || a.action === "updated");
          
          const firstThree = newlyShortlisted.slice(0, 3).map(a => a.applicantName);
          const remaining = newlyShortlisted.length - 3;
          
          const applicantsList = remaining > 0
            ? `${firstThree.join(", ")} and ${remaining} other${remaining > 1 ? 's' : ''}`
            : firstThree.join(", ");

          const { randomUUID } = await import('crypto');
          await db.insert(notificationsTable).values({
            id: `notif_${randomUUID()}`,
            userId: job.employerId,
            role: null,
            type: "application",
            message: `${shortlistedCount} candidate${shortlistedCount > 1 ? 's have' : ' has'} been shortlisted for "${job.positionTitle}": ${applicantsList}`,
            read: false,
            createdAt: now,
            updatedAt: now,
          } as any);
        }
      }

      return res.json({
        message: `Successfully processed ${shortlistedApplicants.length} applicant(s)`,
        shortlisted: shortlistedApplicants,
        errors: errors.length > 0 ? errors : undefined,
        summary: {
          total: applicantIds.length,
          successful: shortlistedApplicants.length,
          failed: errors.length,
          created: shortlistedApplicants.filter(a => a.action === "created").length,
          updated: shortlistedApplicants.filter(a => a.action === "updated").length,
          alreadyShortlisted: shortlistedApplicants.filter(a => a.action === "already_shortlisted").length,
        }
      });
    } catch (error) {
      console.error("Shortlist error:", error);
      return sendError(res, error);
    }
  });

  // PATCH /api/jobs/:jobId/unarchive - Unarchive a job posting or vacancy
  app.patch("/api/jobs/:jobId/unarchive", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const jobId = req.params.jobId;
      const db = await storage.getDb();
      const now = new Date();

      const [existing] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));
      if (!existing) {
        return res.status(404).json({ error: "Job not found" });
      }

      await db
        .update(jobsTable)
        .set({ archived: false, archivedAt: null, updatedAt: now })
        .where(eq(jobsTable.id, jobId));

      const [updated] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId));

      return res.json({
        message: "Job unarchived successfully",
        job: formatJobTimestamps(updated),
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('getTime')) {
        try {
          const fallback = new Date();
          const db = await storage.getDb();
          await db
            .update(jobsTable)
            .set({ archived: false, archivedAt: null, updatedAt: fallback })
            .where(eq(jobsTable.id, req.params.jobId));
          const [updated] = await db.select().from(jobsTable).where(eq(jobsTable.id, req.params.jobId));
          return res.json({ message: "Job unarchived successfully", job: formatJobTimestamps(updated) });
        } catch (inner) {
          return sendError(res, inner);
        }
      }
      return sendError(res, error);
    }
  });

  // POST /api/jobs/:jobId/apply - Apply to a job
  app.post("/api/jobs/:jobId/apply", authMiddleware, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (user?.role !== "jobseeker" && user?.role !== "freelancer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only jobseekers can apply to jobs"));
      }

      const body = req.body || {};
      const parsed = jobApplicationPayloadSchema.safeParse(body);
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        return sendValidationError(res, issue?.message || "Invalid application payload", issue?.path?.[0] as string | undefined);
      }

      const jobId = req.params.jobId || body.jobId;
      const coverLetter = parsed.data.coverLetter || "";

      if (!jobId) {
        return res.status(400).json(createErrorResponse(ErrorCodes.MISSING_FIELD, "Job ID is required", "jobId"));
      }

      const db = await storage.getDb();
      const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, jobId)).limit(1);

      if (!job) {
        return res.status(404).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, "Job not found", "jobId"));
      }

      const [applicant] = await db.select().from(usersTable).where(eq(usersTable.id, user.id)).limit(1);
      const applicantName = (
        (applicant as any)?.name ||
        `${(applicant as any)?.firstName ?? ""} ${(applicant as any)?.surname ?? ""}`.trim() ||
        user?.name ||
        ""
      ).trim() || "Jobseeker";
      const now = new Date();

      // Check if user has already applied or has been shortlisted for this job
      const existingApplication = await db
        .select()
        .from(applicationsTable)
        .where(and(eq(applicationsTable.jobId, jobId), eq(applicationsTable.applicantId, user.id)))
        .limit(1);

      if (existingApplication.length > 0) {
        const status = existingApplication[0].status?.toLowerCase() || 'pending';
        
        // CRITICAL FIX: Allow shortlisted applicants to formally apply (update with cover letter)
        if (status === 'shortlisted') {
          // Update existing shortlisted application with cover letter and keep shortlisted status
          const updatedAt = new Date();
          await db
            .update(applicationsTable)
            .set({ 
              coverLetter, 
              updatedAt,
              // Keep shortlisted status - they're confirming interest, not starting over
            })
            .where(eq(applicationsTable.id, existingApplication[0].id));
          
          return res.status(200).json({
            message: "Your application details have been updated successfully",
            application: {
              ...existingApplication[0],
              coverLetter,
              updatedAt: updatedAt.toISOString(),
            },
            note: "You remain shortlisted for this position. The employer will contact you soon."
          });
        }
        
        // Block other terminal states
        let message = "You have already applied to this job";
        
        if (status === 'hired' || status === 'accepted') {
          message = "You have already been hired for this position.";
        } else if (status === 'rejected') {
          message = "Your previous application for this job was not successful.";
        } else if (status === 'interview') {
          message = "You have an interview scheduled for this position.";
        } else if (status === 'pending' || status === 'reviewed') {
          message = "You have already applied to this job. Your application is being reviewed.";
        }
        
        return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, message));
      }

      const [inserted] = await db
        .insert(applicationsTable)
        .values({
          jobId,
          employerId: job.employerId || null,
          applicantId: user.id,
          applicantName,
          status: "pending",
          coverLetter,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      return res.status(201).json({
        message: "Application submitted successfully",
        application: inserted,
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/jobseeker/applications - Get jobseeker's applications
  app.get("/api/jobseeker/applications", authMiddleware, async (req: Request, res: Response) => {
    try {
      if ((req.user as any)?.role !== "jobseeker" && (req.user as any)?.role !== "freelancer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only jobseekers can view their applications"));
      }

      const db = await storage.getDb();
      const applications = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.applicantId, (req.user as any)?.id));

      const jobIdSet = new Set<string>(
        applications
          .map((app: any) => app.jobId)
          .filter((id: string | undefined | null): id is string => Boolean(id))
      );
      const jobIds = Array.from(jobIdSet);

      let jobsMap = new Map<string, any>();
      if (jobIds.length > 0) {
        const relatedJobs = await db
          .select()
          .from(jobsTable)
          .where(inArray(jobsTable.id, jobIds));
        jobsMap = new Map(relatedJobs.map((job: any) => [job.id, serializeJob(job)]));
      }

      const enriched = applications.map((application: any) => ({
        ...application,
        job: application.jobId ? jobsMap.get(application.jobId) || null : null,
      }));

      res.json(enriched);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/jobseeker/dashboard - Get jobseeker dashboard stats
  app.get("/api/jobseeker/dashboard", authMiddleware, async (req: Request, res: Response) => {
    try {
      if ((req.user as any)?.role !== "jobseeker" && (req.user as any)?.role !== "freelancer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Access denied"));
      }

      const db = await storage.getDb();
      const applications = await db.query.applicationsTable.findMany({
        where: (table: any) => eq(table.applicantId, (req.user as any)?.id),
      });

      const [applicant] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, (req.user as any)?.id));
      const profileCompleteness = applicant ? computeProfileCompleteness(applicant as any) : 0;

      const stats = {
        totalApplications: applications.length,
        pendingApplications: applications.filter((a: any) => a.status === "pending").length,
        shortlistedApplications: applications.filter((a: any) => a.status === "shortlisted").length,
        acceptedApplications: applications.filter((a: any) => a.status === "accepted").length,
        rejectedApplications: applications.filter((a: any) => a.status === "rejected").length,
        profileCompleteness,
        recommendedJobs: [],
      };

      return res.json(stats);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/jobseeker/profile-image - Upload or update profile image
  app.post("/api/jobseeker/profile-image", authMiddleware, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (user?.role !== "jobseeker" && user?.role !== "freelancer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Access denied"));
      }

      const image = req.body?.image;
      if (typeof image !== "string" || image.trim().length === 0) {
        return sendValidationError(res, "Image data is required", "image");
      }

      const imageUrl = await storage.saveJobseekerProfileImage(user.id, req.body);
      return res.json({ imageUrl });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // POST /api/jobseeker/change-password - Change or set password
  app.post("/api/jobseeker/change-password", authMiddleware, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (user?.role !== "jobseeker" && user?.role !== "freelancer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Access denied"));
      }

      const payload = changePasswordSchema.parse(req.body || {});
      const result = await storage.changeJobseekerPassword(
        user.id,
        payload.currentPassword || "",
        payload.newPassword
      );

      if (!result.success) {
        return res
          .status(400)
          .json(createErrorResponse(ErrorCodes.INVALID_CREDENTIALS, result.message));
      }

      return res.json(result);
    } catch (error) {
      if (error instanceof Error) {
        return res.status(400).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, error.message));
      }
      return sendError(res, error);
    }
  });

  // GET /api/employer/applications - List applications for the employer's jobs
  app.get("/api/employer/applications", authMiddleware, async (req: Request, res: Response) => {
    try {
      const user = req.user as any;
      if (user?.role !== "employer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can view applications"));
      }

      const db = await storage.getDb();
      const jobs = await db
        .select()
        .from(jobsTable)
        .where(eq(jobsTable.employerId, user.id));

      if (!jobs || jobs.length === 0) {
        return res.json([]);
      }

      const jobIds = jobs.map((j: any) => j.id).filter(Boolean);
      const applications = await db
        .select()
        .from(applicationsTable)
        .where(inArray(applicationsTable.jobId, jobIds));

      const applicantIds = applications
        .map((a: any) => a.applicantId)
        .filter((id: string | null | undefined): id is string => Boolean(id));

      const applicants = applicantIds.length
        ? await db
            .select()
            .from(usersTable)
            .where(inArray(usersTable.id, applicantIds))
        : [];

      const applicantMap = new Map(applicants.map((a: any) => [a.id, a]));
      const jobMap = new Map(jobs.map((job: any) => [job.id, serializeJob(job)]));

      const result = applications.map((app: any) => {
        const applicant = app.applicantId ? applicantMap.get(app.applicantId) : null;
        const name = (
          (applicant as any)?.name ||
          `${(applicant as any)?.firstName ?? ""} ${(applicant as any)?.surname ?? ""}`.trim() ||
          app.applicantName ||
          "Applicant"
        ).trim();

        const status = typeof app.status === "string" ? app.status.toLowerCase() : "pending";

        return {
          id: app.id,
          jobId: app.jobId,
          status,
          notes: app.notes || app.feedback || "",
          coverLetter: app.coverLetter || (app as any).cover_letter || "",
          createdAt: toIsoString(app.createdAt || (app as any).created_at) || new Date().toISOString(),
          applicant: applicant
            ? {
                id: (applicant as any).id,
                name: name || "Applicant",
                email: (applicant as any).email || null,
                phone: (applicant as any).contactNumber || (applicant as any).phone || null,
              }
            : {
                id: app.applicantId || "",
                name: name || "Applicant",
              },
          job: jobMap.get(app.jobId) || null,
        };
      });

      return res.json(result);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/employer/dashboard - Get employer dashboard stats
  app.get("/api/employer/dashboard", authMiddleware, async (req: Request, res: Response) => {
    try {
      if ((req.user as any)?.role !== "employer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Access denied"));
      }

      const db = await storage.getDb();
      const jobs = await db.query.jobsTable.findMany({
        where: (table: any) => eq(table.employerId, (req.user as any)?.id),
      });

      const jobIds = jobs.map((j: any) => j.id);
      const allApplications = await db.query.applicationsTable.findMany();
      const myApplications = allApplications.filter((a: any) => jobIds.includes(a.jobId));

      const stats = {
        totalJobPostings: jobs.filter((j: any) => !j.archived).length,
        activeJobPostings: jobs.filter((j: any) => j.status === "active" && !j.archived).length,
        totalApplications: myApplications.length,
        pendingApplications: myApplications.filter((a: any) => a.status === "pending").length,
        shortlistedCandidates: myApplications.filter((a: any) => a.status === "shortlisted").length,
        hiredCandidates: myApplications.filter((a: any) => a.status === "accepted").length,
        recentApplications: myApplications.slice(0, 10),
      };

      return res.json(stats);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // PUT /api/employer/applications/:id - Update application status
  app.put("/api/employer/applications/:id", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user.role !== "employer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can update applications"));
      }

      const applicationId = req.params.id;
      const parsed = employerApplicationUpdateSchema.safeParse(req.body || {});
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        return sendValidationError(res, issue?.message || "Invalid application payload", issue?.path?.[0] as string | undefined);
      }
      const { status, notes } = parsed.data;

      const db = await storage.getDb();
      const now = new Date();

      // Get the application details first
      const [application] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.id, applicationId))
        .limit(1);

      if (!application) {
        return res.status(404).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, "Application not found"));
      }

      // VALIDATION: Check if status transition is allowed
      const currentStatus = application.status?.toLowerCase() || APPLICATION_STATUS.PENDING;
      const newStatus = status.toLowerCase();
      
      if (!canTransitionStatus(currentStatus, newStatus)) {
        return res.status(400).json(
          createErrorResponse(
            ErrorCodes.INVALID_FORMAT, 
            `Invalid status transition from "${currentStatus}" to "${newStatus}"`,
            "status"
          )
        );
      }

      // Update application status
      await db
        .update(applicationsTable)
        .set({
          status,
          notes: notes || null,
          updatedAt: now,
        })
        .where(eq(applicationsTable.id, applicationId));

      // Create a polite message to the applicant when hired/rejected (shows in Messages page)
      if (
        application.applicantId &&
        currentStatus !== newStatus &&
        (newStatus === APPLICATION_STATUS.HIRED || newStatus === APPLICATION_STATUS.REJECTED)
      ) {
        try {
          const [job] = await db
            .select()
            .from(jobsTable)
            .where(eq(jobsTable.id, application.jobId))
            .limit(1);

          const jobTitle = (job as any)?.positionTitle || (job as any)?.title || "the position";
          const company = (job as any)?.establishmentName;
          const companyPart = company ? ` at ${company}` : "";

          const [applicantUser] = await db
            .select({ role: usersTable.role })
            .from(usersTable)
            .where(eq(usersTable.id, application.applicantId))
            .limit(1);

          const receiverRoleRaw = (applicantUser as any)?.role;
          const receiverRole = receiverRoleRaw === "freelancer" ? "freelancer" : "jobseeker";

          const applicantName = application.applicantName || "there";
          const employerNotes = (notes || "").trim();

          const subject = newStatus === APPLICATION_STATUS.HIRED
            ? `Application Update: Hired${company ? ` - ${company}` : ""}`
            : `Application Update: Not Selected${company ? ` - ${company}` : ""}`;

          const content = newStatus === APPLICATION_STATUS.HIRED
            ? [
                `Hi ${applicantName},`,
                "",
                `Thank you for applying for \"${jobTitle}\"${companyPart}. We’re happy to inform you that you have been selected for the position.`,
                "",
                "Next steps:",
                "- Please reply to this message to confirm your availability and preferred contact number.",
                "- Prepare your requirements (resume, valid IDs, and other documents that may be requested).",
                "- If instructed, you may visit the PESO office to assist with processing and guidance.",
                "",
                employerNotes ? `Employer note: ${employerNotes}` : undefined,
                "",
                "Congratulations, and we wish you success in your new role.",
              ].filter(Boolean).join("\n")
            : [
                `Hi ${applicantName},`,
                "",
                `Thank you for your interest in \"${jobTitle}\"${companyPart}. After reviewing applications, we will not be moving forward with your application at this time.`,
                "",
                employerNotes ? `Feedback from the employer: ${employerNotes}` : undefined,
                "",
                "Suggestions to improve your chances next time:",
                "- Update your resume and highlight the most relevant skills/experience for the role.",
                "- Consider trainings or certifications related to the job you are applying for.",
                "- Keep applying to other openings on GensanWorks—many opportunities are posted regularly.",
                "- If you need assistance, you may also visit the PESO office for guidance on employment and requirements.",
                "",
                "We appreciate your effort and encourage you to apply again.",
              ].filter(Boolean).join("\n");

          const { messagesTable } = await import("./unified-schema");
          const { randomUUID } = await import("crypto");
          const messageId = `msg_${randomUUID()}`;

          const [newMessage] = await db
            .insert(messagesTable)
            .values({
              id: messageId,
              senderId: req.user.id,
              senderRole: "employer",
              receiverId: application.applicantId,
              receiverRole,
              subject,
              content,
              isRead: false,
              createdAt: now,
              updatedAt: now,
            } as any)
            .returning();

          try {
            const { notifyNewMessage } = await import("./websocket");
            notifyNewMessage(application.applicantId, newMessage);
          } catch (wsError) {
            console.error("Failed to broadcast new message:", wsError);
          }
        } catch (msgError) {
          console.error("Failed to create applicant decision message:", msgError);
        }
      }

      // Notify applicant when hired
      if (
        application.applicantId &&
        currentStatus !== APPLICATION_STATUS.HIRED &&
        newStatus === APPLICATION_STATUS.HIRED
      ) {
        try {
          const [job] = await db
            .select()
            .from(jobsTable)
            .where(eq(jobsTable.id, application.jobId))
            .limit(1);

          const jobTitle = (job as any)?.positionTitle || (job as any)?.title || "the position";
          const company = (job as any)?.establishmentName;

          const { randomUUID } = await import("crypto");
          await db.insert(notificationsTable).values({
            id: `notif_${randomUUID()}`,
            userId: application.applicantId,
            role: null,
            type: "application",
            message: `Congratulations! You have been hired for "${jobTitle}"${company ? ` at ${company}` : ""}.`,
            read: false,
            createdAt: now,
            updatedAt: now,
          } as any);
        } catch (notifError) {
          console.error("Failed to create hire notification:", notifError);
        }
      }

      // Notify applicant when rejected (short notification)
      if (
        application.applicantId &&
        currentStatus !== APPLICATION_STATUS.REJECTED &&
        newStatus === APPLICATION_STATUS.REJECTED
      ) {
        try {
          const [job] = await db
            .select()
            .from(jobsTable)
            .where(eq(jobsTable.id, application.jobId))
            .limit(1);

          const jobTitle = (job as any)?.positionTitle || (job as any)?.title || "the position";
          const company = (job as any)?.establishmentName;

          const { randomUUID } = await import("crypto");
          await db.insert(notificationsTable).values({
            id: `notif_${randomUUID()}`,
            userId: application.applicantId,
            role: null,
            type: "application",
            message: `Application update: You were not selected for \"${jobTitle}\"${company ? ` at ${company}` : ""}.`,
            read: false,
            createdAt: now,
            updatedAt: now,
          } as any);
        } catch (notifError) {
          console.error("Failed to create rejection notification:", notifError);
        }
      }

      // Sync applicant employment status based on application status using constants
      if (application.applicantId) {
        try {
          const newEmploymentStatus = mapApplicationToEmploymentStatus(status);

          if (newEmploymentStatus) {
            // Update employment status in users table
            await db
              .update(usersTable)
              .set({
                employmentStatus: newEmploymentStatus,
                updatedAt: now,
              })
              .where(eq(usersTable.id, application.applicantId));
            
            console.log(`✅ Updated applicant ${application.applicantId} employment status to ${newEmploymentStatus}`);
          }
        } catch (empError) {
          console.error('Failed to update applicant employment status:', empError);
        }
      }

      // Sync with referral record if this application was created from a referral
      if (applicationId.startsWith('app_ref_')) {
        try {
          const referralId = applicationId.replace('app_ref_', '');
          const [referral] = await db
            .select()
            .from(referralsTable)
            .where(eq(referralsTable.referralId, referralId))
            .limit(1);

          if (referral) {
            // Use constants for consistent status mapping
            const referralStatus = mapApplicationToReferralStatus(status);

            await db
              .update(referralsTable)
              .set({
                status: referralStatus,
                feedback: notes || referral.feedback,
                updatedAt: now,
              })
              .where(eq(referralsTable.referralId, referralId));

            // Notify admins when a referred applicant is not hired (include feedback)
            if (newStatus === APPLICATION_STATUS.REJECTED) {
              try {
                const [job] = await db
                  .select()
                  .from(jobsTable)
                  .where(eq(jobsTable.id, application.jobId))
                  .limit(1);

                const jobTitle = (job as any)?.positionTitle || (job as any)?.title || referral.vacancy || "the position";
                const company = (job as any)?.establishmentName || referral.employer;
                const applicantLabel = referral.applicant || application.applicantName || application.applicantId;
                const feedbackText = (notes || referral.feedback || "").trim();

                const { randomUUID } = await import("crypto");
                await db.insert(notificationsTable).values({
                  id: `notif_${randomUUID()}`,
                  userId: null,
                  role: "admin",
                  type: "referral",
                  message: `Referral update: ${applicantLabel} was not hired for \"${jobTitle}\"${company ? ` at ${company}` : ""}.${feedbackText ? ` Feedback: ${feedbackText}` : ""}`,
                  read: false,
                  createdAt: now,
                  updatedAt: now,
                } as any);
              } catch (adminNotifError) {
                console.error("Failed to create admin referral rejection notification:", adminNotifError);
              }
            }
          }
        } catch (refError) {
          console.error('Failed to update referral status:', refError);
        }
      }

      return res.json({ message: "Application status updated successfully" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/employer/applications/:id - Delete an application
  app.delete("/api/employer/applications/:id", authMiddleware, async (req: any, res: Response) => {
    try {
      if (req.user.role !== "employer") {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "Only employers can delete applications"));
      }

      const applicationId = req.params.id;
      const db = await storage.getDb();

      // Verify the application exists and belongs to one of the employer's jobs
      const [application] = await db
        .select()
        .from(applicationsTable)
        .where(eq(applicationsTable.id, applicationId))
        .limit(1);

      if (!application) {
        return res.status(404).json(createErrorResponse(ErrorCodes.INVALID_FORMAT, "Application not found"));
      }

      // Verify employer owns the job
      const [job] = await db
        .select()
        .from(jobsTable)
        .where(eq(jobsTable.id, application.jobId))
        .limit(1);

      if (!job || job.employerId !== req.user.id) {
        return res.status(403).json(createErrorResponse(ErrorCodes.FORBIDDEN, "You can only delete applications for your own jobs"));
      }

      // Delete the application
      await db
        .delete(applicationsTable)
        .where(eq(applicationsTable.id, applicationId));

      return res.json({ message: "Application deleted successfully" });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // ============ ADMIN STAKEHOLDER MANAGEMENT ROUTES ============

  // GET /api/admin/stakeholders - Get all users (jobseekers, employers)
  app.get("/api/admin/stakeholders", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const { role, search, limit = "20", offset = "0" } = req.query;

      const db = await storage.getDb();
      
      // Get jobseekers/freelancers from applicants table
      const applicants = await db.query.usersTable.findMany({
        where: (table: any) => eq(table.hasAccount, true),
      });
      
      // Get employers from employers table
      const employers = await db.query.employersTable.findMany({
        where: (table: any) => eq(table.hasAccount, true),
      });

      // Combine and format
      let users = [
        ...applicants.map((a: any) => ({
          id: a.id,
          name: `${a.firstName} ${a.surname}`,
          email: a.email,
          role: a.role,
          createdAt: a.createdAt,
        })),
        ...employers.map((e: any) => ({
          id: e.id,
          name: e.establishmentName,
          email: e.email,
          role: "employer",
          company: e.establishmentName,
          createdAt: e.createdAt,
        }))
      ];

      // Apply role filter
      if (role && role !== "all") {
        users = users.filter((u: any) => u.role === role);
      }

      // Apply search filter
      if (search) {
        const searchLower = (search as string).toLowerCase();
        users = users.filter((u: any) =>
          u.name?.toLowerCase().includes(searchLower) ||
          u.email?.toLowerCase().includes(searchLower) ||
          u.company?.toLowerCase().includes(searchLower)
        );
      }

      // Apply pagination
      const limitNum = parseInt(limit as string);
      const offsetNum = parseInt(offset as string);
      const paginatedUsers = users.slice(offsetNum, offsetNum + limitNum);

      return res.json({
        users: paginatedUsers,
        total: users.length,
        limit: limitNum,
        offset: offsetNum,
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/admin/applicants - Get all NSRP applicants with filtering
  app.get("/api/admin/applicants", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const { employmentStatus, barangay, employmentType, search, registeredFrom, registeredTo, sortBy = "createdAt", sortOrder = "desc", limit = "20", offset = "0" } = req.query;

      const db = await storage.getDb();
      let applicants = await db.query.usersTable.findMany();

      // Apply filters
      if (employmentStatus) {
        applicants = applicants.filter((a: any) => a.employmentStatus === employmentStatus);
      }

      if (barangay) {
        applicants = applicants.filter((a: any) => a.barangay === barangay);
      }

      if (employmentType) {
        applicants = applicants.filter((a: any) => a.employmentType === employmentType);
      }

      if (registeredFrom || registeredTo) {
        applicants = applicants.filter((a: any) => {
          if (!a.createdAt) return false;
          const created = new Date(a.createdAt);
          if (registeredFrom && created < new Date(registeredFrom as string)) return false;
          if (registeredTo && created > new Date(registeredTo as string)) return false;
          return true;
        });
      }

      if (search) {
        const searchLower = (search as string).toLowerCase();
        applicants = applicants.filter((a: any) =>
          a.firstName?.toLowerCase().includes(searchLower) ||
          a.surname?.toLowerCase().includes(searchLower) ||
          a.email?.toLowerCase().includes(searchLower)
        );
      }

      // Apply pagination
      // Sort applicants
      if (sortBy && typeof sortBy === 'string') {
        applicants = applicants.sort((a: any, b: any) => {
          let aValue = a[sortBy as keyof typeof a];
          let bValue = b[sortBy as keyof typeof b];
          // If sorting by date, convert to Date
          if (sortBy.toLowerCase().includes('date') || sortBy === 'createdAt') {
            aValue = aValue ? new Date(aValue) : new Date(0);
            bValue = bValue ? new Date(bValue) : new Date(0);
          }
          if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
          if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
          return 0;
        });
      }

      const limitNum = parseInt(limit as string);
      const offsetNum = parseInt(offset as string);
      const paginatedApplicants = applicants.slice(offsetNum, offsetNum + limitNum);
      const serializedApplicants = paginatedApplicants.map(mapApplicantToTableShape);

      return res.json({
        applicants: serializedApplicants,
        total: applicants.length,
        limit: limitNum,
        offset: offsetNum,
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/admin/employers - Get all employers with filtering
  app.get("/api/admin/employers", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const { industryType, municipality, search, limit = "20", offset = "0" } = req.query;
      const includeArchived = req.query.includeArchived === "true";

      const db = await storage.getDb();
      let employers = await db.query.employersTable.findMany();

      // Default behavior: only show non-archived employers.
      // Some admin UIs (like the Employers Management page) can request archived too.
      if (!includeArchived) {
        employers = employers.filter((e: any) => !e.archived);
      }

      // Apply filters
      if (industryType) {
        employers = employers.filter((e: any) =>
          e.industryType?.includes(industryType as string)
        );
      }

      if (municipality) {
        employers = employers.filter((e: any) => e.municipality === municipality);
      }

      if (search) {
        const searchLower = (search as string).toLowerCase();
        employers = employers.filter((e: any) =>
          e.establishmentName?.toLowerCase().includes(searchLower) ||
          e.email?.toLowerCase().includes(searchLower)
        );
      }

      // Apply pagination
      const limitNum = parseInt(limit as string);
      const offsetNum = parseInt(offset as string);
      // Admin employers page needs full employer payload (requirements + document metadata) for compliance UI and preview/download.
      const paginatedEmployers = employers.slice(offsetNum, offsetNum + limitNum).map(serializeEmployerRow);

      return res.json({
        employers: paginatedEmployers,
        total: employers.length,
        limit: limitNum,
        offset: offsetNum,
      });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // ===== Employer management endpoints (shared by admin UI + public selectors) =====

  // PATCH /api/employers/:id/requirements/submit-all - mark all compliance requirements as submitted
  app.patch("/api/employers/:id/requirements/submit-all", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const employerId = req.params.id;
      const db = await storage.getDb();
      const employer = await db.query.employersTable.findFirst({
        where: (table: typeof employersTable) => eq(table.id, employerId),
      });

      if (!employer) {
        return res.status(404).json({ error: "Employer not found" });
      }

      const serialized = serializeEmployerRow(employer);
      const seeded = mergeEmployerRequirements(employer.requirements, deriveEmployerRequirements(serialized));

      const updated: Record<string, any> = {};
      Object.entries(seeded || {}).forEach(([key, value]) => {
        const base = value && typeof value === "object" ? value : {};
        updated[key] = { ...base, submitted: true };
      });

      await db
        .update(employersTable)
        .set({ requirements: updated })
        .where(eq(employersTable.id, employerId));

      return res.json({ success: true, requirements: updated });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Lightweight employer listing for dropdowns, optionally including archived records
  app.get("/api/employers", async (req: Request, res: Response) => {
    try {
      const includeArchived = req.query.includeArchived === "true";
      const limit = req.query.limit ? Number(req.query.limit) : undefined;
      const db = await storage.getDb();
      let employers = await db.select().from(employersTable);
      if (!includeArchived) {
        employers = employers.filter((e: any) => !e.archived);
      }
      if (limit && Number.isFinite(limit)) {
        employers = employers.slice(0, limit);
      }
      const normalized = employers.map(serializeEmployerRow).map(mapEmployerToTableShape);
      return res.json(normalized);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Duplicate checker used by the admin create form
  app.post("/api/employers/check-duplicate", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const normalized = normalizeEmployerInput(req.body);
      const establishmentName = normalized.establishmentName?.trim().toLowerCase();
      const tin = sanitizeTin(normalized.companyTIN || normalized.companyTin);

      if (!establishmentName && !tin) {
        return sendValidationError(res, "Establishment name or company TIN is required", "establishmentName");
      }

      const db = await storage.getDb();
      const candidates = await db.select().from(employersTable);
      const duplicate = candidates.find((emp: any) => {
        const matchesName = establishmentName
          ? emp.establishmentName?.trim().toLowerCase() === establishmentName
          : false;
        const matchesTin = tin ? sanitizeTin(emp.companyTin) === tin : false;
        return matchesName || matchesTin;
      });

      if (duplicate) {
        return res.json({
          isDuplicate: true,
          message: `"${duplicate.establishmentName}" already exists in the registry`,
        });
      }

      return res.json({ isDuplicate: false });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // File upload endpoint for employer documents (accessible to both admins and employers)
  app.post("/api/upload/employer-docs", authMiddleware, uploadEmployerDocs.fields([
    { name: "srsFormFile", maxCount: 1 },
    { name: "businessPermitFile", maxCount: 1 },
    { name: "bir2303File", maxCount: 1 },
    { name: "companyProfileFile", maxCount: 1 },
    { name: "doleCertificationFile", maxCount: 1 },
  ]), async (req: Request, res: Response) => {
    try {
      const files = req.files as { [fieldname: string]: Express.Multer.File[] };
      const fileMetadata: Record<string, any> = {};

      if (files) {
        for (const [fieldName, fileArray] of Object.entries(files)) {
          if (fileArray && fileArray[0]) {
            fileMetadata[fieldName] = await formatEmployerDocMetadata(fileArray[0]);
          }
        }
      }

      return res.json({ files: fileMetadata });
    } catch (error: any) {
      console.error("File upload error:", error);
      return res.status(500).json({ error: error.message || "File upload failed" });
    }
  });

  // Static file serving for uploaded documents (local-disk mode only)
  if (!process.env.SUPABASE_STORAGE_BUCKET) {
    app.use("/uploads/employer-documents", express.static(path.join(process.cwd(), "uploads", "employer-documents")));
  }

  // Create a new employer (SRS Form 2) with file uploads
  app.post("/api/employers", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const prepared = prepareEmployerPayload(req.body);
      const payload = employerCreateSchema.parse(prepared);
      const db = await storage.getDb();
      const [created] = await db.insert(employersTable).values(buildEmployerInsert(payload)).returning();
      return res.status(201).json({ employer: serializeEmployerRow(created) });
    } catch (error: any) {
      if (error?.name === "ZodError") {
        const message = error?.issues?.[0]?.message || error.message || "Invalid employer payload";
        return sendValidationError(res, message);
      }
      return sendError(res, error);
    }
  });

  // Get archived employers list for management UI
  app.get("/api/employers/archived", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const archived = await db.select().from(employersTable).where(eq(employersTable.archived, true));
      return res.json({ employers: archived.map(serializeEmployerRow) });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Bulk delete employers
  app.post("/api/employers/bulk-delete", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter(Boolean) : [];
      if (ids.length === 0) {
        return sendValidationError(res, "At least one employer id is required", "ids");
      }
      const db = await storage.getDb();
      await db.delete(employersTable).where(inArray(employersTable.id, ids));
      return res.json({ deleted: ids.length });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Fetch a single employer record
  app.get("/api/employers/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const employer = await db.query.employersTable.findFirst({ where: (table: typeof employersTable) => eq(table.id, req.params.id) });
      if (!employer) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }
      return res.json(serializeEmployerRow(employer));
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Update an employer
  app.put("/api/employers/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const existing = await db
        .query.employersTable
        .findFirst({ where: (table: typeof employersTable) => eq(table.id, req.params.id) });

      if (!existing) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }

      const prepared = prepareEmployerPayload(req.body, existing);
      const payload = employerUpdateSchema.parse({ ...prepared, id: req.params.id });
      const [updated] = await db
        .update(employersTable)
        .set(buildEmployerUpdate(payload))
        .where(eq(employersTable.id, req.params.id))
        .returning();

      if (!updated) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }

      return res.json({ employer: serializeEmployerRow(updated) });
    } catch (error: any) {
      if (error?.name === "ZodError") {
        console.error("[Employer Update] Validation failed", error.issues, req.body);
        const message = error?.issues?.[0]?.message || error.message || "Invalid employer payload";
        return sendValidationError(res, message);
      }
      return sendError(res, error);
    }
  });

  // Toggle archive flag
  // Approve employer account (allow job posting)
  app.patch("/api/employers/:id/approve", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const now = new Date();
      const [updated] = await (await storage.getDb())
        .update(employersTable)
        .set({ 
          accountStatus: "active", 
          reviewedBy: (req as any).user?.id || "admin",
          reviewedAt: now,
          rejectionReason: null,
          updatedAt: now 
        })
        .where(eq(employersTable.id, req.params.id))
        .returning();

      if (!updated) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }

      return res.json({ employer: serializeEmployerRow(updated) });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Reject employer account
  app.patch("/api/employers/:id/reject", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const { reason } = req.body as { reason?: string };
      const now = new Date();
      const [updated] = await (await storage.getDb())
        .update(employersTable)
        .set({ 
          accountStatus: "rejected", 
          reviewedBy: (req as any).user?.id || "admin",
          reviewedAt: now,
          rejectionReason: reason || null,
          updatedAt: now 
        })
        .where(eq(employersTable.id, req.params.id))
        .returning();

      if (!updated) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }

      return res.json({ employer: serializeEmployerRow(updated) });
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.patch("/api/employers/:id/archive", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const { archived } = req.body as { archived?: boolean };
      if (typeof archived !== "boolean") {
        return sendValidationError(res, "archived flag must be boolean", "archived");
      }
      const now = new Date();
      const [updated] = await (await storage.getDb())
        .update(employersTable)
        .set({ archived, archivedAt: archived ? now : null, updatedAt: now })
        .where(eq(employersTable.id, req.params.id))
        .returning();

      if (!updated) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }

      return res.json({ employer: serializeEmployerRow(updated) });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Delete a single employer
  app.delete("/api/employers/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const deleted = await db.delete(employersTable).where(eq(employersTable.id, req.params.id)).returning();
      if (!deleted || deleted.length === 0) {
        return res.status(404).json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "Employer not found"));
      }
      return res.json({ success: true });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // GET /api/admin/dashboard - Get comprehensive admin dashboard stats
  app.get("/api/admin/dashboard", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const db = await storage.getDb();
      
      let applicants = await db.query.usersTable.findMany();
      let employers = await db.query.employersTable.findMany();
      let jobs = await db.query.jobsTable.findMany();
      let applications = await db.query.applicationsTable.findMany();

      // Apply date range filtering if provided
      if (startDate && endDate) {
        const start = new Date(startDate + 'T00:00:00.000Z');
        const end = new Date(endDate + 'T23:59:59.999Z');
        
        applicants = applicants.filter((a: any) => {
          if (!a.createdAt) return false;
          const created = new Date(a.createdAt);
          return created >= start && created <= end;
        });
        
        employers = employers.filter((e: any) => {
          if (!e.createdAt) return false;
          const created = new Date(e.createdAt);
          return created >= start && created <= end;
        });
        
        jobs = jobs.filter((j: any) => {
          if (!j.createdAt) return false;
          const created = new Date(j.createdAt);
          return created >= start && created <= end;
        });
        
        applications = applications.filter((app: any) => {
          if (!app.createdAt) return false;
          const created = new Date(app.createdAt);
          return created >= start && created <= end;
        });
      }

      const jobseekersWithAccounts = applicants.filter((a: any) => a.hasAccount && a.role === "jobseeker");
      const freelancersWithAccounts = applicants.filter((a: any) => a.hasAccount && a.role === "freelancer");
      const employersWithAccounts = employers.filter((e: any) => e.hasAccount);

      const stats = {
        totalUsers: jobseekersWithAccounts.length + freelancersWithAccounts.length + employersWithAccounts.length,
        totalJobseekers: jobseekersWithAccounts.length,
        totalFreelancers: freelancersWithAccounts.length,
        totalEmployers: employersWithAccounts.length,
        totalApplicants: applicants.length,
        totalEmployerEstablishments: employers.length,
        // FIX: Exclude archived jobs from total count
        totalJobs: jobs.filter((j: any) => !j.archived).length,
        // FIX: Only count active (non-archived) jobs
        activeJobs: jobs.filter((j: any) => j.status === "active" && !j.archived).length,
        totalApplications: applications.length,
        pendingApplications: applications.filter((a: any) => a.status === "pending").length,
        // NEW: Add shortlisted and hired metrics
        shortlistedApplications: applications.filter((a: any) => a.status === "shortlisted").length,
        hiredApplicants: applications.filter((a: any) => a.status === "hired").length,
        interviewScheduled: applications.filter((a: any) => a.status === "interview").length,
        rejectedApplications: applications.filter((a: any) => a.status === "rejected").length,
        recentActivity: [], // TODO: Implement activity log
      };

      return res.json(stats);
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.get("/api/admin/system-alerts", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    return res.json({ alerts: validationAlerts });
  });

  // DELETE /api/admin/users/:id - Delete a user (admin only)
  app.delete("/api/admin/users/:id", authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const userId = req.params.id;
      const db = await storage.getDb();

      // Try deleting from applicants first
      const deletedApplicant = await db.delete(usersTable).where(eq(usersTable.id, userId));
      
      // If not found in applicants, try employers
      if (!deletedApplicant) {
        await db.delete(employersTable).where(eq(employersTable.id, userId));
      }

      return res.json({ message: "User deleted successfully" });
    } catch (error) {
      return sendError(res, error);
    }
  });
  
    // DELETE /api/account - Jobseeker self-service account deletion
    app.delete("/api/account", authMiddleware, async (req: Request, res: Response) => {
      try {
        // `authMiddleware` should attach a user object on `req`. Be defensive in case
        // it's missing or has different shape in some environments. Cast to a
        // lightweight local type so TypeScript can narrow safely.
        type AuthUser = { id: string; role?: string } | undefined;
        const user = (req.user as unknown) as AuthUser;

        if (!user || user.role !== "jobseeker") {
          return res.status(403).json({ error: "Only jobseekers can delete their own account" });
        }
        const userId = user.id;
        const db = await storage.getDb();
        const deletedApplicant = await db.delete(usersTable).where(eq(usersTable.id, userId));
        if (!deletedApplicant) {
          return res.status(404).json({ error: "Applicant not found" });
        }
        // Optionally: log out, clean up sessions, etc.
        return res.json({ message: "Account deleted successfully" });
      } catch (error) {
        return sendError(res, error);
      }
    });

  // PUT /api/admin/users/:id/suspend - Not implemented (no suspended flag in schema)
  app.put("/api/admin/users/:id/suspend", authMiddleware, adminOnly, async (_req: Request, res: Response) => {
    return res
      .status(501)
      .json({ error: "Suspend/activate not implemented. No suspended flag in schema." });
  });

  // Get impact metrics and statistics
  app.get("/api/public/impact", async (_req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      
      const applicants = await db.query.usersTable.findMany();
      const applications = await db.query.applicationsTable.findMany();
      
      // Calculate average time to first interview (simulate with created dates)
      const avgTimeToInterview = "48 hrs"; // Can be calculated from application data
      
      // Calculate average salary from applicants' expected salary
      let totalSalary = 0;
      let salaryCount = 0;
      
      applicants.forEach((applicant: any) => {
        let education: any[] = [];
        if (applicant.education) {
          try {
            education = JSON.parse(applicant.education);
            if (!Array.isArray(education)) education = [];
          } catch (e) {
            education = [];
          }
        }
        education.forEach((edu: any) => {
          if (edu.expectedSalary) {
            const salary = parseInt(edu.expectedSalary);
            if (!isNaN(salary)) {
              totalSalary += salary;
              salaryCount++;
            }
          }
        });
      });
      
      const avgSalary = salaryCount > 0 ? Math.round(totalSalary / salaryCount / 1000) : 32;
      
      // Calculate satisfaction rate (based on successful applications)
      const successfulApps = applications.filter((app: any) => 
        app.status === 'hired' || app.status === 'accepted'
      ).length;
      const satisfactionRate = applications.length > 0 
        ? Math.round((successfulApps / applications.length) * 100) 
        : 94.5;
      
      res.json({
        avgTimeToInterview,
        avgSalary: `?${avgSalary}K`,
        satisfactionRate: `${satisfactionRate}%`,
        yearsOfService: 25
      });
    } catch (error) {
      console.error("Failed to fetch impact data:", error);
      res.status(500).json({ error: "Failed to fetch impact data" });
    }
  });

  // ============ DASHBOARD DATA ROUTES (keep existing) ============

  app.get("/api/summary", async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const data = await storage.getSummaryData(startDate, endDate);
      
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch summary data" });
    }
  });

  app.get("/api/recent-activities", async (_req: Request, res: Response) => {
    try {
      const activities = await storage.getRecentActivities();
      res.json(activities);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch recent activities" });
    }
  });


  // ================= NOTIFICATIONS + SSE =================
  const sseClients: Response[] = [];

  function broadcastNotification(event: string, payload: any) {
    const data = JSON.stringify(payload);
    sseClients.forEach((res) => {
      try {
        res.write(`event: ${event}\n`);
        res.write(`data: ${data}\n\n`);
      } catch {}
    });
  }

  // SSE stream
  app.get('/api/notifications/stream', authMiddleware, (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();
    res.write('retry: 10000\n\n');
    sseClients.push(res);
    req.on('close', () => {
      const idx = sseClients.indexOf(res);
      if (idx >= 0) sseClients.splice(idx, 1);
    });
  });

  // GET notifications from DB
  app.get('/api/notifications', authMiddleware, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const user = (req as any).user;
      const role = user?.role;
      const userId = user?.id;

      console.log('[GET /api/notifications] User ID:', userId, 'Role:', role);

      // Fetch notifications targeted to this user or role (or global role=null/userId=null)
      const rows = await db.select().from(notificationsTable);
      
      console.log('[GET /api/notifications] Total notifications in DB:', rows.length);
      console.log('[GET /api/notifications] Sample notification:', rows[0]);

      const filtered = rows.filter((n: any) => {
        const userIdMatch = n.userId && userId && n.userId === userId;
        const roleMatch = n.role && role && n.role === role;
        const isGlobal = !n.userId && !n.role;
        
        if (userIdMatch) {
          console.log('[MATCH] userId:', n.userId, '===', userId);
          return true;
        }
        if (roleMatch) {
          console.log('[MATCH] role:', n.role, '===', role);
          return true;
        }
        if (isGlobal) {
          console.log('[MATCH] Global notification');
          return true;
        }
        return false;
      }).sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

      console.log('[GET /api/notifications] Filtered count:', filtered.length);

      // If empty, return empty by default.
      // (Optional) enable sample seeding for demos/dev via SEED_NOTIFICATIONS=true
      if (filtered.length === 0) {
        const shouldSeed = process.env.SEED_NOTIFICATIONS === 'true';
        if (shouldSeed) {
          const now = new Date();
          const seed = [
            { id: `seed_${Date.now()}_1`, userId: null, role, type: 'system', message: 'Welcome! Notifications are now live.', read: false, createdAt: now, updatedAt: now },
          ];
          for (const s of seed) {
            await db.insert(notificationsTable).values(s as any);
          }
          broadcastNotification('seed', seed);
          return res.json(seed);
        }

        return res.json([]);
      }

      res.json(filtered);
    } catch (e) {
      console.error('Failed fetching notifications', e);
      res.status(500).json({ error: 'Failed to fetch notifications' });
    }
  });

  // POST create notification (admin only for now)
  app.post('/api/notifications', authMiddleware, adminOnly, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      const { role, userId, type, message } = req.body;
      if (!message) return res.status(400).json({ error: 'Message required' });
      const now = new Date().toISOString();
      const notif = { id: `notif_${Date.now()}_${Math.random().toString(36).slice(2,8)}`, role: role || null, userId: userId || null, type: type || 'system', message, read: false, createdAt: now, updatedAt: now };
      await db.insert(notificationsTable).values(notif as any);
      broadcastNotification('new', notif);
      res.status(201).json(notif);
    } catch (e) {
      console.error('Failed creating notification', e);
      res.status(500).json({ error: 'Failed to create notification' });
    }
  });

  // PATCH mark as read (scoped to owner/role/global/admin)
  app.patch('/api/notifications/:id/read', authMiddleware, async (req: Request, res: Response) => {
    try {
      const { id } = notificationReadSchema.parse({ id: req.params.id });
      const db = await storage.getDb();
      const user = (req as any).user;
      const role = user?.role;
      const userId = user?.id;

      const existing = await db
        .select()
        .from(notificationsTable)
        .where(eq(notificationsTable.id, id))
        .limit(1);

      const notif = existing[0];
      if (!notif) {
        return res.status(404).json({ error: 'Notification not found' });
      }

      const isOwner = !!notif.userId && !!userId && notif.userId === userId;
      const matchesRole = !notif.userId && !!notif.role && !!role && notif.role === role;
      const isGlobal = !notif.userId && !notif.role;
      const isAdmin = role === 'admin';

      if (!(isOwner || matchesRole || isGlobal || isAdmin)) {
        return res.status(403).json({ error: 'Not allowed to modify this notification' });
      }

      await db
        .update(notificationsTable)
        .set({ read: true, updatedAt: new Date() })
        .where(eq(notificationsTable.id, id));

      broadcastNotification('read', { id, read: true });
      res.json({ id, read: true });
    } catch (e) {
      console.error('Failed marking notification read', e);
      res.status(500).json({ error: 'Failed to mark notification read' });
    }
  });

  // DELETE notification (scoped to owner/role/global/admin)
  app.delete('/api/notifications/:id', authMiddleware, async (req: Request, res: Response) => {
    try {
      const { id } = notificationReadSchema.parse({ id: req.params.id });
      const db = await storage.getDb();
      const user = (req as any).user;
      const role = user?.role;
      const userId = user?.id;

      const existing = await db
        .select()
        .from(notificationsTable)
        .where(eq(notificationsTable.id, id))
        .limit(1);

      const notif = existing[0];
      if (!notif) {
        return res.status(404).json({ error: 'Notification not found' });
      }

      const isOwner = !!notif.userId && !!userId && notif.userId === userId;
      const matchesRole = !notif.userId && !!notif.role && !!role && notif.role === role;
      const isGlobal = !notif.userId && !notif.role;
      const isAdmin = role === 'admin';

      if (!(isOwner || matchesRole || isGlobal || isAdmin)) {
        return res.status(403).json({ error: 'Not allowed to delete this notification' });
      }

      await db
        .delete(notificationsTable)
        .where(eq(notificationsTable.id, id));

      broadcastNotification('delete', { id });
      res.json({ id, deleted: true });
    } catch (e) {
      console.error('Failed deleting notification', e);
      res.status(500).json({ error: 'Failed to delete notification' });
    }
  });

  app.get("/api/charts/bar", async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const data = await storage.getBarChartData(startDate, endDate);
      
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch bar chart data" });
    }
  });

  app.get("/api/charts/doughnut", async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const data = await storage.getDoughnutChartData(startDate, endDate);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch doughnut chart data" });
    }
  });

  app.get("/api/charts/line", async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const data = await storage.getLineChartData(startDate, endDate);
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch line chart data" });
    }
  });

  // GET /api/charts/employment-status
  app.get("/api/charts/employment-status", async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const db = await storage.getDb();
      if (!db) {
        return res.json({
          employed: 0,
          unemployed: 0,
          selfEmployed: 0,
          newEntrant: 0,
        });
      }

      // Fetch all applicants from database
      let applicants = await db.query.usersTable.findMany();
      
      // Filter by date range if provided
      if (startDate && endDate) {
        const start = new Date(startDate + 'T00:00:00.000Z');
        const end = new Date(endDate + 'T23:59:59.999Z');
        
        applicants = applicants.filter((app: any) => {
          const createdDate = app.createdAt ? new Date(app.createdAt) : null;
          return createdDate && createdDate >= start && createdDate <= end;
        });
      }
      
      // Initialize counters
      let employed = 0;
      let wageEmployed = 0;
      let unemployed = 0;
      let selfEmployed = 0;
      let newEntrant = 0;

      // Count by employment status (match all variations)
      applicants.forEach((applicant: any) => {
        const bucket = classifyEmploymentStatus(applicant);
        if (!bucket) {
          return;
        }

        if (bucket === 'employed') {
          wageEmployed++;
          employed++;
        } else if (bucket === 'unemployed') {
          unemployed++;
        } else if (bucket === 'selfEmployed') {
          selfEmployed++;
          employed++;
        } else if (bucket === 'newEntrant') {
          newEntrant++;
          unemployed++;
        }
      });

      res.json({
        employed,
        wageEmployed,
        unemployed,
        selfEmployed,
        newEntrant,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch employment status data" });
    }
  });

  app.post("/api/referrals", authMiddleware, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      if (!db) return res.status(500).json({ error: "Database unavailable" });

      const body = req.body || {};
      const referralId = body.referralId || body.referralSlipNumber || `ref_${Date.now()}`;
      const statusInput = (body.status || "Pending").toString().trim();
      const normalizedStatus = statusInput.charAt(0).toUpperCase() + statusInput.slice(1).toLowerCase();
      const now = new Date();

      // Resolve employer name/id from job/employer tables when the client payload is missing it.
      const firstNonEmpty = (...vals: any[]) => vals.find((v) => typeof v === "string" && v.trim().length > 0);
      let resolvedEmployerId = body.employerId || null;
      let resolvedEmployerName = typeof body.employer === "string" && body.employer.trim().length > 0 ? body.employer : null;

      // Look up the job to backfill employer info.
      if ((!resolvedEmployerId || !resolvedEmployerName) && body.vacancyId) {
        const [job] = await db.select().from(jobsTable).where(eq(jobsTable.id, body.vacancyId));
        if (job) {
          resolvedEmployerId = resolvedEmployerId || job.employerId || job.employer_id || null;
          resolvedEmployerName =
            resolvedEmployerName ||
            firstNonEmpty(
              job.establishmentName,
              job.companyName as any,
              job.employerName as any,
              job.tradeName as any,
              job.positionTitle as any // last resort to avoid "Unspecified"
            ) || null;
        }
      }

      // If still missing name but we have an employerId, fetch employer details.
      if (!resolvedEmployerName && resolvedEmployerId) {
        const [employer] = await db.select().from(employersTable).where(eq(employersTable.id, resolvedEmployerId));
        if (employer) {
          resolvedEmployerName = firstNonEmpty(
            employer.establishmentName,
            employer.companyName,
            employer.name,
            employer.contactPerson,
            employer.tradeName,
            employer.id
          ) || null;
        }
      }

      if (!body.applicantId || !body.applicant || !body.vacancyId || !body.vacancy) {
        return res.status(400).json({ error: "Missing required fields: applicantId, applicant, vacancyId, vacancy" });
      }

      const record = {
        referralId,
        applicantId: body.applicantId,
        applicant: body.applicant,
        employerId: resolvedEmployerId,
        employer: resolvedEmployerName,
        vacancyId: body.vacancyId,
        vacancy: body.vacancy,
        barangay: body.barangay || null,
        jobCategory: body.jobCategory || null,
        dateReferred: body.dateReferred || now.toISOString(),
        status: normalizedStatus,
        feedback: body.feedback || "",
        referralSlipNumber: body.referralSlipNumber || referralId,
        pesoOfficerName: body.pesoOfficerName || null,
        pesoOfficerDesignation: body.pesoOfficerDesignation || null,
        updatedAt: now,
        createdAt: now,
      };

      const existing = await db.select().from(referralsTable).where(eq(referralsTable.referralId, referralId));

      if (existing?.length) {
        await db
          .update(referralsTable)
          .set(record)
          .where(eq(referralsTable.referralId, referralId));
        return res.status(200).json(record);
      }

      await db.insert(referralsTable).values(record);

      // Also create an application record so it appears in employer applications page
      try {
        const applicationId = `app_ref_${referralId}`;
        const existingApp = await db.select().from(applicationsTable).where(eq(applicationsTable.id, applicationId)).limit(1);
        
        if (!existingApp.length) {
          await db.insert(applicationsTable).values({
            id: applicationId,
            jobId: body.vacancyId,
            employerId: resolvedEmployerId,
            applicantId: body.applicantId,
            applicantName: body.applicant,
            status: normalizedStatus.toLowerCase(),
            notes: body.feedback || `Referral: ${referralId}`,
            createdAt: now,
            updatedAt: now,
          });
        }
      } catch (appError) {
        console.error('Failed to create application from referral:', appError);
        // Continue anyway - referral was created successfully
      }

      return res.status(201).json(record);
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.patch("/api/referrals/:referralId/status", authMiddleware, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      if (!db) return res.status(500).json({ error: "Database unavailable" });

      const { referralId } = req.params;
      const { status, feedback } = req.body || {};

      if (!status) return res.status(400).json({ error: "Status is required" });

      const normalizedStatus = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
      const updatedAt = new Date();

      const existing = await db.select().from(referralsTable).where(eq(referralsTable.referralId, referralId));
      if (!existing || existing.length === 0) {
        return res.status(404).json({ error: "Referral not found" });
      }

      // Update the referral status/feedback first
      await db
        .update(referralsTable)
        .set({ status: normalizedStatus, feedback: feedback || "", updatedAt })
        .where(eq(referralsTable.referralId, referralId));

      // Cascade employment status to applicant if currently unset and referral is marked hired
      const referral = existing[0];
      if (normalizedStatus === "Hired" && referral.applicantId) {
        const [applicant] = await db.select().from(usersTable).where(eq(usersTable.id, referral.applicantId));
        const hasStatus = applicant?.employmentStatus && String(applicant.employmentStatus).trim().length > 0;

        if (applicant && !hasStatus) {
          await db
            .update(usersTable)
            .set({ employmentStatus: "Employed", updatedAt })
            .where(eq(usersTable.id, referral.applicantId));
        } else if (!applicant) {
          // Fallback: try users table if applicant record is absent
          const [user] = await db.select().from(usersTable).where(eq(usersTable.id, referral.applicantId));
          const userHasStatus = user?.employmentStatus && String(user.employmentStatus).trim().length > 0;
          if (user && !userHasStatus) {
            await db
              .update(usersTable)
              .set({ employmentStatus: "Employed", updatedAt })
              .where(eq(usersTable.id, referral.applicantId));
          }
        }
      }

      const refreshed = await db.select().from(referralsTable).where(eq(referralsTable.referralId, referralId));

      // Also update the corresponding application status
      try {
        const applicationId = `app_ref_${referralId}`;
        const existingApp = await db.select().from(applicationsTable).where(eq(applicationsTable.id, applicationId)).limit(1);
        
        if (existingApp.length) {
          await db
            .update(applicationsTable)
            .set({
              status: normalizedStatus.toLowerCase(),
              notes: feedback || existingApp[0].notes,
              updatedAt: new Date(),
            })
            .where(eq(applicationsTable.id, applicationId));
        }
      } catch (appError) {
        console.error('Failed to update application from referral:', appError);
        // Continue anyway - referral was updated successfully
      }

      return res.status(200).json(refreshed?.[0] || { referralId, status: normalizedStatus, feedback });
    } catch (error) {
      return sendError(res, error);
    }
  });

  // DELETE /api/referrals/:referralId - remove a referral record
  app.delete("/api/referrals/:referralId", authMiddleware, async (req: Request, res: Response) => {
    try {
      const db = await storage.getDb();
      if (!db) return res.status(500).json({ error: "Database unavailable" });

      const { referralId } = req.params;
      if (!referralId) return res.status(400).json({ error: "referralId is required" });

      const existing = await db.select().from(referralsTable).where(eq(referralsTable.referralId, referralId));
      if (!existing || existing.length === 0) {
        return res.status(404).json({ error: "Referral not found" });
      }

      const referral = existing[0];

      await db.delete(referralsTable).where(eq(referralsTable.referralId, referralId));

      // Cascade delete matching applications for the same applicant + vacancy
      if (referral.applicantId && referral.vacancyId) {
        await db
          .delete(applicationsTable)
          .where(
            and(
              eq(applicationsTable.applicantId, referral.applicantId),
              eq(applicationsTable.jobId, referral.vacancyId)
            )
          );
      }

      return res.status(200).json({ success: true, referralId });
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.get("/api/referrals", authMiddleware, async (req: Request, res: Response) => {
    try {
      const startDate = req.query.startDate as string | undefined;
      const endDate = req.query.endDate as string | undefined;
      
      const filters = referralFiltersSchema.parse({
        barangay: req.query.barangay as string | undefined,
        employer: req.query.employer as string | undefined,
        jobCategory: req.query.jobCategory as string | undefined,
        dateRange: req.query.dateRange as string | undefined,
        status: req.query.status as string | undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string) : undefined,
        offset: req.query.offset ? parseInt(req.query.offset as string) : undefined,
      });

      const db = await storage.getDb();
      
      let referrals: any[] = [];
      referrals = await db.select().from(referralsTable);
      
      // Filter by date range if provided
      if (startDate && endDate) {
        const start = new Date(startDate + 'T00:00:00.000Z');
        const end = new Date(endDate + 'T23:59:59.999Z');
        
        referrals = referrals.filter((ref: any) => {
          const refDate = ref.dateReferred ? new Date(ref.dateReferred) : null;
          return refDate && refDate >= start && refDate <= end;
        });
      }
      
      // Apply status filter if provided
      if (filters.status) {
        referrals = referrals.filter((ref: any) => 
          ref.status?.toLowerCase() === filters.status?.toLowerCase()
        );
      }
      
      // Apply barangay filter if provided
      if (filters.barangay) {
        referrals = referrals.filter((ref: any) => 
          ref.barangay?.toLowerCase() === filters.barangay?.toLowerCase()
        );
      }
      
      // Apply employer filter if provided
      if (filters.employer) {
        referrals = referrals.filter((ref: any) => 
          ref.employer?.toLowerCase().includes(filters.employer?.toLowerCase())
        );
      }
      
      // Apply job category filter if provided
      if (filters.jobCategory) {
        referrals = referrals.filter((ref: any) => 
          ref.jobCategory?.toLowerCase() === filters.jobCategory?.toLowerCase()
        );
      }
      
      // Apply pagination
      const limit = filters.limit || 100;
      const offset = filters.offset || 0;
      // Enrich with applicant, job, and employer details
      const applicantIds = Array.from(new Set(referrals.map((r: any) => r.applicantId).filter(Boolean)));
      const vacancyIds = Array.from(new Set(referrals.map((r: any) => r.vacancyId).filter(Boolean)));
      const employerIdsFromRefs = referrals.map((r: any) => r.employerId).filter(Boolean);

      const applicantsMap: Record<string, any> = {};
      if (applicantIds.length) {
        const applicants = await db.select().from(usersTable).where(inArray(usersTable.id, applicantIds));
        for (const a of applicants) {
          applicantsMap[a.id] = a;
        }
      }

      const jobsMap: Record<string, any> = {};
      if (vacancyIds.length) {
        const jobs = await db.select().from(jobsTable).where(inArray(jobsTable.id, vacancyIds));
        for (const j of jobs) {
          jobsMap[j.id] = j;
        }
      }

      // Collect employerIds from referrals and jobs so we can display real employer names
      const employerIds = Array.from(new Set([
        ...employerIdsFromRefs,
        ...Object.values(jobsMap)
          .map((job: any) => job.employerId || job.employer_id)
          .filter(Boolean),
      ]));

      const employersMap: Record<string, any> = {};
      if (employerIds.length) {
        const employers = await db.select().from(employersTable).where(inArray(employersTable.id, employerIds));
        for (const e of employers) {
          employersMap[e.id] = e;
        }
      }

      const firstNonEmpty = (...vals: any[]) =>
        vals.find((v) => typeof v === "string" && v.trim().length > 0);

      const paginatedReferrals = referrals.slice(offset, offset + limit).map((ref: any) => {
        const applicant = ref.applicantId ? applicantsMap[ref.applicantId] : null;
        const job = ref.vacancyId ? jobsMap[ref.vacancyId] : null;
        const status = ref.status ? ref.status.charAt(0).toUpperCase() + ref.status.slice(1).toLowerCase() : "Pending";

        const employerId = ref.employerId || job?.employerId || job?.employer_id;
        const employer = employerId ? employersMap[employerId] : undefined;
        const employerName =
          firstNonEmpty(
            ref.employer,
            job?.establishmentName,
            employer?.establishmentName,
            employer?.companyName,
            employer?.contactPerson,
            employerId
          ) || "Unknown Employer";

        return {
          ...ref,
          status,
          employer: employerName,
          applicant: applicant
            ? {
                id: applicant.id,
                name: `${applicant.firstName || applicant.name || ""} ${applicant.middleName || ""} ${applicant.surname || applicant.lastName || ""}`.trim(),
                email: applicant.email || applicant.emailAddress || applicant.email_address || null,
                phone: applicant.contactNumber || applicant.phone || applicant.contact_number || null,
              }
            : ref.applicant,
          job: job
            ? {
                id: job.id,
                title: job.positionTitle || job.title || job.position || "Untitled role",
                location: job.locationSummary || job.location || job.barangay || job.municipality || null,
              }
            : undefined,
        };
      });

      // Preserve backward-compatible body shape (array) while still exposing pagination metadata
      res.setHeader("X-Total-Count", referrals.length.toString());
      res.setHeader("X-Limit", limit.toString());
      res.setHeader("X-Offset", offset.toString());
      res.status(200).json(paginatedReferrals);
    } catch (error) {
      return sendError(res, error);
    }
  });

  app.get("/api/notes", authMiddleware, async (req: Request, res: Response) => {
    try {
      const filters = notesFiltersSchema.parse({
        limit: req.query.limit ? parseInt(req.query.limit as string) : undefined,
        offset: req.query.offset ? parseInt(req.query.offset as string) : undefined,
      });

      const db = await storage.getDb();
      const notes = await db.select().from(notesTable);

      const sorted = [...notes].sort(
        (a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );

      const limit = filters.limit || 100;
      const offset = filters.offset || 0;
      const paginated = sorted.slice(offset, offset + limit);

      res.setHeader("X-Total-Count", sorted.length.toString());
      res.setHeader("X-Limit", limit.toString());
      res.setHeader("X-Offset", offset.toString());
      res.json(paginated);
    } catch (error) {
      return sendError(res, error);
    }
  });

  // Fallback so API callers never receive the Vite HTML shell for unknown endpoints
  app.use("/api", (_req: Request, res: Response) =>
    res
      .status(404)
      .json(createErrorResponse(ErrorCodes.RESOURCE_NOT_FOUND, "API endpoint not found"))
  );
}

// End of registerRoutes









