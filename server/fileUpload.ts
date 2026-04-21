import multer from "multer";
import path from "path";
import fs from "fs";
import { randomBytes } from "crypto";
import { createSupabaseServiceClient, getSupabaseUrl } from "./supabase";

function isSupabaseStorageConfigured(): boolean {
  return Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY && process.env.SUPABASE_STORAGE_BUCKET);
}

// Ensure uploads directory exists (only for local-disk uploads)
const UPLOADS_DIR = path.join(process.cwd(), "uploads");
const EMPLOYER_DOCS_DIR = path.join(UPLOADS_DIR, "employer-documents");

if (!isSupabaseStorageConfigured()) {
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }

  if (!fs.existsSync(EMPLOYER_DOCS_DIR)) {
    fs.mkdirSync(EMPLOYER_DOCS_DIR, { recursive: true });
  }
}

// Storage configuration for employer documents
const employerDocsDiskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, EMPLOYER_DOCS_DIR);
  },
  filename: (_req, file, cb) => {
    // Generate unique filename: timestamp-random-originalname
    const uniqueSuffix = `${Date.now()}-${randomBytes(6).toString("hex")}`;
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    const sanitized = basename.replace(/[^a-zA-Z0-9-_]/g, "_");
    cb(null, `${sanitized}-${uniqueSuffix}${ext}`);
  },
});

const employerDocsMemoryStorage = multer.memoryStorage();

// File filter for documents (PDF, images)
const documentFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedMimes = [
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/gif",
  ];
  
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Invalid file type. Only PDF, JPEG, JPG, PNG, and GIF are allowed."));
  }
};

// Multer upload instance for employer documents
export const uploadEmployerDocs = multer({
  storage: isSupabaseStorageConfigured() ? employerDocsMemoryStorage : employerDocsDiskStorage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size
  },
  fileFilter: documentFilter,
});

// Helper to get file URL
export function getFileUrl(filename: string): string {
  if (isSupabaseStorageConfigured()) {
    const bucket = process.env.SUPABASE_STORAGE_BUCKET as string;
    // Public bucket URL format
    return `${getSupabaseUrl()}/storage/v1/object/public/${bucket}/${filename}`;
  }
  return `/uploads/employer-documents/${filename}`;
}

// Helper to delete a file
export function deleteFile(filepath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(process.cwd(), filepath);
    fs.unlink(fullPath, (err) => {
      if (err && err.code !== "ENOENT") {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

// Helper to format file metadata
export function formatFileMetadata(file: Express.Multer.File) {
  return {
    name: file.originalname,
    filename: file.filename,
    path: getFileUrl(file.filename),
    type: file.mimetype,
    size: file.size,
    uploadedAt: new Date().toISOString(),
  };
}

function buildSupabaseObjectPath(originalname: string) {
  const uniqueSuffix = `${Date.now()}-${randomBytes(6).toString("hex")}`;
  const ext = path.extname(originalname);
  const basename = path.basename(originalname, ext);
  const sanitized = basename.replace(/[^a-zA-Z0-9-_]/g, "_");
  // Keep a folder prefix to stay compatible with existing /uploads/employer-documents mental model.
  return `employer-documents/${sanitized}-${uniqueSuffix}${ext}`;
}

export async function formatEmployerDocMetadata(file: Express.Multer.File) {
  // Local disk upload (multer sets file.filename)
  if (!isSupabaseStorageConfigured()) {
    return formatFileMetadata(file);
  }

  // Supabase storage upload
  const bucket = process.env.SUPABASE_STORAGE_BUCKET as string;
  const supabase = createSupabaseServiceClient();
  const objectPath = buildSupabaseObjectPath(file.originalname);

  const uploadResult = await supabase.storage
    .from(bucket)
    .upload(objectPath, file.buffer, {
      contentType: file.mimetype,
      upsert: false,
    });

  if (uploadResult.error) {
    throw new Error(uploadResult.error.message);
  }

  return {
    name: file.originalname,
    filename: objectPath,
    path: getFileUrl(objectPath),
    type: file.mimetype,
    size: file.size,
    uploadedAt: new Date().toISOString(),
  };
}
