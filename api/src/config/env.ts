import dotenv from 'dotenv';

dotenv.config();

interface EnvConfig {
  apiPort: number;
  mongodbUri: string;
  jwtSecret: string;
  maxFileSize: number;
  analysisTimeout: number;
  frontendPort: number;
}

function required(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const env: EnvConfig = {
  apiPort: Number(required('API_PORT', '5000')),
  mongodbUri: required('MONGODB_URI', 'mongodb://localhost:27017/analyzer'),
  jwtSecret: required('JWT_SECRET', 'dev-secret-change-me'),
  maxFileSize: Number(required('MAX_FILE_SIZE', '10485760')),
  analysisTimeout: Number(required('ANALYSIS_TIMEOUT', '30')),
  frontendPort: Number(required('FRONTEND_PORT', '3000')),
};
