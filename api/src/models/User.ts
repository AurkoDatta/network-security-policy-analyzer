import { Schema, model, Document } from 'mongoose';

/**
 * Schema only for now — register/login endpoints and password hashing
 * are wired up in Phase 3 (JWT auth). See middleware/auth.ts.
 */
export interface UserDocument extends Document {
  email: string;
  password_hash: string;
  name?: string;
  created_at: Date;
  updated_at: Date;
}

const UserSchema = new Schema<UserDocument>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password_hash: { type: String, required: true, select: false },
    name: { type: String },
  },
  { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } },
);

export const User = model<UserDocument>('User', UserSchema);
