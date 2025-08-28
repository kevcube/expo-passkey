/**
 * @file Server-specific type definitions
 * @module expo-passkey/types/server
 */

import { z } from "zod";

/**
 * Schema configuration for the Expo Passkey plugin
 */
export interface ExpoPasskeySchemaConfig {
  passkey?: {
    modelName?: string;
  };
  passkeyChallenge?: {
    modelName?: string;
  };
}

/**
 * Configuration options for the Expo Passkey server plugin
 */
export interface ExpoPasskeyOptions {
  /** Relying Party Name for the passkey */
  rpName: string;

  /** Relying Party ID for the passkey */
  rpId: string;

  /**
   * Expected origins for WebAuthn verification
   * For ios, this is your associated domain, for android this is the SHA-256 hash of the apk signing certificate and is in this format:
   * android:apk-key-hash:{base64url-encoded-hash}
   */
  origin?: string | string[];

  /** Schema configuration for database models */
  schema?: ExpoPasskeySchemaConfig;

  /** Rate limiting configuration */
  rateLimit?: {
    /** Window for registration attempts in seconds */
    registerWindow?: number;
    /** Maximum registration attempts per window */
    registerMax?: number;
    /** Window for authentication attempts in seconds */
    authenticateWindow?: number;
    /** Maximum authentication attempts per window */
    authenticateMax?: number;
  };

  /** Cleanup configuration for old/inactive passkeys */
  cleanup?: {
    /** Number of days after which inactive passkeys are revoked */
    inactiveDays?: number;
    /**
     * Disable the interval for automatically cleaning up inactive passkeys.
     * Set to true for serverless environments.
     * When true, cleanup will still run once on startup but not continuously.
     */
    disableInterval?: boolean;
  };

  /** Logger configuration */
  logger?: {
    enabled?: boolean;
    level?: "debug" | "info" | "warn" | "error";
  };
}

/**
 * Internal configuration with resolved model names
 */
export interface ResolvedSchemaConfig {
  passkeyModel: string;
  passkeyChallengeModel: string;
}

/**
 * Database schema for the passkey model
 */
export const passkeySchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  publicKey: z.string(),
  userId: z.string(),
  credentialID: z.string(),
  counter: z.number().default(0),
  deviceType: z.string(),
  backedUp: z.boolean(),
  transports: z.string().optional(),
  createdAt: z.date(),
  aaguid: z.string().optional(),
});

/**
 * Database schema for the passkeyChallenge model
 */
export const passkeyChallengeSchema = z.object({
  id: z.string(),
  userId: z.string(),
  challenge: z.string(),
  type: z.enum(["registration", "authentication"]),
  createdAt: z.string(),
  expiresAt: z.string(),
  registrationOptions: z.string().optional(), // JSON string containing client registration preferences
});

/** Passkey model type */
export type Passkey = z.infer<typeof passkeySchema>;

/** PasskeyChallenge model type */
export type PasskeyChallenge = z.infer<typeof passkeyChallengeSchema>;
