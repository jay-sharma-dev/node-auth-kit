import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import type { OtpChannel, OtpPurpose } from "./delivery";

export interface OtpOptions {
  /** Secret used to HMAC OTP codes before storage. Prefer a dedicated pepper. */
  pepper: string;
  /** OTP length (4–8). Default: 6. */
  length?: number;
  /** Lifetime in seconds. Default: 600 (10 minutes). */
  expiresInSeconds?: number;
  /** Max failed verify attempts. Default: 5. */
  maxAttempts?: number;
}

export interface OtpChallenge {
  otpHash: string;
  purpose: OtpPurpose;
  destination: string;
  channel: OtpChannel;
  expiresAt: Date;
  attemptsRemaining: number;
}

export interface CreateOtpInput {
  destination: string;
  channel: OtpChannel;
  purpose: OtpPurpose;
}

export interface CreateOtpResult {
  /** Plaintext code — send via SMTP/SMS, then discard. */
  code: string;
  /** Persist this in your DB (hashed OTP + metadata). */
  challenge: OtpChallenge;
}

export interface VerifyOtpResult {
  ok: boolean;
  reason?:
    | "expired"
    | "exhausted"
    | "mismatch"
    | "purpose_mismatch"
    | "destination_mismatch";
  /** Always persist the returned challenge (attempts may have decreased). */
  challenge: OtpChallenge;
}

export function createOtpManager(options: OtpOptions) {
  if (
    typeof options.pepper !== "string" ||
    Buffer.byteLength(options.pepper, "utf8") < 32
  ) {
    throw new Error("OTP pepper must contain at least 32 bytes");
  }

  const length = options.length ?? 6;
  const expiresInSeconds = options.expiresInSeconds ?? 600;
  const maxAttempts = options.maxAttempts ?? 5;

  if (!Number.isInteger(length) || length < 4 || length > 8) {
    throw new Error("OTP length must be an integer between 4 and 8");
  }

  if (
    !Number.isSafeInteger(expiresInSeconds) ||
    expiresInSeconds <= 0
  ) {
    throw new Error("Invalid OTP expiry");
  }

  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new Error("OTP maxAttempts must be a positive integer");
  }

  const max = 10 ** length;

  return {
    create(input: CreateOtpInput): CreateOtpResult {
      if (!input.destination?.trim()) {
        throw new Error("OTP destination is required");
      }

      const code = String(randomInt(0, max)).padStart(length, "0");
      const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

      const challenge: OtpChallenge = {
        otpHash: hashOtp(code, options.pepper),
        purpose: input.purpose,
        destination: input.destination.trim(),
        channel: input.channel,
        expiresAt,
        attemptsRemaining: maxAttempts,
      };

      return { code, challenge };
    },

    verify(
      code: string,
      challenge: OtpChallenge,
      expected?: { purpose?: OtpPurpose; destination?: string }
    ): VerifyOtpResult {
      const next: OtpChallenge = {
        ...challenge,
        expiresAt: new Date(challenge.expiresAt),
      };

      if (expected?.purpose && challenge.purpose !== expected.purpose) {
        return { ok: false, reason: "purpose_mismatch", challenge: next };
      }

      if (
        expected?.destination &&
        challenge.destination !== expected.destination.trim()
      ) {
        return {
          ok: false,
          reason: "destination_mismatch",
          challenge: next,
        };
      }

      if (Date.now() > new Date(challenge.expiresAt).getTime()) {
        return { ok: false, reason: "expired", challenge: next };
      }

      if (challenge.attemptsRemaining <= 0) {
        return { ok: false, reason: "exhausted", challenge: next };
      }

      const candidate =
        typeof code === "string" ? code.trim() : "";
      const matches =
        candidate.length === length &&
        safeEqualHash(hashOtp(candidate, options.pepper), challenge.otpHash);

      if (!matches) {
        next.attemptsRemaining = Math.max(0, challenge.attemptsRemaining - 1);
        return { ok: false, reason: "mismatch", challenge: next };
      }

      // Consume the challenge after success so it cannot be reused.
      next.attemptsRemaining = 0;
      return { ok: true, challenge: next };
    },
  };
}

function hashOtp(code: string, pepper: string): string {
  return createHmac("sha256", pepper).update(code).digest("hex");
}

function safeEqualHash(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");

  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(left, right);
}
