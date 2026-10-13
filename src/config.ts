export interface AuthConfig {
  accessSecret: string;
  accessExpiresIn?: number;
  bcryptRounds?: number;
  issuer?: string;
  audience?: string;
  /** Pepper for hashing OTPs. Falls back to accessSecret when unset. */
  otpPepper?: string;
  otpLength?: number;
  otpExpiresInSeconds?: number;
  otpMaxAttempts?: number;
}

export function loadAuthConfig(
  env: NodeJS.ProcessEnv = process.env
): AuthConfig {
  const accessSecret = env.AUTH_ACCESS_SECRET;

  if (!accessSecret || accessSecret.length < 32) {
    throw new Error(
      "AUTH_ACCESS_SECRET must be configured securely"
    );
  }

  const bcryptRounds = Number(env.AUTH_BCRYPT_ROUNDS ?? 12);
  const accessExpiresIn = Number(
    env.AUTH_ACCESS_EXPIRES_SECONDS ?? 900
  );
  const otpPepper = env.AUTH_OTP_PEPPER || accessSecret;
  const otpLength = Number(env.AUTH_OTP_LENGTH ?? 6);
  const otpExpiresInSeconds = Number(
    env.AUTH_OTP_EXPIRES_SECONDS ?? 600
  );
  const otpMaxAttempts = Number(env.AUTH_OTP_MAX_ATTEMPTS ?? 5);

  if (
    !Number.isInteger(bcryptRounds) ||
    bcryptRounds < 10 ||
    bcryptRounds > 15
  ) {
    throw new Error("AUTH_BCRYPT_ROUNDS must be between 10 and 15");
  }

  if (
    !Number.isSafeInteger(accessExpiresIn) ||
    accessExpiresIn <= 0
  ) {
    throw new Error("Invalid access token expiry");
  }

  if (Buffer.byteLength(otpPepper, "utf8") < 32) {
    throw new Error("AUTH_OTP_PEPPER must contain at least 32 bytes");
  }

  if (!Number.isInteger(otpLength) || otpLength < 4 || otpLength > 8) {
    throw new Error("AUTH_OTP_LENGTH must be between 4 and 8");
  }

  if (
    !Number.isSafeInteger(otpExpiresInSeconds) ||
    otpExpiresInSeconds <= 0
  ) {
    throw new Error("Invalid OTP expiry");
  }

  if (!Number.isInteger(otpMaxAttempts) || otpMaxAttempts < 1) {
    throw new Error("AUTH_OTP_MAX_ATTEMPTS must be a positive integer");
  }

  return {
    accessSecret,
    bcryptRounds,
    accessExpiresIn,
    issuer: env.AUTH_ISSUER || undefined,
    audience: env.AUTH_AUDIENCE || undefined,
    otpPepper,
    otpLength,
    otpExpiresInSeconds,
    otpMaxAttempts,
  };
}
