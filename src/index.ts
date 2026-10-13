import { createPasswordManager } from "./password";
import { createTokenManager } from "./tokens";
import { createAuthMiddleware } from "./middleware";
import { loadAuthConfig } from "./config";
import { createOtpManager } from "./otp";
import { createPasswordResetManager } from "./password-reset";
import type { OtpDelivery } from "./delivery";

export { createPasswordManager } from "./password";
export { createTokenManager } from "./tokens";
export { createAuthMiddleware } from "./middleware";
export { loadAuthConfig } from "./config";
export { createOtpManager } from "./otp";
export { createPasswordResetManager } from "./password-reset";
export { createChannelDelivery } from "./delivery";

export type { AuthConfig } from "./config";
export type { PasswordOptions } from "./password";
export type { TokenOptions } from "./tokens";
export type {
  OtpOptions,
  OtpChallenge,
  CreateOtpInput,
  CreateOtpResult,
  VerifyOtpResult,
} from "./otp";
export type {
  OtpChannel,
  OtpPurpose,
  OtpDelivery,
  OtpDeliveryPayload,
} from "./delivery";
export type {
  PasswordResetOptions,
  RequestPasswordResetInput,
  RequestPasswordResetResult,
  ConfirmPasswordResetInput,
  ConfirmPasswordResetResult,
  ConfirmPasswordResetFailure,
} from "./password-reset";

export {
  AuthError,
  ConfigError,
  PasswordError,
  TokenError,
  OtpError,
} from "./errors";

export interface CreateAuthOptions {
  /**
   * Optional SMTP/SMS (or custom) delivery adapter.
   * When provided, `createAuth()` also returns `passwordReset`.
   */
  delivery?: OtpDelivery;
}

export interface CreateAuthOptionsWithDelivery extends CreateAuthOptions {
  delivery: OtpDelivery;
}

export type AuthKit = {
  password: ReturnType<typeof createPasswordManager>;
  tokens: ReturnType<typeof createTokenManager>;
  otp: ReturnType<typeof createOtpManager>;
  middleware: ReturnType<typeof createAuthMiddleware>;
};

export type AuthKitWithDelivery = AuthKit & {
  delivery: OtpDelivery;
  passwordReset: ReturnType<typeof createPasswordResetManager>;
};

export function createAuth(
  options: CreateAuthOptionsWithDelivery
): AuthKitWithDelivery;
export function createAuth(options?: CreateAuthOptions): AuthKit;
export function createAuth(
  options: CreateAuthOptions = {}
): AuthKit | AuthKitWithDelivery {
  const config = loadAuthConfig();

  const password = createPasswordManager({
    rounds: config.bcryptRounds,
  });

  const tokens = createTokenManager({
    accessSecret: config.accessSecret,
    accessExpiresIn: config.accessExpiresIn,
    issuer: config.issuer,
    audience: config.audience,
  });

  const otp = createOtpManager({
    pepper: config.otpPepper ?? config.accessSecret,
    length: config.otpLength,
    expiresInSeconds: config.otpExpiresInSeconds,
    maxAttempts: config.otpMaxAttempts,
  });

  const base: AuthKit = {
    password,
    tokens,
    otp,
    middleware: createAuthMiddleware(tokens),
  };

  if (!options.delivery) {
    return base;
  }

  return {
    ...base,
    delivery: options.delivery,
    passwordReset: createPasswordResetManager({
      otp,
      password,
      delivery: options.delivery,
    }),
  };
}
