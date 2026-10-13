import type { createPasswordManager } from "./password";
import type { createOtpManager, OtpChallenge } from "./otp";
import type {
  OtpChannel,
  OtpDelivery,
  OtpDeliveryPayload,
} from "./delivery";

type PasswordManager = ReturnType<typeof createPasswordManager>;
type OtpManager = ReturnType<typeof createOtpManager>;

export interface PasswordResetOptions {
  otp: OtpManager;
  password: PasswordManager;
  /** Your SMTP and/or SMS adapter. Required to send the OTP. */
  delivery: OtpDelivery;
}

export interface RequestPasswordResetInput {
  /** Email or phone number where the OTP should be delivered. */
  to: string;
  channel: OtpChannel;
  /** Optional extra data passed through to your delivery adapter. */
  meta?: Record<string, unknown>;
}

export interface RequestPasswordResetResult {
  /** Persist this challenge in your DB keyed by user/email/phone. */
  challenge: OtpChallenge;
  /** Echo of delivery metadata (code is NOT returned — already sent). */
  deliveredTo: string;
  channel: OtpChannel;
  expiresAt: Date;
}

export interface ConfirmPasswordResetInput {
  code: string;
  challenge: OtpChallenge;
  newPassword: string;
  /** Expected destination; defaults to challenge.destination. */
  to?: string;
}

export interface ConfirmPasswordResetResult {
  ok: true;
  /** Store this as the user's new password hash. */
  passwordHash: string;
  challenge: OtpChallenge;
}

export interface ConfirmPasswordResetFailure {
  ok: false;
  reason: NonNullable<
    ReturnType<OtpManager["verify"]>["reason"]
  >;
  challenge: OtpChallenge;
}

/**
 * Password-reset helpers built on OTP + your delivery adapter.
 * The package does not talk to SMTP/SMS providers directly.
 */
export function createPasswordResetManager(
  options: PasswordResetOptions
) {
  const { otp, password, delivery } = options;

  return {
    /**
     * Create an OTP challenge, send it via your SMTP/SMS adapter,
     * and return the challenge for DB storage.
     */
    async requestReset(
      input: RequestPasswordResetInput
    ): Promise<RequestPasswordResetResult> {
      const { code, challenge } = otp.create({
        destination: input.to,
        channel: input.channel,
        purpose: "password_reset",
      });

      const payload: OtpDeliveryPayload = {
        to: input.to,
        code,
        purpose: "password_reset",
        channel: input.channel,
        expiresAt: challenge.expiresAt,
        meta: input.meta,
      };

      await delivery.send(payload);

      return {
        challenge,
        deliveredTo: input.to,
        channel: input.channel,
        expiresAt: challenge.expiresAt,
      };
    },

    /**
     * Verify the OTP and hash the new password.
     * On success, persist `passwordHash` and invalidate the stored challenge.
     */
    async confirmReset(
      input: ConfirmPasswordResetInput
    ): Promise<ConfirmPasswordResetResult | ConfirmPasswordResetFailure> {
      const verified = otp.verify(input.code, input.challenge, {
        purpose: "password_reset",
        destination: input.to ?? input.challenge.destination,
      });

      if (!verified.ok) {
        return {
          ok: false,
          reason: verified.reason!,
          challenge: verified.challenge,
        };
      }

      const passwordHash = await password.hash(input.newPassword);

      return {
        ok: true,
        passwordHash,
        challenge: verified.challenge,
      };
    },
  };
}
