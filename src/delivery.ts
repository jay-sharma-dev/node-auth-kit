/**
 * Pluggable OTP delivery. Implement this with your SMTP provider,
 * SMS gateway (Twilio, MSG91, etc.), or any custom channel.
 *
 * jay-auth-kit never sends email/SMS itself — your adapter does.
 */

export type OtpChannel = "email" | "sms" | "custom";

export type OtpPurpose =
  | "password_reset"
  | "login"
  | "verify_contact"
  | (string & {});

export interface OtpDeliveryPayload {
  /** Destination: email address or phone number (E.164 recommended for SMS). */
  to: string;
  /** Plaintext OTP — send this once, never store it. */
  code: string;
  purpose: OtpPurpose;
  channel: OtpChannel;
  expiresAt: Date;
  meta?: Record<string, unknown>;
}

export interface OtpDelivery {
  send(payload: OtpDeliveryPayload): Promise<void>;
}

/**
 * Route by channel to email and/or SMS adapters.
 * Useful when the same app supports both SMTP and SMS.
 */
export function createChannelDelivery(options: {
  email?: OtpDelivery;
  sms?: OtpDelivery;
  custom?: OtpDelivery;
}): OtpDelivery {
  return {
    async send(payload) {
      const adapter =
        payload.channel === "email"
          ? options.email
          : payload.channel === "sms"
            ? options.sms
            : options.custom;

      if (!adapter) {
        throw new Error(
          `No OTP delivery adapter configured for channel "${payload.channel}"`
        );
      }

      await adapter.send(payload);
    },
  };
}
