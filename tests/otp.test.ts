import { describe, expect, it, vi } from "vitest";
import { createOtpManager } from "../src/otp";
import { createPasswordManager } from "../src/password";
import { createPasswordResetManager } from "../src/password-reset";
import {
  createChannelDelivery,
  type OtpDelivery,
} from "../src/delivery";

const PEPPER = "p".repeat(32);

describe("createOtpManager", () => {
  const otp = createOtpManager({
    pepper: PEPPER,
    length: 6,
    expiresInSeconds: 600,
    maxAttempts: 3,
  });

  it("creates a numeric OTP and verifies it", () => {
    const { code, challenge } = otp.create({
      destination: "user@example.com",
      channel: "email",
      purpose: "password_reset",
    });

    expect(code).toMatch(/^\d{6}$/);
    expect(challenge.otpHash).not.toContain(code);

    const result = otp.verify(code, challenge, {
      purpose: "password_reset",
      destination: "user@example.com",
    });

    expect(result.ok).toBe(true);
    expect(result.challenge.attemptsRemaining).toBe(0);
  });

  it("rejects wrong codes and decrements attempts", () => {
    const { challenge } = otp.create({
      destination: "+15551234567",
      channel: "sms",
      purpose: "password_reset",
    });

    const first = otp.verify("000000", challenge);
    expect(first.ok).toBe(false);
    expect(first.reason).toBe("mismatch");
    expect(first.challenge.attemptsRemaining).toBe(2);
  });

  it("rejects weak peppers", () => {
    expect(() => createOtpManager({ pepper: "short" })).toThrow(
      "OTP pepper must contain at least 32 bytes"
    );
  });

  it("rejects expired OTPs", () => {
    const shortLived = createOtpManager({
      pepper: PEPPER,
      expiresInSeconds: 1,
    });
    const { code, challenge } = shortLived.create({
      destination: "user@example.com",
      channel: "email",
      purpose: "password_reset",
    });

    challenge.expiresAt = new Date(Date.now() - 1000);

    const result = shortLived.verify(code, challenge);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("expired");
  });

  it("rejects after max attempts are exhausted", () => {
    const limited = createOtpManager({
      pepper: PEPPER,
      maxAttempts: 1,
    });
    const { challenge } = limited.create({
      destination: "user@example.com",
      channel: "email",
      purpose: "password_reset",
    });

    const first = limited.verify("000000", challenge);
    expect(first.reason).toBe("mismatch");

    const second = limited.verify("000000", first.challenge);
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("exhausted");
  });

  it("rejects purpose and destination mismatches", () => {
    const { code, challenge } = otp.create({
      destination: "user@example.com",
      channel: "email",
      purpose: "password_reset",
    });

    expect(
      otp.verify(code, challenge, { purpose: "login" }).reason
    ).toBe("purpose_mismatch");

    expect(
      otp.verify(code, challenge, {
        purpose: "password_reset",
        destination: "other@example.com",
      }).reason
    ).toBe("destination_mismatch");
  });
});

describe("createPasswordResetManager", () => {
  it("sends OTP via delivery adapter and confirms reset", async () => {
    const sent: unknown[] = [];
    const delivery: OtpDelivery = {
      async send(payload) {
        sent.push(payload);
      },
    };

    const otp = createOtpManager({ pepper: PEPPER, length: 6 });
    const password = createPasswordManager({ rounds: 10 });
    const reset = createPasswordResetManager({ otp, password, delivery });

    const requested = await reset.requestReset({
      to: "user@example.com",
      channel: "email",
    });

    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      to: "user@example.com",
      channel: "email",
      purpose: "password_reset",
    });

    const code = (sent[0] as { code: string }).code;

    const confirmed = await reset.confirmReset({
      code,
      challenge: requested.challenge,
      newPassword: "NewStrongPass123!",
    });

    expect(confirmed.ok).toBe(true);
    if (confirmed.ok) {
      await expect(
        password.verify("NewStrongPass123!", confirmed.passwordHash)
      ).resolves.toBe(true);
    }
  });

  it("routes email and sms through channel delivery", async () => {
    const emailSend = vi.fn(async () => undefined);
    const smsSend = vi.fn(async () => undefined);

    const delivery = createChannelDelivery({
      email: { send: emailSend },
      sms: { send: smsSend },
    });

    const otp = createOtpManager({ pepper: PEPPER });
    const password = createPasswordManager({ rounds: 10 });
    const reset = createPasswordResetManager({ otp, password, delivery });

    await reset.requestReset({
      to: "user@example.com",
      channel: "email",
    });
    await reset.requestReset({
      to: "+15551234567",
      channel: "sms",
    });

    expect(emailSend).toHaveBeenCalledOnce();
    expect(smsSend).toHaveBeenCalledOnce();
  });

  it("fails confirmReset with a wrong OTP", async () => {
    const delivery: OtpDelivery = {
      async send() {
        /* no-op */
      },
    };
    const otp = createOtpManager({ pepper: PEPPER });
    const password = createPasswordManager({ rounds: 10 });
    const reset = createPasswordResetManager({ otp, password, delivery });

    const requested = await reset.requestReset({
      to: "user@example.com",
      channel: "email",
    });

    const failed = await reset.confirmReset({
      code: "000000",
      challenge: requested.challenge,
      newPassword: "NewStrongPass123!",
    });

    expect(failed.ok).toBe(false);
    if (!failed.ok) {
      expect(failed.reason).toBe("mismatch");
    }
  });

  it("throws when channel adapter is missing", async () => {
    const delivery = createChannelDelivery({
      email: {
        async send() {
          /* no-op */
        },
      },
    });

    await expect(
      delivery.send({
        to: "+15551234567",
        code: "123456",
        purpose: "password_reset",
        channel: "sms",
        expiresAt: new Date(),
      })
    ).rejects.toThrow('No OTP delivery adapter configured for channel "sms"');
  });
});
