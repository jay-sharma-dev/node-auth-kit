import { afterEach, describe, expect, it } from "vitest";
import { createAuth } from "../src/index";
import type { OtpDelivery } from "../src/delivery";

const SECRET = "c".repeat(32);
const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

function setAuthEnv() {
  process.env.AUTH_ACCESS_SECRET = SECRET;
  process.env.AUTH_ACCESS_EXPIRES_SECONDS = "900";
  process.env.AUTH_BCRYPT_ROUNDS = "10";
  process.env.AUTH_OTP_PEPPER = "o".repeat(32);
  process.env.AUTH_ISSUER = "jay-auth-kit";
  process.env.AUTH_AUDIENCE = "test-api";
  delete process.env.AUTH_OTP_LENGTH;
  delete process.env.AUTH_OTP_EXPIRES_SECONDS;
  delete process.env.AUTH_OTP_MAX_ATTEMPTS;
}

describe("createAuth", () => {
  it("builds password, tokens, otp, and middleware from env", async () => {
    setAuthEnv();

    const auth = createAuth();

    expect(auth.password).toBeDefined();
    expect(auth.tokens).toBeDefined();
    expect(auth.otp).toBeDefined();
    expect(auth.middleware).toBeTypeOf("function");
    expect("passwordReset" in auth).toBe(false);

    const hash = await auth.password.hash("TestPass123!");
    await expect(auth.password.verify("TestPass123!", hash)).resolves.toBe(
      true
    );

    const token = auth.tokens.sign("user-1", "user");
    expect(auth.tokens.verify(token).sub).toBe("user-1");
  });

  it("attaches passwordReset when delivery is provided", async () => {
    setAuthEnv();

    const delivery: OtpDelivery = {
      async send() {
        /* no-op */
      },
    };

    const auth = createAuth({ delivery });

    expect(auth.passwordReset).toBeDefined();
    expect(auth.delivery).toBe(delivery);

    const requested = await auth.passwordReset.requestReset({
      to: "user@example.com",
      channel: "email",
    });

    expect(requested.challenge.purpose).toBe("password_reset");
  });

  it("fails when AUTH_ACCESS_SECRET is missing", () => {
    delete process.env.AUTH_ACCESS_SECRET;

    expect(() => createAuth()).toThrow(
      "AUTH_ACCESS_SECRET must be configured securely"
    );
  });
});
