import { describe, expect, it } from "vitest";
import { loadAuthConfig } from "../src/config";

const SECRET = "a".repeat(32);

describe("loadAuthConfig validation", () => {
  it("rejects bcrypt rounds outside 10–15", () => {
    expect(() =>
      loadAuthConfig({
        AUTH_ACCESS_SECRET: SECRET,
        AUTH_BCRYPT_ROUNDS: "9",
      })
    ).toThrow("AUTH_BCRYPT_ROUNDS must be between 10 and 15");

    expect(() =>
      loadAuthConfig({
        AUTH_ACCESS_SECRET: SECRET,
        AUTH_BCRYPT_ROUNDS: "16",
      })
    ).toThrow("AUTH_BCRYPT_ROUNDS must be between 10 and 15");
  });

  it("rejects invalid access token expiry", () => {
    expect(() =>
      loadAuthConfig({
        AUTH_ACCESS_SECRET: SECRET,
        AUTH_ACCESS_EXPIRES_SECONDS: "0",
      })
    ).toThrow("Invalid access token expiry");
  });

  it("rejects invalid OTP length", () => {
    expect(() =>
      loadAuthConfig({
        AUTH_ACCESS_SECRET: SECRET,
        AUTH_OTP_LENGTH: "3",
      })
    ).toThrow("AUTH_OTP_LENGTH must be between 4 and 8");
  });

  it("rejects short OTP pepper", () => {
    expect(() =>
      loadAuthConfig({
        AUTH_ACCESS_SECRET: SECRET,
        AUTH_OTP_PEPPER: "short",
      })
    ).toThrow("AUTH_OTP_PEPPER must contain at least 32 bytes");
  });

  it("loads custom OTP settings", () => {
    const config = loadAuthConfig({
      AUTH_ACCESS_SECRET: SECRET,
      AUTH_OTP_PEPPER: "p".repeat(32),
      AUTH_OTP_LENGTH: "8",
      AUTH_OTP_EXPIRES_SECONDS: "120",
      AUTH_OTP_MAX_ATTEMPTS: "3",
    });

    expect(config.otpPepper).toBe("p".repeat(32));
    expect(config.otpLength).toBe(8);
    expect(config.otpExpiresInSeconds).toBe(120);
    expect(config.otpMaxAttempts).toBe(3);
  });
});
