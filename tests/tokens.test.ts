import { describe, expect, it } from "vitest";
import { createTokenManager } from "../src/tokens";
import { loadAuthConfig } from "../src/config";

const SECRET = "a".repeat(32);

describe("createTokenManager", () => {
  const tokens = createTokenManager({
    accessSecret: SECRET,
    accessExpiresIn: 60,
    issuer: "jay-auth-kit",
    audience: "test-api",
  });

  it("signs and verifies an access token", () => {
    const token = tokens.sign("user-123", "admin");
    const payload = tokens.verify(token);

    expect(payload.sub).toBe("user-123");
    expect(payload.role).toBe("admin");
    expect(payload.iss).toBe("jay-auth-kit");
    expect(payload.aud).toBe("test-api");
  });

  it("rejects tokens signed with a different secret", () => {
    const other = createTokenManager({
      accessSecret: "b".repeat(32),
      accessExpiresIn: 60,
    });
    const token = other.sign("user-123");

    expect(() => tokens.verify(token)).toThrow();
  });

  it("rejects expired tokens", () => {
    const shortLived = createTokenManager({
      accessSecret: SECRET,
      accessExpiresIn: 1,
    });
    const token = shortLived.sign("user-123");

    return new Promise<void>((resolve, reject) => {
      setTimeout(() => {
        try {
          expect(() => shortLived.verify(token)).toThrow();
          resolve();
        } catch (error) {
          reject(error);
        }
      }, 1100);
    });
  });

  it("rejects malformed tokens", () => {
    expect(() => tokens.verify("not.a.jwt")).toThrow();
    expect(() => tokens.verify("abc")).toThrow();
  });

  it("requires a user id when signing", () => {
    expect(() => tokens.sign("")).toThrow("User ID is required");
  });

  it("rejects weak access secrets", () => {
    expect(() =>
      createTokenManager({ accessSecret: "too-short" })
    ).toThrow("Access secret must contain at least 32 bytes");
  });
});

describe("loadAuthConfig", () => {
  it("loads valid configuration from environment", () => {
    const config = loadAuthConfig({
      AUTH_ACCESS_SECRET: SECRET,
      AUTH_ACCESS_EXPIRES_SECONDS: "900",
      AUTH_BCRYPT_ROUNDS: "12",
      AUTH_ISSUER: "jay-auth-kit",
      AUTH_AUDIENCE: "my-api",
    });

    expect(config).toEqual({
      accessSecret: SECRET,
      accessExpiresIn: 900,
      bcryptRounds: 12,
      issuer: "jay-auth-kit",
      audience: "my-api",
      otpPepper: SECRET,
      otpLength: 6,
      otpExpiresInSeconds: 600,
      otpMaxAttempts: 5,
    });
  });

  it("fails safely when the access secret is missing", () => {
    expect(() => loadAuthConfig({})).toThrow(
      "AUTH_ACCESS_SECRET must be configured securely"
    );
  });

  it("fails safely when the access secret is too short", () => {
    expect(() =>
      loadAuthConfig({ AUTH_ACCESS_SECRET: "short" })
    ).toThrow("AUTH_ACCESS_SECRET must be configured securely");
  });
});
