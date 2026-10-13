import { describe, expect, it, vi } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { createTokenManager } from "../src/tokens";
import { createAuthMiddleware } from "../src/middleware";

const SECRET = "m".repeat(32);

function mockRes() {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    locals: {} as Record<string, unknown>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return res;
}

function run(
  middleware: ReturnType<typeof createAuthMiddleware>,
  authorization?: string
) {
  const req = {
    headers: authorization ? { authorization } : {},
  } as Request;
  const res = mockRes();
  const next = vi.fn() as unknown as NextFunction;

  middleware(req, res as unknown as Response, next);

  return { res, next };
}

describe("createAuthMiddleware", () => {
  const tokens = createTokenManager({
    accessSecret: SECRET,
    accessExpiresIn: 60,
  });
  const middleware = createAuthMiddleware(tokens);

  it("allows a valid Bearer token and sets res.locals.auth", () => {
    const token = tokens.sign("user-42", "admin");
    const { res, next } = run(middleware, `Bearer ${token}`);

    expect(next).toHaveBeenCalledOnce();
    expect(res.locals.auth).toEqual({
      userId: "user-42",
      role: "admin",
    });
  });

  it("returns 401 when Authorization header is missing", () => {
    const { res, next } = run(middleware);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({
      success: false,
      message: "Authentication required",
    });
  });

  it("returns 401 for non-Bearer schemes", () => {
    const { res, next } = run(middleware, "Basic abc");

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ message: "Authentication required" });
  });

  it("returns 401 for malformed JWT shape", () => {
    const { res, next } = run(middleware, "Bearer not-a-jwt");

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({
      success: false,
      message: "Invalid access token",
    });
  });

  it("returns 401 for an invalid signature", () => {
    const other = createTokenManager({
      accessSecret: "x".repeat(32),
      accessExpiresIn: 60,
    });
    const token = other.sign("user-42");
    const { res, next } = run(middleware, `Bearer ${token}`);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({
      success: false,
      message: "Invalid or expired access token",
    });
  });

  it("returns 401 for an expired token", async () => {
    const shortLived = createTokenManager({
      accessSecret: SECRET,
      accessExpiresIn: 1,
    });
    const guard = createAuthMiddleware(shortLived);
    const token = shortLived.sign("user-42");

    await new Promise((resolve) => setTimeout(resolve, 1100));

    const { res, next } = run(guard, `Bearer ${token}`);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({
      message: "Invalid or expired access token",
    });
  });
});
