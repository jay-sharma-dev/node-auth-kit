import type { RequestHandler } from "express";
import type { createTokenManager } from "./tokens";

type TokenManager = ReturnType<typeof createTokenManager>;

export function createAuthMiddleware(
  tokens: TokenManager
): RequestHandler {
  return (req, res, next) => {
    const authorization = req.headers.authorization;

    if (!authorization?.startsWith("Bearer ")) {
      res.status(401).json({
        success: false,
        message: "Authentication required",
      });
      return;
    }

    const token = authorization.slice(7).trim();

    if (!token || token.split(".").length !== 3) {
      res.status(401).json({
        success: false,
        message: "Invalid access token",
      });
      return;
    }

    try {
      const payload = tokens.verify(token);

      if (!payload.sub) {
        res.status(401).json({
          success: false,
          message: "Invalid token subject",
        });
        return;
      }

      res.locals.auth = {
        userId: payload.sub,
        role: payload.role,
      };

      next();
    } catch {
      res.status(401).json({
        success: false,
        message: "Invalid or expired access token",
      });
    }
  };
}
