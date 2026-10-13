import jwt, { type JwtPayload } from "jsonwebtoken";

export interface TokenOptions {
  accessSecret: string;
  accessExpiresIn?: number;
  issuer?: string;
  audience?: string;
}

export function createTokenManager(options: TokenOptions) {
  if (
    typeof options.accessSecret !== "string" ||
    Buffer.byteLength(options.accessSecret, "utf8") < 32
  ) {
    throw new Error(
      "Access secret must contain at least 32 bytes"
    );
  }

  const expiresIn = options.accessExpiresIn ?? 900;

  if (!Number.isSafeInteger(expiresIn) || expiresIn <= 0) {
    throw new Error("Invalid access token expiry");
  }

  return {
    sign(userId: string, role?: string): string {
      if (!userId) {
        throw new Error("User ID is required");
      }

      return jwt.sign(
        { role },
        options.accessSecret,
        {
          algorithm: "HS256",
          subject: userId,
          expiresIn,
          ...(options.issuer ? { issuer: options.issuer } : {}),
          ...(options.audience
            ? { audience: options.audience }
            : {}),
        }
      );
    },

    verify(token: string): JwtPayload {
      const payload = jwt.verify(
        token,
        options.accessSecret,
        {
          algorithms: ["HS256"],
          ...(options.issuer ? { issuer: options.issuer } : {}),
          ...(options.audience
            ? { audience: options.audience }
            : {}),
        }
      );

      if (typeof payload === "string") {
        throw new Error("Invalid token payload");
      }

      return payload;
    },
  };
}
