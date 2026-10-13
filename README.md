# jay-auth-kit

Reusable authentication building blocks for Node.js and Express.

`jay-auth-kit` helps you hash passwords, issue and verify JWT access tokens, protect Express routes, and run OTP-based password reset — without rewriting the same auth utilities in every backend project.

OTP delivery is **pluggable**: bring your own SMTP or SMS gateway via a small `OtpDelivery` adapter. The package never talks to email/SMS providers directly.

Your application still owns the user database, registration endpoints, business logic, and account status. This package only provides the secure primitives.

---

## Requirements

- Node.js **20** or later
- TypeScript 5+ recommended for typed consumers
- Express 4 or 5 (for middleware)

---

## Installation

```bash
npm install jay-auth-kit
```

---

## Environment setup

In your backend project, create a `.env` file and generate a secret:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Put the generated value into `AUTH_ACCESS_SECRET` (never in frontend environment variables).

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `AUTH_ACCESS_SECRET` | Yes | — | Secret used to sign access tokens. Must be at least **32 bytes**. |
| `AUTH_ACCESS_EXPIRES_SECONDS` | No | `900` | Access token lifetime in seconds (15 minutes). |
| `AUTH_BCRYPT_ROUNDS` | No | `12` | bcrypt work factor (**10–15**). |
| `AUTH_ISSUER` | No | — | Optional JWT `iss` claim. |
| `AUTH_AUDIENCE` | No | — | Optional JWT `aud` claim. |
| `AUTH_OTP_PEPPER` | No | falls back to access secret | HMAC pepper for OTP hashes (≥32 bytes recommended). |
| `AUTH_OTP_LENGTH` | No | `6` | OTP digit length (**4–8**). |
| `AUTH_OTP_EXPIRES_SECONDS` | No | `600` | OTP lifetime (10 minutes). |
| `AUTH_OTP_MAX_ATTEMPTS` | No | `5` | Max failed verify attempts per challenge. |

Load env in your app before calling `createAuth()`:

```ts
import "dotenv/config";
```

---

## Quick start

```ts
import "dotenv/config";
import express from "express";
import { createAuth } from "jay-auth-kit";

const app = express();
app.use(express.json());

const auth = createAuth();

// Password
const hash = await auth.password.hash("MyStrongPassword123!");
const ok = await auth.password.verify("MyStrongPassword123!", hash);

// Access token
const token = auth.tokens.sign("user-id-123", "admin");
const payload = auth.tokens.verify(token);

// Protect routes
app.get("/private", auth.middleware, (req, res) => {
  res.json({ user: res.locals.auth }); // { userId, role }
});
```

---

## How integration works

```
┌──────────────────────────┐         ┌──────────────────────────┐
│  Your backend app        │         │      jay-auth-kit        │
│                          │         │                          │
│  User DB / ORM           │────────▶│  password.hash/verify    │
│  /register, /login       │────────▶│  tokens.sign/verify      │
│  SMTP / SMS gateway      │◀────────│  otp + passwordReset     │
│  (your OtpDelivery)      │  send() │  (generate / verify OTP) │
│  Account status          │────────▶│  auth.middleware         │
└──────────────────────────┘         └──────────────────────────┘
```

| Your app owns | Package provides |
| --- | --- |
| User schema (MongoDB, Prisma, etc.) | Password hashing & verification |
| `/register`, `/login`, `/logout` routes | JWT access token sign & verify |
| SMTP provider / SMS gateway credentials | OTP generate, hash, verify + reset helpers |
| `OtpDelivery` adapter (`send`) | Express Bearer middleware |
| Refresh tokens / session store | — (bring your own) |

---

## Express integration

### 1. Initialize once

```ts
// src/auth.ts
import "dotenv/config";
import { createAuth } from "jay-auth-kit";

export const auth = createAuth();
```

With SMTP/SMS password reset:

```ts
import { createAuth, createChannelDelivery } from "jay-auth-kit";
import { smtpDelivery, smsDelivery } from "./delivery"; // your adapters

export const auth = createAuth({
  delivery: createChannelDelivery({
    email: smtpDelivery,
    sms: smsDelivery,
  }),
});
```

### 2. Register — hash password, store only the hash

```ts
import express from "express";
import { auth } from "./auth";

const app = express();
app.use(express.json());

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const passwordHash = await auth.password.hash(password);

    // Your DB — store hash, never plaintext
    // await User.create({ email, passwordHash });

    return res.status(201).json({ message: "User registered" });
  } catch (error) {
    return res.status(400).json({
      message: error instanceof Error ? error.message : "Registration failed",
    });
  }
});
```

### 3. Login — verify password, issue access token

```ts
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // const user = await User.findOne({ email });
  // if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const user = {
    id: "user-123",
    passwordHash: "...from db...",
    role: "user",
    isActive: true,
  };

  const valid = await auth.password.verify(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  if (!user.isActive) {
    return res.status(403).json({ message: "Account disabled" });
  }

  const accessToken = auth.tokens.sign(user.id, user.role);

  return res.json({
    accessToken,
    tokenType: "Bearer",
    expiresIn: Number(process.env.AUTH_ACCESS_EXPIRES_SECONDS ?? 900),
  });
});
```

### 4. Protect routes

```ts
app.get("/me", auth.middleware, (req, res) => {
  const { userId, role } = res.locals.auth;
  return res.json({ userId, role });
});

app.get("/admin", auth.middleware, (req, res) => {
  if (res.locals.auth.role !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }
  return res.json({ message: "Admin only" });
});
```

### 5. Call protected APIs from the client

```bash
curl http://localhost:3000/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

```ts
const res = await fetch("https://api.example.com/me", {
  headers: {
    Authorization: `Bearer ${accessToken}`,
  },
});
```

Missing, invalid, or expired tokens → middleware responds with **401**.

---

## OTP + password reset (SMTP / SMS)

The package does **not** hard-code Nodemailer, Twilio, MSG91, etc.  
You plug in any provider by implementing `OtpDelivery`.

### Flow

1. Package creates a one-time OTP and returns a **hashed challenge** for your DB.
2. Package calls your `delivery.send(...)` with the plaintext code once.
3. User submits the code; package verifies it (expiry + attempts).
4. On success, package hashes the new password — you save it.

### 1. Implement adapters

```ts
import type { OtpDelivery } from "jay-auth-kit";

// SMTP — Nodemailer, Resend, SES, SendGrid, ...
const smtpDelivery: OtpDelivery = {
  async send({ to, code, purpose, expiresAt }) {
    // await transporter.sendMail({
    //   to,
    //   subject: "Password reset code",
    //   text: `Your code is ${code}. Expires at ${expiresAt.toISOString()}`,
    // });
  },
};

// SMS — Twilio, MSG91, SNS, ...
const smsDelivery: OtpDelivery = {
  async send({ to, code, purpose }) {
    // await twilio.messages.create({
    //   to,
    //   from: process.env.TWILIO_FROM,
    //   body: `Your ${purpose} code is ${code}`,
    // });
  },
};
```

### 2. Wire into `createAuth`

```ts
import { createAuth, createChannelDelivery } from "jay-auth-kit";

const delivery = createChannelDelivery({
  email: smtpDelivery,
  sms: smsDelivery,
});

export const auth = createAuth({ delivery });
// auth.otp            — low-level create / verify
// auth.passwordReset  — requestReset / confirmReset
```

Without `delivery`, you still get `auth.otp` for custom flows.  
`passwordReset` is only attached when `delivery` is provided.

### 3. Express routes

```ts
// POST /password/forgot  { email }  OR  { phone }
app.post("/password/forgot", async (req, res) => {
  const channel = req.body.phone ? "sms" : "email";
  const to = channel === "sms" ? req.body.phone : req.body.email;

  const result = await auth.passwordReset!.requestReset({ to, channel });

  // Save result.challenge in your DB
  // await OtpStore.save(userId, result.challenge);

  return res.json({
    message: "If the account exists, a reset code was sent",
    expiresAt: result.expiresAt,
  });
});

// POST /password/reset  { email|phone, code, newPassword }
app.post("/password/reset", async (req, res) => {
  const { code, newPassword, email, phone } = req.body;
  const to = phone ?? email;

  // const challenge = await OtpStore.findLatest(to, "password_reset");
  const challenge = req.body.challenge; // replace with DB load

  const result = await auth.passwordReset!.confirmReset({
    code,
    challenge,
    newPassword,
    to,
  });

  // Always persist result.challenge (attempts may have decreased)

  if (!result.ok) {
    return res.status(400).json({
      message: "Invalid or expired code",
      reason: result.reason,
    });
  }

  // await User.updateOne({ email: to }, { passwordHash: result.passwordHash });
  // await OtpStore.invalidate(challenge.id);

  return res.json({ message: "Password updated" });
});
```

### OTP security notes

- Store only `challenge.otpHash` — never the plaintext OTP.
- Rate-limit forgot/reset endpoints.
- Prefer a dedicated `AUTH_OTP_PEPPER` separate from the JWT secret.
- Return generic messages on forgot (don’t reveal whether email/phone exists).
- Invalidate the challenge after a successful reset.

---

## Next.js integration

Use `jay-auth-kit` only in **trusted server-side** code:

- App Router Route Handlers (`app/api/.../route.ts`)
- Server Actions / server utilities
- A separate Express / BFF service

**Do not** import this package into Client Components or any browser bundle. Secrets must never ship to the client.

### Login Route Handler

```ts
// app/api/login/route.ts
import { createAuth } from "jay-auth-kit";

const auth = createAuth();

export async function POST(request: Request) {
  const { email, password } = await request.json();

  // const user = await db.user.findUnique({ where: { email } });
  const user = { id: "user-123", passwordHash: "...", role: "user" };

  const valid = await auth.password.verify(password, user.passwordHash);
  if (!valid) {
    return Response.json({ ok: false }, { status: 401 });
  }

  const token = auth.tokens.sign(user.id, user.role);
  return Response.json({ token });
}
```

### Protecting a Route Handler

Express middleware does not run inside Next.js Route Handlers. Verify the token manually:

```ts
// app/api/me/route.ts
import { createAuth } from "jay-auth-kit";

const auth = createAuth();

export async function GET(request: Request) {
  const header = request.headers.get("authorization");

  if (!header?.startsWith("Bearer ")) {
    return Response.json({ message: "Authentication required" }, { status: 401 });
  }

  try {
    const payload = auth.tokens.verify(header.slice(7).trim());
    return Response.json({
      userId: payload.sub,
      role: payload.role,
    });
  } catch {
    return Response.json(
      { message: "Invalid or expired access token" },
      { status: 401 }
    );
  }
}
```

---

## API reference

### `createAuth(options?)`

Loads config from env and returns:

```ts
{
  password: ReturnType<typeof createPasswordManager>;
  tokens: ReturnType<typeof createTokenManager>;
  otp: ReturnType<typeof createOtpManager>;
  middleware: RequestHandler; // Express
  // when options.delivery is provided:
  delivery?: OtpDelivery;
  passwordReset?: ReturnType<typeof createPasswordResetManager>;
}
```

```ts
createAuth();
createAuth({ delivery }); // enables passwordReset helpers
```

Throws if `AUTH_ACCESS_SECRET` is missing or shorter than 32 characters, or if bcrypt / OTP / expiry values are invalid.

### Password hashing

```ts
import { createPasswordManager } from "jay-auth-kit";

const passwords = createPasswordManager({ rounds: 12 });

const hash = await passwords.hash("MyStrongPassword123!");
const isValid = await passwords.verify("MyStrongPassword123!", hash);
```

| Method | Behavior |
| --- | --- |
| `hash(password)` | Returns bcrypt hash. Rejects empty or >72 UTF-8 byte passwords. |
| `verify(password, hash)` | Returns `true`/`false`. Malformed hashes return `false`. |

Store only the hash in your database — never the plaintext password.

### JWT and middleware

```ts
import {
  createTokenManager,
  createAuthMiddleware,
} from "jay-auth-kit";

const tokens = createTokenManager({
  accessSecret: process.env.AUTH_ACCESS_SECRET!,
  accessExpiresIn: 900,
  issuer: "jay-auth-kit",
  audience: "my-api",
});

const token = tokens.sign("user-123", "admin");
const payload = tokens.verify(token);
const requireAuth = createAuthMiddleware(tokens);
```

| Method | Behavior |
| --- | --- |
| `sign(userId, role?)` | HS256 JWT with `sub` = userId and optional `role`. |
| `verify(token)` | Verifies signature, expiry, and optional issuer/audience. |

Middleware expects `Authorization: Bearer <token>` and sets:

```ts
res.locals.auth = {
  userId: string;
  role?: unknown;
};
```

Tokens are signed with **HS256 only**.

### OTP

```ts
import { createOtpManager } from "jay-auth-kit";

const otp = createOtpManager({
  pepper: process.env.AUTH_OTP_PEPPER!,
  length: 6,
  expiresInSeconds: 600,
  maxAttempts: 5,
});

const { code, challenge } = otp.create({
  destination: "user@example.com",
  channel: "email",
  purpose: "password_reset",
});

// send `code` via your SMTP/SMS adapter, store `challenge` in DB

const result = otp.verify(code, challenge, {
  purpose: "password_reset",
  destination: "user@example.com",
});
```

### Password reset helpers

```ts
import { createPasswordResetManager } from "jay-auth-kit";

const passwordReset = createPasswordResetManager({
  otp,
  password,
  delivery,
});

await passwordReset.requestReset({ to: "user@example.com", channel: "email" });
await passwordReset.confirmReset({ code, challenge, newPassword });
```

### Configuration defaults

| Option | Default | Notes |
| --- | --- | --- |
| `bcryptRounds` / `rounds` | `12` | Integer between 10 and 15. |
| `accessExpiresIn` | `900` | Seconds; positive safe integer. |
| `accessSecret` | — | Required; minimum 32 UTF-8 bytes. |
| `otpPepper` | access secret | Prefer a dedicated pepper. |
| `otpLength` | `6` | Digits, 4–8. |
| `otpExpiresInSeconds` | `600` | OTP lifetime. |
| `otpMaxAttempts` | `5` | Failed verify limit. |
| `issuer` / `audience` | unset | Included in sign/verify when provided. |

Advanced: use `loadAuthConfig(env)`, `createPasswordManager`, `createTokenManager`, `createOtpManager`, and `createPasswordResetManager` separately if you prefer not to use `createAuth()`.

---

## Security guidance

- Generate secrets with a CSPRNG (`crypto.randomBytes`).
- Keep access tokens short-lived (for example 15 minutes).
- Always verify JWT signatures; never trust claims from an unsigned payload.
- Return generic auth errors to clients; log details only server-side.
- Add rate limiting / account lockout around login and OTP endpoints in **your** app.
- After middleware succeeds, still check that the user exists and is active in your DB.
- For full production session management, add refresh-token rotation, revocation, and a security review.

### Common errors

| Situation | Expected behavior |
| --- | --- |
| Missing / short `AUTH_ACCESS_SECRET` | `createAuth()` / `loadAuthConfig()` throws |
| Missing `Authorization` header | Middleware responds `401` |
| Malformed or expired token | Middleware responds `401` |
| Wrong password | `verify()` returns `false` |
| Password > 72 UTF-8 bytes | `hash()` / `verify()` throws |
| Wrong / expired OTP | `confirmReset` / `otp.verify` returns `ok: false` |

---

## License

MIT
