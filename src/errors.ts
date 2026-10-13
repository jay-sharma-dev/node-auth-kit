export class AuthError extends Error {
  readonly code: string;

  constructor(message: string, code = "AUTH_ERROR") {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}

export class ConfigError extends AuthError {
  constructor(message: string) {
    super(message, "CONFIG_ERROR");
    this.name = "ConfigError";
  }
}

export class PasswordError extends AuthError {
  constructor(message: string) {
    super(message, "PASSWORD_ERROR");
    this.name = "PasswordError";
  }
}

export class TokenError extends AuthError {
  constructor(message: string) {
    super(message, "TOKEN_ERROR");
    this.name = "TokenError";
  }
}

export class OtpError extends AuthError {
  constructor(message: string) {
    super(message, "OTP_ERROR");
    this.name = "OtpError";
  }
}
