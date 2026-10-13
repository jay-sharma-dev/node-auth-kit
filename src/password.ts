import bcrypt from "bcrypt";

export interface PasswordOptions {
  rounds?: number;
}

export function createPasswordManager(
  options: PasswordOptions = {}
) {
  const rounds = options.rounds ?? 12;

  if (!Number.isInteger(rounds) || rounds < 10 || rounds > 15) {
    throw new Error("Invalid bcrypt work factor");
  }

  return {
    async hash(password: string): Promise<string> {
      validatePassword(password);

      return bcrypt.hash(password, rounds);
    },

    async verify(
      password: string,
      hashedPassword: string
    ): Promise<boolean> {
      validatePassword(password);

      if (
        typeof hashedPassword !== "string" ||
        !/^\$2[aby]\$\d{2}\$/.test(hashedPassword)
      ) {
        return false;
      }

      return bcrypt.compare(password, hashedPassword);
    },
  };
}

function validatePassword(password: string): void {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password is required");
  }

  // bcrypt processes at most 72 UTF-8 bytes.
  if (Buffer.byteLength(password, "utf8") > 72) {
    throw new Error("Password must not exceed 72 UTF-8 bytes");
  }
}
