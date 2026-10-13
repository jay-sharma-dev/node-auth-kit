import { describe, expect, it } from "vitest";
import { createPasswordManager } from "../src/password";

describe("createPasswordManager", () => {
  const passwords = createPasswordManager({ rounds: 10 });

  it("hashes and verifies a valid password", async () => {
    const hash = await passwords.hash("MyStrongPassword123!");
    expect(hash).toMatch(/^\$2[aby]\$/);
    await expect(
      passwords.verify("MyStrongPassword123!", hash)
    ).resolves.toBe(true);
  });

  it("returns false for an incorrect password", async () => {
    const hash = await passwords.hash("MyStrongPassword123!");
    await expect(
      passwords.verify("WrongPassword!", hash)
    ).resolves.toBe(false);
  });

  it("returns false for a malformed hash", async () => {
    await expect(
      passwords.verify("MyStrongPassword123!", "not-a-bcrypt-hash")
    ).resolves.toBe(false);
  });

  it("rejects empty passwords", async () => {
    await expect(passwords.hash("")).rejects.toThrow(
      "Password is required"
    );
  });

  it("rejects passwords longer than 72 UTF-8 bytes", async () => {
    const tooLong = "a".repeat(73);
    await expect(passwords.hash(tooLong)).rejects.toThrow(
      "Password must not exceed 72 UTF-8 bytes"
    );
  });

  it("rejects invalid bcrypt work factors", () => {
    expect(() => createPasswordManager({ rounds: 9 })).toThrow(
      "Invalid bcrypt work factor"
    );
    expect(() => createPasswordManager({ rounds: 16 })).toThrow(
      "Invalid bcrypt work factor"
    );
  });
});
