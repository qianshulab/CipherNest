import { describe, expect, it } from "vitest";

import { estimateMasterPassword, hasObviousMasterPasswordPattern } from "./master-password";

describe("master password strength guidance", () => {
  it("rejects long repeated strings with a small suffix or substitution", () => {
    for (const weak of [
      "aaaaaaaaaaaaX",
      "aaaaaaaaaaaaaaaaaaaaaaaX",
      "abcabcabcabc!1",
      "abcabcabcabc!@#",
      "pa\u0085ssword1234!",
      "password1234!",
      "correct horse battery staple",
    ]) {
      expect(hasObviousMasterPasswordPattern(weak), weak).toBe(true);
      expect(estimateMasterPassword(weak), weak).toEqual({ label: "模式过于可预测", level: "0" });
    }
  });

  it("keeps distinct long passphrases out of the pattern rejection", () => {
    for (const passphrase of [
      "five violet cedar lantern river words",
      "A long independent master passphrase",
      "passwordless-7M%q!f9p2Rz",
      "pa\ufeffssword1234!",
    ]) {
      expect(hasObviousMasterPasswordPattern(passphrase), passphrase).toBe(false);
      expect(estimateMasterPassword(passphrase).level, passphrase).not.toBe("0");
    }
  });
});
