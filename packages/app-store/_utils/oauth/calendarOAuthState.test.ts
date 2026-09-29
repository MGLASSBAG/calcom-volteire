import { describe, expect, it } from "vitest";
import { validateCalendarOAuthNonce } from "./calendarOAuthNonce";

describe("calendar OAuth CSRF state", () => {
  const nonce = "b".repeat(64);
  it("accepts the browser nonce bound to the current Cal user", () => {
    expect(validateCalendarOAuthNonce(`7.${nonce}`, nonce, 7)).toBe(true);
  });
  it("rejects missing, forged and cross-account state", () => {
    expect(validateCalendarOAuthNonce(undefined, nonce, 7)).toBe(false);
    expect(validateCalendarOAuthNonce(`7.${nonce}`, "c".repeat(64), 7)).toBe(false);
    expect(validateCalendarOAuthNonce(`7.${nonce}`, nonce, 8)).toBe(false);
    expect(validateCalendarOAuthNonce(`7.${nonce}`, nonce, undefined)).toBe(false);
  });
});
