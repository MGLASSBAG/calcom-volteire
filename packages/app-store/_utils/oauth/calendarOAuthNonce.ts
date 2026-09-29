import { timingSafeEqual } from "node:crypto";

export function validateCalendarOAuthNonce(
  cookie: string | undefined,
  nonce: unknown,
  userId: number | undefined
) {
  if (
    !cookie ||
    !/^[0-9]+\.[a-f0-9]{64}$/.test(cookie) ||
    !userId ||
    typeof nonce !== "string" ||
    !/^[a-f0-9]{64}$/.test(nonce)
  )
    return false;
  const expected = `${userId}.${nonce}`;
  return cookie.length === expected.length && timingSafeEqual(Buffer.from(cookie), Buffer.from(expected));
}
