import { randomBytes } from "node:crypto";
import { WEBAPP_URL_FOR_OAUTH } from "@calcom/lib/constants";
import { HttpError } from "@calcom/lib/http-error";
import type { NextApiRequest, NextApiResponse } from "next";
import type { IntegrationOAuthCallbackState } from "../../types";
import { validateCalendarOAuthNonce } from "./calendarOAuthNonce";

type Provider = "google" | "office365";
type State = IntegrationOAuthCallbackState & { calendarOAuthNonce: string };
function cookieName(provider: Provider) {
  return `${WEBAPP_URL_FOR_OAUTH.startsWith("https:") ? "__Host-" : ""}cal-${provider}-oauth`;
}
function setCookie(res: NextApiResponse, provider: Provider, value: string, maxAge: number) {
  const existing = res.getHeader("Set-Cookie");
  const cookies = Array.isArray(existing) ? existing : existing ? [String(existing)] : [];
  res.setHeader("Set-Cookie", [
    ...cookies,
    `${cookieName(provider)}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${WEBAPP_URL_FOR_OAUTH.startsWith("https:") ? "; Secure" : ""}`,
  ]);
}
export function createCalendarOAuthState(req: NextApiRequest, res: NextApiResponse, provider: Provider) {
  if (!req.session?.user?.id) throw new HttpError({ statusCode: 401, message: "Authentication required" });
  const input = typeof req.query.state === "string" ? JSON.parse(req.query.state) : {};
  // The server replaces the browser nonce and binds it to the authenticated user.
  const nonce = randomBytes(32).toString("hex");
  setCookie(res, provider, `${req.session.user.id}.${nonce}`, 600);
  return JSON.stringify({ ...input, calendarOAuthNonce: nonce });
}

export function consumeCalendarOAuthState(
  req: NextApiRequest,
  res: NextApiResponse,
  provider: Provider
): IntegrationOAuthCallbackState {
  const cookie = req.cookies[cookieName(provider)];
  setCookie(res, provider, "", 0);
  let state: State;
  try {
    state = JSON.parse(typeof req.query.state === "string" ? req.query.state : "null");
  } catch {
    throw new HttpError({
      statusCode: 403,
      message: "Calendar authorization expired. Please reconnect from settings.",
    });
  }
  if (!state || !validateCalendarOAuthNonce(cookie, state.calendarOAuthNonce, req.session?.user?.id)) {
    throw new HttpError({
      statusCode: 403,
      message: "Calendar authorization expired. Please reconnect from settings.",
    });
  }
  const { calendarOAuthNonce: _nonce, ...navigation } = state;
  return navigation;
}
