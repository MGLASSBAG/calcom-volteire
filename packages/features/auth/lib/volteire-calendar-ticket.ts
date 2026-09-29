import { createHash } from "node:crypto";
import { z } from "zod";

export const CALENDAR_TICKET_PURPOSE = "volteire-calendar-v1:";
export const CALENDAR_HANDOFF_COOKIE = "__Host-volteire-calendar-handoff";
export const CALENDAR_HANDOFF_COOKIE_DEV = "volteire-calendar-handoff";
export const CALENDAR_SETTINGS_PATH = "/settings/my-account/calendars";
const claimsSchema = z
  .object({
    email: z.string().email(),
    userId: z.number().int().positive(),
    teamId: z.number().int().positive(),
    eventTypeId: z.number().int().positive(),
    origin: z.string().url(),
    audience: z.string().url(),
    installerId: z.string().min(1),
  })
  .strict();

export function isInstallerCalendarConnectEnabled(): boolean {
  return process.env.INSTALLER_CALENDAR_CONNECT_ENABLED === "true";
}

export function requireInstallerCalendarConnectEnabled(): void {
  if (!isInstallerCalendarConnectEnabled()) throw new Error("Calendar connections are not available yet");
}

export function ticketHash(ticket: unknown): string {
  if (typeof ticket !== "string" || !/^[a-f0-9]{64}$/.test(ticket))
    throw new Error("Invalid calendar handoff");
  return createHash("sha256").update(ticket).digest("hex");
}

/** NextAuth credentials requests expose the raw cookie header, not a cookies map. */
export function readCalendarHandoffCookie(cookieHeader: unknown, audience: string): string | undefined {
  if (typeof cookieHeader !== "string") return undefined;
  const cookieName = audience.startsWith("https:") ? CALENDAR_HANDOFF_COOKIE : CALENDAR_HANDOFF_COOKIE_DEV;
  const prefix = `${cookieName}=`;
  const matches = cookieHeader
    .split(";")
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith(prefix));
  if (matches.length !== 1) return undefined;
  const ticket = matches[0].slice(prefix.length);
  return /^[a-f0-9]{64}$/.test(ticket) ? ticket : undefined;
}

export function parseCalendarTicket(identifier: string, audience: string) {
  if (!identifier.startsWith(CALENDAR_TICKET_PURPOSE)) throw new Error("Invalid calendar handoff");
  const parsed = claimsSchema.parse(JSON.parse(identifier.slice(CALENDAR_TICKET_PURPOSE.length)));
  if (
    parsed.audience !== audience ||
    !["https://volteire.ie", "https://installer.volteire.ie"].includes(parsed.origin)
  ) {
    throw new Error("Invalid calendar handoff");
  }
  return parsed;
}

export function requireCalendarOrigin(origin: unknown, expected: string) {
  if (typeof origin !== "string" || origin !== expected) throw new Error("Invalid calendar handoff origin");
}

export type CalendarTicketStore = {
  consume: (hash: string) => Promise<{ identifier: string } | null>;
  resolveMember: (
    claims: z.infer<typeof claimsSchema>
  ) => Promise<{ id: number; email: string; role: string; locked: boolean } | null>;
};

/** Store.consume must atomically DELETE ... WHERE expires > NOW() RETURNING identifier. */
export async function consumeCalendarTicket(
  ticket: unknown,
  origin: unknown,
  audience: string,
  store: CalendarTicketStore
) {
  requireInstallerCalendarConnectEnabled();
  requireCalendarOrigin(origin, audience);
  const stored = await store.consume(ticketHash(ticket));
  if (!stored) throw new Error("Calendar handoff expired or already used");
  const claims = parseCalendarTicket(stored.identifier, audience);
  const user = await store.resolveMember(claims);
  if (
    !user ||
    user.id !== claims.userId ||
    user.id === 2 ||
    user.role !== "USER" ||
    user.locked ||
    user.email.toLowerCase() !== claims.email.toLowerCase()
  ) {
    throw new Error("Calendar account is not available");
  }
  return { userId: user.id };
}
