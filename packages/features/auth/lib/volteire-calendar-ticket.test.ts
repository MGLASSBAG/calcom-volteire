import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CALENDAR_TICKET_PURPOSE,
  type CalendarTicketStore,
  consumeCalendarTicket,
  parseCalendarTicket,
  readCalendarHandoffCookie,
  ticketHash,
} from "./volteire-calendar-ticket";

const audience = "https://cal.volteire.ie";
const ticket = "a".repeat(64);
const identifier =
  CALENDAR_TICKET_PURPOSE +
  JSON.stringify({
    email: "installer@example.test",
    userId: 7,
    teamId: 1,
    eventTypeId: 5,
    origin: "https://installer.volteire.ie",
    audience,
    installerId: "installer",
  });
function store(overrides: Partial<CalendarTicketStore> = {}): CalendarTicketStore {
  let unused = true;
  return {
    consume: vi.fn(async () => {
      if (!unused) return null;
      unused = false;
      return { identifier };
    }),
    resolveMember: vi.fn(async () => ({
      id: 7,
      email: "installer@example.test",
      role: "USER",
      locked: false,
    })),
    ...overrides,
  };
}
describe("installer calendar handoff", () => {
  beforeEach(() => {
    vi.stubEnv("INSTALLER_CALENDAR_CONNECT_ENABLED", "true");
  });
  it.each([
    undefined,
    "false",
    "1",
    "TRUE",
  ])("refuses a disabled rollout gate %s without consuming the ticket", async (value) => {
    vi.stubEnv("INSTALLER_CALENDAR_CONNECT_ENABLED", value);
    const db = store();
    await expect(consumeCalendarTicket(ticket, audience, audience, db)).rejects.toThrow("not available yet");
    expect(db.consume).not.toHaveBeenCalled();
    expect(db.resolveMember).not.toHaveBeenCalled();
  });
  it("consumes an opaque ticket once and rejects replay", async () => {
    const db = store();
    expect(await consumeCalendarTicket(ticket, audience, audience, db)).toEqual({ userId: 7 });
    expect(db.consume).toHaveBeenCalledWith(ticketHash(ticket));
    await expect(consumeCalendarTicket(ticket, audience, audience, db)).rejects.toThrow("already used");
  });
  it("allows only one concurrent consumer", async () => {
    const db = store();
    const results = await Promise.allSettled([
      consumeCalendarTicket(ticket, audience, audience, db),
      consumeCalendarTicket(ticket, audience, audience, db),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  });
  it.each([
    null,
    "https://installer.volteire.ie",
    "https://evil.example",
  ])("refuses non-Cal-origin credential POST %s before consumption", async (origin) => {
    const db = store();
    await expect(consumeCalendarTicket(ticket, origin, audience, db)).rejects.toThrow("origin");
    expect(db.consume).not.toHaveBeenCalled();
  });
  it("rejects the operations Cal account even with matching claims", async () => {
    const operationsIdentifier = identifier.replace('"userId":7', '"userId":2');
    await expect(
      consumeCalendarTicket(
        ticket,
        audience,
        audience,
        store({
          consume: async () => ({ identifier: operationsIdentifier }),
          resolveMember: async () => ({
            id: 2,
            email: "installer@example.test",
            role: "USER",
            locked: false,
          }),
        })
      )
    ).rejects.toThrow("not available");
  });
  it("rejects expired tickets", async () => {
    await expect(
      consumeCalendarTicket(ticket, audience, audience, store({ consume: async () => null }))
    ).rejects.toThrow("expired");
  });
  it.each([
    { id: 7, email: "installer@example.test", role: "ADMIN", locked: false },
    { id: 8, email: "installer@example.test", role: "USER", locked: false },
    { id: 7, email: "installer@example.test", role: "USER", locked: true },
  ])("rejects privileged or mismatched Cal account %j", async (user) => {
    await expect(
      consumeCalendarTicket(ticket, audience, audience, store({ resolveMember: async () => user }))
    ).rejects.toThrow("not available");
  });
  it("rejects a Cal email changed after ticket issuance", async () => {
    await expect(
      consumeCalendarTicket(
        ticket,
        audience,
        audience,
        store({
          resolveMember: async () => ({
            id: 7,
            email: "changed@example.test",
            role: "USER",
            locked: false,
          }),
        })
      )
    ).rejects.toThrow("not available");
  });
  it("rejects another purpose, audience and portal origin", () => {
    expect(() =>
      parseCalendarTicket(identifier.replace("volteire-calendar-v1", "login"), audience)
    ).toThrow();
    expect(() => parseCalendarTicket(identifier, "https://evil.example")).toThrow();
    expect(() =>
      parseCalendarTicket(
        identifier.replace("https://installer.volteire.ie", "https://evil.example"),
        audience
      )
    ).toThrow();
  });
});

describe("NextAuth calendar handoff cookie", () => {
  it("reads the secure cookie from the credentials request header", () => {
    expect(
      readCalendarHandoffCookie(
        `other=value; __Host-volteire-calendar-handoff=${ticket}; next-auth.csrf-token=csrf`,
        audience
      )
    ).toBe(ticket);
  });
  it("uses the development cookie only for an HTTP audience", () => {
    const header = `volteire-calendar-handoff=${ticket}`;
    expect(readCalendarHandoffCookie(header, "http://localhost:3000")).toBe(ticket);
    expect(readCalendarHandoffCookie(header, audience)).toBeUndefined();
  });
  it("rejects duplicate cookie names instead of selecting an account ambiguously", () => {
    expect(
      readCalendarHandoffCookie(
        `__Host-volteire-calendar-handoff=${ticket}; __Host-volteire-calendar-handoff=${"b".repeat(64)}`,
        audience
      )
    ).toBeUndefined();
  });
  it.each([
    undefined,
    [],
    "unrelated=value",
    "__Host-volteire-calendar-handoff=invalid",
    `__Host-volteire-calendar-handoff=%61${"a".repeat(63)}`,
  ])("rejects missing or malformed cookies %s", (header) => {
    expect(readCalendarHandoffCookie(header, audience)).toBeUndefined();
  });
});
