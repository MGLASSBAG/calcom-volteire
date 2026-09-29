import {
  CALENDAR_HANDOFF_COOKIE,
  CALENDAR_HANDOFF_COOKIE_DEV,
  CALENDAR_TICKET_PURPOSE,
  parseCalendarTicket,
  requireCalendarOrigin,
  requireInstallerCalendarConnectEnabled,
  ticketHash,
} from "@calcom/features/auth/lib/volteire-calendar-ticket";
import { WEBAPP_URL } from "@calcom/lib/constants";
import prisma from "@calcom/prisma";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

/** Receives an allowlisted portal POST; consumption happens in NextAuth's CSRF-protected POST. */
export async function POST(req: NextRequest) {
  const audience = new URL(WEBAPP_URL).origin;
  try {
    requireInstallerCalendarConnectEnabled();
    if (Number(req.headers.get("content-length") || 0) > 1024) throw new Error("Invalid request");
    const data = await req.formData();
    const ticket = data.get("ticket");
    const token = ticketHash(ticket);
    const stored = await prisma.verificationToken.findFirst({
      where: { token, identifier: { startsWith: CALENDAR_TICKET_PURPOSE }, expires: { gt: new Date() } },
      select: { identifier: true },
    });
    if (!stored) throw new Error("Invalid calendar handoff");
    const claims = parseCalendarTicket(stored.identifier, audience);
    requireCalendarOrigin(req.headers.get("origin"), claims.origin);
    const response = NextResponse.redirect(`${audience}/auth/volteire-calendar`, 303);
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Referrer-Policy", "no-referrer");
    response.cookies.set(
      audience.startsWith("https:") ? CALENDAR_HANDOFF_COOKIE : CALENDAR_HANDOFF_COOKIE_DEV,
      String(ticket),
      {
        httpOnly: true,
        secure: audience.startsWith("https:"),
        sameSite: "lax",
        path: "/",
        maxAge: 90,
      }
    );
    return response;
  } catch {
    // Never log the request, ticket or credential cookies.
    return NextResponse.json(
      { error: "Calendar handoff expired or invalid. Please return to the installer portal and try again." },
      { status: 403, headers: { "Cache-Control": "no-store" } }
    );
  }
}
