import { ProfileRepository } from "@calcom/features/profile/repositories/ProfileRepository";
import { WEBAPP_URL } from "@calcom/lib/constants";
import prisma from "@calcom/prisma";
import CredentialsProvider from "next-auth/providers/credentials";
import {
  CALENDAR_TICKET_PURPOSE,
  consumeCalendarTicket,
  readCalendarHandoffCookie,
} from "./volteire-calendar-ticket";

export const VolteireCalendarProvider = CredentialsProvider({
  id: "volteire-calendar",
  name: "Volt Éire calendar",
  credentials: {},
  async authorize(_credentials, req) {
    const audience = new URL(WEBAPP_URL).origin;
    // The short-lived ticket is HttpOnly. NextAuth enforces CSRF on this same-origin POST.
    const token = readCalendarHandoffCookie(req.headers?.cookie, audience);
    const { userId } = await consumeCalendarTicket(token, req.headers?.origin, audience, {
      consume: async (hash) => {
        const rows = await prisma.$queryRaw<Array<{ identifier: string }>>`
          DELETE FROM "VerificationToken" WHERE token=${hash} AND expires>NOW()
            AND identifier LIKE ${CALENDAR_TICKET_PURPOSE + "%"} RETURNING identifier`;
        return rows[0] ?? null;
      },
      resolveMember: async (claims) =>
        prisma.user.findFirst({
          where: {
            id: claims.userId,
            email: { equals: claims.email, mode: "insensitive" },
            role: "USER",
            locked: false,
            teams: {
              some: {
                teamId: claims.teamId,
                accepted: true,
                role: "MEMBER",
                team: { eventTypes: { some: { id: claims.eventTypeId } } },
              },
            },
          },
          select: { id: true, email: true, role: true, locked: true },
        }),
    });
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, uuid: true, name: true, email: true, username: true, role: true, locale: true },
    });
    if (!user || user.role !== "USER") return null;
    const profiles = await ProfileRepository.findAllProfilesForUserIncludingMovedUser(user);
    return { ...user, belongsToActiveTeam: true, profile: profiles[0] };
  },
});
