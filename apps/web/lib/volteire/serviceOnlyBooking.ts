import { createHash, timingSafeEqual } from "node:crypto";

import { HttpError } from "@calcom/lib/http-error";
import { prisma } from "@calcom/prisma";

/**
 * Volt Éire: service-only event types.
 *
 * Installation bookings are payment-first: the Volt Éire app creates the Cal
 * booking only after the customer has paid. The public booking page and the
 * unauthenticated booking/cancel endpoints would otherwise let anyone book an
 * installer's time without paying, or cancel a paid booking from a Cal email
 * link.
 *
 * Event types listed in CAL_SERVICE_ONLY_EVENT_TYPE_IDS (comma separated) can
 * only be booked, rescheduled or cancelled by:
 *   - a server presenting CAL_SERVICE_SECRET in `x-cal-service-secret`, or
 *   - a signed-in Cal instance admin (for manual fixes in the Cal UI).
 * Other event types behave exactly as upstream.
 */

export const SERVICE_SECRET_HEADER = "x-cal-service-secret";

function serviceOnlyEventTypeIds(): Set<number> {
  return new Set(
    (process.env.CAL_SERVICE_ONLY_EVENT_TYPE_IDS || "")
      .split(",")
      .map((value) => Number(value.trim()))
      .filter((value) => Number.isInteger(value) && value > 0)
  );
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Constant-time check of the shared service secret. False when unset. */
export function isValidServiceSecret(presented: string | string[] | null | undefined): boolean {
  const configured = process.env.CAL_SERVICE_SECRET;
  const value = Array.isArray(presented) ? presented[0] : presented;
  if (!configured || !value) return false;
  return timingSafeEqual(digest(value), digest(configured));
}

export function isServiceOnlyEventType(eventTypeId: unknown): boolean {
  const id = Number(eventTypeId);
  return Number.isInteger(id) && serviceOnlyEventTypeIds().has(id);
}

const FORBIDDEN_MESSAGE =
  "This booking is managed by Volt Éire. Please contact ev@volteire.ie to book, change or cancel.";

/** Throw 403 unless the caller may manage bookings for this event type. */
export function assertServiceOnlyBookingAllowed(input: {
  eventTypeIds: unknown[];
  serviceSecret: string | string[] | null | undefined;
  sessionRole?: string | null;
}): void {
  if (!input.eventTypeIds.some(isServiceOnlyEventType)) return;
  if (input.sessionRole === "ADMIN") return;
  if (isValidServiceSecret(input.serviceSecret)) return;
  throw new HttpError({ statusCode: 403, message: FORBIDDEN_MESSAGE });
}

/** Resolve a booking's event type for cancellation checks. */
export async function getBookingEventTypeId(ref: {
  id?: number;
  uid?: string;
}): Promise<number | null> {
  if (!ref.id && !ref.uid) return null;
  const booking = await prisma.booking.findFirst({
    where: ref.id ? { id: ref.id } : { uid: ref.uid },
    select: { eventTypeId: true },
  });
  return booking?.eventTypeId ?? null;
}
