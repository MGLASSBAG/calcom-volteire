import { defaultResponderForAppDir } from "app/api/defaultResponderForAppDir";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import handleCancelBooking from "@calcom/features/bookings/lib/handleCancelBooking";
import { checkRateLimitAndThrowError } from "@calcom/lib/checkRateLimitAndThrowError";
import { bookingCancelSchema } from "@calcom/prisma/zod-utils";

import { SERVICE_SECRET_HEADER, isValidServiceSecret } from "@lib/volteire/serviceOnlyBooking";

/**
 * Server-to-server booking cancellation.
 *
 * `POST /api/cancel` is built for the browser: it requires a CSRF token paired
 * with a session cookie, so an integration calling it from a server gets
 * `400 invalid_type in 'csrfToken': Required`, and presenting a token without
 * the cookie gets `403 Invalid CSRF token`. This deployment does not expose the
 * v1 or v2 REST API either, so there was no way for Volt Éire to cancel a
 * booking it had created.
 *
 * The consequence was quiet and expensive: when a customer's payment failed or
 * was cancelled, Volt Éire marked the appointment cancelled on its side while
 * the booking stayed `accepted` here. Cal derives availability from the Booking
 * table, so the slot stayed unbookable forever while the other system believed
 * it was free.
 *
 * A direct `UPDATE "Booking" SET status = 'cancelled'` is NOT a workaround —
 * it leaves the slot permanently unbookable and any re-book of that time fails
 * with a database error. Cancellation has to go through `handleCancelBooking`
 * so the calendar sync, webhooks, refunds and emails all run.
 *
 * Auth is a shared secret in `x-cal-service-secret`, compared in constant time
 * (lib/volteire/serviceOnlyBooking).
 * The route is inert unless `CAL_SERVICE_SECRET` is set.
 */

async function handler(req: NextRequest) {
  const configuredSecret = process.env.CAL_SERVICE_SECRET;

  // Fail closed. An unset secret must not mean "anyone may cancel".
  if (!configuredSecret) {
    return NextResponse.json(
      { success: false, message: "Service cancellation is not configured" },
      { status: 503 }
    );
  }

  if (!isValidServiceSecret(req.headers.get(SERVICE_SECRET_HEADER))) {
    return NextResponse.json({ success: false, message: "Unauthorized" }, { status: 401 });
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, message: "Invalid JSON" }, { status: 400 });
  }

  // Same payload as the browser route, minus the CSRF token.
  const parsed = bookingCancelSchema.safeParse(body);
  if (!parsed.success || (!parsed.data.id && !parsed.data.uid)) {
    return NextResponse.json({ success: false, message: "Invalid cancellation request" }, { status: 400 });
  }
  const bookingData = parsed.data;

  await checkRateLimitAndThrowError({
    rateLimitingType: "core",
    identifier: "api:cancel-service",
  });

  // userId -1 mirrors the unauthenticated branch of the browser route: the
  // cancellation is attributed to the integration rather than to a person.
  const result = await handleCancelBooking({
    bookingData,
    userId: -1,
    actionSource: "WEBAPP",
  });

  return NextResponse.json(result, { status: result.success ? 200 : 400 });
}

export const POST = defaultResponderForAppDir(handler);
