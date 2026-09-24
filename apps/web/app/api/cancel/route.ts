import { defaultResponderForAppDir } from "app/api/defaultResponderForAppDir";
import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { getServerSession } from "@calcom/features/auth/lib/getServerSession";
import handleCancelBooking from "@calcom/features/bookings/lib/handleCancelBooking";
import { checkRateLimitAndThrowError } from "@calcom/lib/checkRateLimitAndThrowError";
import getIP from "@calcom/lib/getIP";
import { piiHasher } from "@calcom/lib/server/PiiHasher";
import { bookingCancelWithCsrfSchema } from "@calcom/prisma/zod-utils";
import { validateCsrfToken } from "@calcom/web/lib/validateCsrfToken";

import { buildLegacyRequest } from "@lib/buildLegacyCtx";
import {
  SERVICE_SECRET_HEADER,
  assertServiceOnlyBookingAllowed,
  getBookingEventTypeId,
} from "@lib/volteire/serviceOnlyBooking";

async function handler(req: NextRequest) {
  let appDirRequestBody;
  try {
    appDirRequestBody = await req.json();
  } catch {
    return NextResponse.json({ success: false, message: "Invalid JSON" }, { status: 400 });
  }
  const bookingData = bookingCancelWithCsrfSchema.parse(appDirRequestBody);

  const csrfError = await validateCsrfToken(bookingData.csrfToken);
  if (csrfError) {
    return csrfError;
  }

  const session = await getServerSession({ req: buildLegacyRequest(await headers(), await cookies()) });

  // Volt Éire: installation bookings are cancelled through Volt Éire, not
  // from a Cal email link, so refunds and the installer are handled.
  assertServiceOnlyBookingAllowed({
    eventTypeIds: [await getBookingEventTypeId({ id: bookingData.id, uid: bookingData.uid })],
    serviceSecret: req.headers.get(SERVICE_SECRET_HEADER),
    sessionRole: session?.user?.role,
  });

  // Rate limit: 10 booking cancellations per 60 seconds per user (or IP if not authenticated)
  const identifier = session?.user?.id
    ? `api:cancel-user:${session.user.id}`
    : `api:cancel-ip:${piiHasher.hash(getIP(req))}`;
  await checkRateLimitAndThrowError({
    rateLimitingType: "core",
    identifier,
  });

  const result = await handleCancelBooking({
    bookingData,
    userId: session?.user?.id || -1,
    userUuid: session?.user?.uuid,
    actionSource: "WEBAPP",
  });

  // const bookingCancelService = getBookingCancelService();
  // const result = await bookingCancelService.cancelBooking({
  //   bookingData: bookingData,
  //   bookingMeta: {
  //     userId: session?.user?.id || -1,
  //   },
  // });

  const statusCode = result.success ? 200 : 400;

  return NextResponse.json(result, { status: statusCode });
}

export const DELETE = defaultResponderForAppDir(handler);
export const POST = defaultResponderForAppDir(handler);
