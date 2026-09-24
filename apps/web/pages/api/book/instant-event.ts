import type { NextApiRequest } from "next";

import { getServerSession } from "@calcom/features/auth/lib/getServerSession";
import { getInstantBookingCreateService } from "@calcom/features/bookings/di/InstantBookingCreateService.container";
import { checkRateLimitAndThrowError } from "@calcom/lib/checkRateLimitAndThrowError";
import getIP from "@calcom/lib/getIP";
import { piiHasher } from "@calcom/lib/server/PiiHasher";
import { defaultResponder } from "@calcom/lib/server/defaultResponder";
import { CreationSource } from "@calcom/prisma/enums";

import {
  SERVICE_SECRET_HEADER,
  assertServiceOnlyBookingAllowed,
} from "@lib/volteire/serviceOnlyBooking";

async function handler(req: NextApiRequest & { userId?: number }) {
  const userIp = getIP(req);

  await checkRateLimitAndThrowError({
    rateLimitingType: "instantMeeting",
    identifier: `instant.event-${piiHasher.hash(userIp)}`,
  });

  const session = await getServerSession({ req });

  // Volt Éire: installation bookings are created only after payment.
  assertServiceOnlyBookingAllowed({
    eventTypeIds: [req.body?.eventTypeId],
    serviceSecret: req.headers[SERVICE_SECRET_HEADER],
    sessionRole: session?.user?.role,
  });

  req.userId = session?.user?.id || -1;
  req.body.creationSource = CreationSource.WEBAPP;

  const instantBookingService = getInstantBookingCreateService();
  // Even though req.body is any type, createBooking validates the schema on run-time.
  // TODO: We should do the run-time schema validation here and pass a typed bookingData instead and then run-time schema could be removed from createBooking. Then we can remove the any type from req.body.
  const booking = await instantBookingService.createBooking({
    bookingData: req.body,
  });

  return booking;
}
export default defaultResponder(handler);
