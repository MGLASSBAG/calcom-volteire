import { WEBAPP_URL } from "@calcom/lib/constants";
import { appsRouter } from "@calcom/trpc/server/routers/viewer/apps/_router";
import { calendarsRouter } from "@calcom/trpc/server/routers/viewer/calendars/_router";
import { CalendarListContainer } from "@components/apps/CalendarListContainer";
import { VolteireCalendarReturnLink } from "@components/apps/VolteireCalendarReturnLink";
import { createRouterCaller } from "app/_trpc/context";
import { _generateMetadata } from "app/_utils";

export const generateMetadata = async () =>
  await _generateMetadata(
    (t) => t("calendars"),
    (t) => t("calendars_description"),
    undefined,
    undefined,
    "/settings/my-account/calendars"
  );

const Page = async () => {
  const [calendarsCaller, appsCaller] = await Promise.all([
    createRouterCaller(calendarsRouter),
    createRouterCaller(appsRouter),
  ]);

  const [connectedCalendars, installedCalendars] = await Promise.all([
    calendarsCaller.connectedCalendars(),
    appsCaller.integrations({
      variant: "calendar",
      onlyInstalled: true,
    }),
  ]);
  return (
    <>
      {new URL(WEBAPP_URL).hostname === "cal.volteire.ie" && <VolteireCalendarReturnLink />}
      <CalendarListContainer
        connectedCalendars={connectedCalendars}
        installedCalendars={installedCalendars}
      />
    </>
  );
};

export default Page;
