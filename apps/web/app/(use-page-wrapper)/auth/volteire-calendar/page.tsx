"use client";

import { useLocale } from "@calcom/lib/hooks/useLocale";
import { Button } from "@calcom/ui/components/button";
import { signIn } from "next-auth/react";
import { useEffect, useRef, useState } from "react";

export default function VolteireCalendarSignIn() {
  const started = useRef(false);
  const [failed, setFailed] = useState(false);
  const { t } = useLocale();
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void signIn("volteire-calendar", { redirect: false, callbackUrl: "/settings/my-account/calendars" })
      .then((result) => {
        if (result?.error || !result?.ok) setFailed(true);
        else window.location.replace("/settings/my-account/calendars");
      })
      .catch(() => setFailed(true));
  }, []);
  return (
    <main className="mx-auto max-w-lg space-y-4 p-6">
      <h1 className="text-xl font-semibold">{t("volteire_calendar_title")}</h1>
      <p role="status">{t(failed ? "volteire_calendar_handoff_failed" : "volteire_calendar_opening")}</p>
      {failed && (
        <Button href="https://installer.volteire.ie/installer/availability">
          {t("volteire_return_to_availability")}
        </Button>
      )}
    </main>
  );
}
