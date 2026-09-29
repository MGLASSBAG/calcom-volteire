"use client";
import { useLocale } from "@calcom/lib/hooks/useLocale";
import { Button } from "@calcom/ui/components/button";
export function VolteireCalendarReturnLink() {
  const { t } = useLocale();
  return (
    <div className="mb-4 flex flex-col items-start gap-2">
      <Button color="secondary" href="https://installer.volteire.ie/installer/availability">
        {t("volteire_return_to_availability")}
      </Button>
      <p className="text-subtle text-sm">{t("volteire_calendar_hours_hint")}</p>
    </div>
  );
}
