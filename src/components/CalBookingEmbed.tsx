import Cal, { getCalApi } from "@calcom/embed-react";
import { useEffect } from "react";

const NAMESPACE = "bastco-15min";

const CalBookingEmbed = () => {
  useEffect(() => {
    (async () => {
      const cal = await getCalApi({ namespace: NAMESPACE });
      cal("ui", {
        hideEventTypeDetails: true,
        layout: "month_view",
        theme: "dark",
        styles: {
          branding: {
            brandColor: "#00aeef",
          },
          typography: {
            fontFamily: "var(--font-body)",
            fontColor: "#e8f4f8",
          },
        },
      });
    })();
  }, []);

  return (
    <Cal
      namespace={NAMESPACE}
      calLink="bastco/15min"
      className="w-full"
      style={{
        width: "100%",
        minWidth: "100%",
        maxWidth: "100%",
        minHeight: "480px",
        maxHeight: "540px",
        overflow: "auto",
        border: "none",
        backgroundColor: "transparent",
        fontFamily: "var(--font-body)",
        color: "var(--color-bs-foreground-light)",
        scrollbarWidth: "thin",
        display: "block",
        padding: "0",
      }}
      config={{ layout: "week_view" }}
    />
  );
};

export default CalBookingEmbed;
