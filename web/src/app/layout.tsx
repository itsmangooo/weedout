import type { Metadata } from "next";
import Script from "next/script";
import type { ReactNode } from "react";
import "@/ui/styles/globals.css";

export const metadata: Metadata = {
  title: { default: "Weedout", template: "%s · Weedout" },
  description: "Automatic dependency vulnerability findings inside your IDE, with the context to fix them.",
  icons: { icon: "/static/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <Script src="/static/js/theme-boot.js" strategy="beforeInteractive" />
        {children}
      </body>
    </html>
  );
}
