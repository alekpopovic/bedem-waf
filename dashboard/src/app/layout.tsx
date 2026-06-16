import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BedemWAF Dashboard",
  description: "Admin dashboard for BedemWAF",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
