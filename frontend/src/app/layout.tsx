import type { Metadata } from "next";
import Link from "next/link";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "IPsec VPN Protocol Analyzer",
  description:
    "Determines the security posture of an IPsec deployment from captured traffic alone.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col bg-zinc-50 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
        <header className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
            <Link href="/" className="flex items-baseline gap-3">
              <span className="text-base font-semibold tracking-tight">IPsec Analyzer</span>
              <span className="hidden text-xs text-zinc-500 sm:inline dark:text-zinc-400">
                security posture from captured traffic alone
              </span>
            </Link>
            <nav className="flex items-center gap-5 text-sm">
              <Link href="/" className="hover:text-sky-700 dark:hover:text-sky-400">
                Captures
              </Link>
              <Link href="/compare" className="hover:text-sky-700 dark:hover:text-sky-400">
                Compare
              </Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-6 py-8">{children}</main>
        <footer className="border-t border-zinc-200 px-6 py-4 text-xs text-zinc-500 dark:border-zinc-800 dark:text-zinc-400">
          Every reported value is tagged observed, inferred, or unavailable. Unavailable is an
          answer, not a gap.
        </footer>
      </body>
    </html>
  );
}
