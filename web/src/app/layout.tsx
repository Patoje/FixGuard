import type { Metadata } from "next";
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
  title: "FixGuard V2",
  description: "Authorized web security assessment — FixGuard V2",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`dark ${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-black text-white">
        <nav className="w-full border-b border-zinc-800 bg-black/50 backdrop-blur-xl sticky top-0 z-50">
          <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
            <a href="/v2/assessments" className="font-bold tracking-tight text-xl">
              Fix<span className="text-zinc-500">Guard</span>
            </a>
            <div className="flex items-center gap-6 text-sm font-medium">
              <a
                href="/v2/assessments"
                className="text-emerald-400 hover:text-emerald-300 font-semibold transition-colors flex items-center gap-1.5"
              >
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                Assessments
              </a>
              <a
                href="/v2"
                className="text-zinc-400 hover:text-white transition-colors"
              >
                Triage
              </a>
              <a
                href="/v2/attack"
                className="text-zinc-400 hover:text-white transition-colors"
              >
                Attack
              </a>
              <a
                href="/v2/review"
                className="text-zinc-400 hover:text-white transition-colors"
              >
                Review
              </a>
            </div>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
