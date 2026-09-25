"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

/**
 * Minimal chrome: brand + optional back to launch.
 * Wizard stepper on /v2 owns the assessment flow — not this nav.
 */
export function V2TopNav() {
  const pathname = usePathname();
  const showBack =
    pathname.startsWith("/v2/") &&
    pathname !== "/v2" &&
    !pathname.startsWith("/v2?");

  return (
    <nav className="w-full border-b border-zinc-800 bg-black/50 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        <Link href="/v2" className="font-bold tracking-tight text-xl">
          Fix<span className="text-zinc-500">Guard</span>
        </Link>
        {showBack ? (
          <Link
            href="/v2"
            className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            ← Volver
          </Link>
        ) : null}
      </div>
    </nav>
  );
}
