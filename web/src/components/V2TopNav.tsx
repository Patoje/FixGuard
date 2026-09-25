"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

/**
 * Minimal chrome: brand centered.
 * Hidden on /v2 launch (stage 1 owns the hero brand).
 * Wizard stepper on /v2 owns the assessment flow — not this nav.
 */
export function V2TopNav() {
  const pathname = usePathname();
  const isLaunchHome = pathname === "/v2" || pathname === "/v2/";

  if (isLaunchHome) {
    return null;
  }

  return (
    <nav className="w-full border-b border-zinc-800 bg-black/50 backdrop-blur-xl sticky top-0 z-50">
      <div className="relative max-w-6xl mx-auto px-6 h-16 flex items-center justify-center">
        <Link
          href="/v2"
          className="font-bold tracking-tight text-xl text-center"
        >
          Fix<span className="text-zinc-500">Guard</span>
        </Link>
      </div>
    </nav>
  );
}
