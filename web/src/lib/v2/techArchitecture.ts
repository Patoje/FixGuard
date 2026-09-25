/**
 * Classify TargetProfile / fingerprint into operator-facing Spanish labels.
 * Versions only when OBSERVED on detectedTechnologies.
 */

import type { TargetProfileDto } from "@/lib/v2Api";

export type TechEpistemic = "OBSERVED" | "INFERRED";

export type TechItem = {
  readonly name: string;
  readonly version?: string;
  readonly epistemic: TechEpistemic;
};

export type TechGroup = {
  readonly label: string;
  readonly items: readonly TechItem[];
};

export type TechArchitectureView = {
  readonly groups: readonly TechGroup[];
  readonly hostHint: string | null;
};

function pushUnique(
  map: Map<string, TechItem>,
  key: string,
  item: TechItem
): void {
  const existing = map.get(key);
  if (!existing) {
    map.set(key, item);
    return;
  }
  // Prefer OBSERVED + version over INFERRED.
  if (
    item.epistemic === "OBSERVED" &&
    (existing.epistemic !== "OBSERVED" ||
      (item.version && !existing.version))
  ) {
    map.set(key, item);
  }
}

export function classifyTechArchitecture(
  profile: TargetProfileDto | null | undefined
): TechArchitectureView {
  if (!profile) {
    return { groups: [], hostHint: null };
  }

  const frameworks = new Map<string, TechItem>();
  const languages = new Map<string, TechItem>();
  const hosting = new Map<string, TechItem>();
  const databases = new Map<string, TechItem>();
  const services = new Map<string, TechItem>();

  const eco = profile.ecosystemProfile;
  const detected = profile.detectedTechnologies ?? [];
  const techNames = profile.technologies ?? [];

  for (const t of detected) {
    const name = t.name.trim();
    if (!name) continue;
    const lower = name.toLowerCase();
    const item: TechItem = {
      name,
      ...(t.version ? { version: t.version } : {}),
      epistemic: "OBSERVED",
    };
    const cat = t.category.toLowerCase();
    // Order matters: language / data / hosting before generic "framework" category.
    if (
      cat === "runtime" ||
      cat === "language" ||
      /^(javascript|typescript|node\.?js|python|php|ruby|go|java|kotlin|swift|rust)$/i.test(
        lower
      )
    ) {
      pushUnique(languages, lower, item);
    } else if (
      cat === "database" ||
      /postgres|mysql|mongo|redis|supabase/i.test(lower)
    ) {
      pushUnique(databases, lower, item);
    } else if (/postgrest/i.test(lower)) {
      pushUnique(services, "postgrest", { ...item, name: "PostgREST" });
    } else if (
      cat === "cdn" ||
      cat === "server" ||
      cat === "hosting" ||
      /vercel|netlify|cloudflare|aws|azure|heroku|fastly/i.test(lower)
    ) {
      pushUnique(hosting, lower, item);
    } else if (
      cat === "framework" ||
      cat === "frontend" ||
      /next|react|vue|angular|nuxt|svelte/i.test(lower)
    ) {
      pushUnique(frameworks, lower, item);
    } else {
      pushUnique(services, lower, item);
    }
  }

  // Ecosystem heuristics (INFERRED unless already OBSERVED)
  if (eco?.spaFramework === "nextjs") {
    pushUnique(frameworks, "next.js", {
      name: "Next.js",
      epistemic: "INFERRED",
    });
    pushUnique(frameworks, "react", { name: "React", epistemic: "INFERRED" });
  } else if (eco?.spaFramework === "react") {
    pushUnique(frameworks, "react", { name: "React", epistemic: "INFERRED" });
  } else if (eco?.spaFramework === "vue") {
    pushUnique(frameworks, "vue", { name: "Vue", epistemic: "INFERRED" });
  } else if (eco?.spaFramework === "angular") {
    pushUnique(frameworks, "angular", {
      name: "Angular",
      epistemic: "INFERRED",
    });
  } else if (eco?.spaFramework === "nuxtjs") {
    pushUnique(frameworks, "nuxt", { name: "Nuxt", epistemic: "INFERRED" });
  }

  if (eco?.hasSpa && frameworks.size === 0) {
    pushUnique(frameworks, "spa", {
      name: "SPA (frontend)",
      epistemic: "INFERRED",
    });
  }

  if (eco?.hasSupabase) {
    pushUnique(databases, "supabase", {
      name: "Supabase",
      epistemic: "INFERRED",
    });
  }
  if (eco?.hasPostgrest) {
    pushUnique(services, "postgrest", {
      name: "PostgREST",
      epistemic: "INFERRED",
    });
  }
  if (eco?.hasGraphQL) {
    pushUnique(services, "graphql", {
      name: "GraphQL",
      epistemic: "INFERRED",
    });
  }
  if (eco?.hasCms && eco.cmsType) {
    const cmsLabel =
      eco.cmsType === "wordpress"
        ? "WordPress"
        : eco.cmsType === "joomla"
          ? "Joomla"
          : eco.cmsType === "drupal"
            ? "Drupal"
            : "CMS";
    pushUnique(frameworks, `cms-${eco.cmsType}`, {
      name: cmsLabel,
      epistemic: "INFERRED",
    });
  }

  for (const raw of techNames) {
    const name = raw.trim();
    if (!name) continue;
    const lower = name.toLowerCase();
    if (/next/i.test(lower)) {
      pushUnique(frameworks, "next.js", {
        name: "Next.js",
        epistemic: "INFERRED",
      });
    } else if (/react/i.test(lower)) {
      pushUnique(frameworks, "react", {
        name: "React",
        epistemic: "INFERRED",
      });
    } else if (/vercel/i.test(lower)) {
      pushUnique(hosting, "vercel", {
        name: "Vercel",
        epistemic: "INFERRED",
      });
    } else if (/supabase/i.test(lower)) {
      pushUnique(databases, "supabase", {
        name: "Supabase",
        epistemic: "INFERRED",
      });
    } else if (/javascript|typescript|node/i.test(lower)) {
      pushUnique(languages, lower, { name, epistemic: "INFERRED" });
    }
  }

  // Hosting hint from hostname
  const host = profile.targetHost.toLowerCase();
  if (host.endsWith(".vercel.app") || host.includes("vercel")) {
    pushUnique(hosting, "vercel", { name: "Vercel", epistemic: "INFERRED" });
  }
  if (host.includes("supabase.co")) {
    pushUnique(databases, "supabase", {
      name: "Supabase",
      epistemic: "INFERRED",
    });
  }
  if (host.endsWith(".netlify.app")) {
    pushUnique(hosting, "netlify", {
      name: "Netlify",
      epistemic: "INFERRED",
    });
  }

  // JS language soft hint when SPA/Next observed
  if (
    (frameworks.has("next.js") ||
      frameworks.has("react") ||
      eco?.hasSpa) &&
    languages.size === 0
  ) {
    pushUnique(languages, "javascript", {
      name: "JavaScript",
      epistemic: "INFERRED",
    });
  }

  const groups: TechGroup[] = [];
  if (frameworks.size > 0) {
    groups.push({
      label: "Frameworks",
      items: [...frameworks.values()],
    });
  }
  if (hosting.size > 0) {
    groups.push({ label: "Hosting / cloud", items: [...hosting.values()] });
  }
  if (languages.size > 0) {
    groups.push({
      label: "Tecnologías / Lenguajes",
      items: [...languages.values()],
    });
  }
  if (databases.size > 0) {
    groups.push({
      label: "Bases / datos",
      items: [...databases.values()],
    });
  }
  if (services.size > 0) {
    groups.push({ label: "Servicios", items: [...services.values()] });
  }

  return {
    groups,
    hostHint: profile.targetHost || null,
  };
}
