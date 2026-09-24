/**
 * Honest severity presentation for Evidence Triage / findings cards.
 * Aligns with FindingAutoPromotionPolicy: soft/cosmetic stays low/info;
 * confirmed access-control / chain signals rate higher. Never invent Critical
 * for missing headers alone.
 */

export type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";

export type SeverityPresentation = {
  readonly level: SeverityLevel;
  readonly label: string;
  readonly badgeClass: string;
};

const GREEN =
  "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
const YELLOW =
  "border-yellow-400/40 bg-yellow-400/10 text-yellow-200";
const ORANGE =
  "border-orange-500/40 bg-orange-500/15 text-orange-300";
const RED = "border-rose-500/50 bg-rose-500/20 text-rose-300";

/** Detection kinds that stay cosmetic / discovery — green (info/low). */
const LOW_INFO_KINDS = new Set<string>([
  "missing_security_headers",
  "wordpress_surface",
  "graphql_surface",
  "api_versioning_sprawl",
  "manifest_exposure",
  "object_mapping_anomaly",
  "state_transition_anomaly",
  "custom_difference",
  "static_route_extraction",
  "attack_surface_delta",
  "sourcemap_exposure",
]);

/** Confirmed access / authz / chain signals — orange (high). */
const HIGH_KINDS = new Set<string>([
  "idor_access_control",
  "auth_bypass",
  "credentialed_cors",
  "cors_idor_compound",
  "cross_finding_chain",
  "jwt_algorithm_confusion",
  "session_fixation",
  "blind_ssrf",
  "blind_xss",
  "oob_canary_interaction",
  "subdomain_takeover",
  "static_secret_exposure",
  "sql_error_oracle",
  "dependency_confusion",
]);

/** Meaningful misconfig / disclosure with attack value — light yellow (medium). */
const MEDIUM_KINDS = new Set<string>([
  "cors_misconfiguration",
  "parameter_reflection",
  "open_redirect",
  "parameter_integrity",
  "http_method_manipulation",
  "cms_plugin_vulnerability",
  "weak_tls_configuration",
  "dependency_vulnerability",
  "information_disclosure",
]);

/** Rare critical — only for explicit critical finding severity, not detection kinds by default. */
function normalizeFindingSeverity(raw: string | undefined): SeverityLevel | null {
  if (!raw) return null;
  const s = raw.toLowerCase().trim();
  if (s === "critical") return "critical";
  if (s === "high" || s === "elevated") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low" || s === "lowest") return "low";
  if (s === "info" || s === "informational" || s === "weak") return "info";
  return null;
}

export function severityFromDetectionKind(
  detectionKind: string | undefined,
  options?: {
    readonly disclosureKind?: string;
    readonly findingSeverity?: string;
  }
): SeverityLevel {
  const fromFinding = normalizeFindingSeverity(options?.findingSeverity);
  if (fromFinding === "critical") return "critical";

  const kind = detectionKind ?? "";

  if (kind === "information_disclosure") {
    if (
      options?.disclosureKind === "stack_trace" ||
      options?.disclosureKind === "internal_path"
    ) {
      return "medium";
    }
    return "info";
  }

  if (kind === "missing_security_headers") return "info";

  if (LOW_INFO_KINDS.has(kind)) return "low";
  if (HIGH_KINDS.has(kind)) return "high";
  if (MEDIUM_KINDS.has(kind)) return "medium";

  if (fromFinding) return fromFinding;

  // Unknown draft without kind: do not inflate.
  return "low";
}

export function presentSeverity(level: SeverityLevel): SeverityPresentation {
  switch (level) {
    case "critical":
      return { level, label: "Critical", badgeClass: RED };
    case "high":
      return { level, label: "High", badgeClass: ORANGE };
    case "medium":
      return { level, label: "Medium", badgeClass: YELLOW };
    case "low":
      return { level, label: "Low", badgeClass: GREEN };
    case "info":
    default:
      return { level: "info", label: "Info", badgeClass: GREEN };
  }
}

const KIND_TITLES: Readonly<Record<string, string>> = {
  missing_security_headers: "Missing security headers",
  idor_access_control: "Broken access control (IDOR / BOLA)",
  auth_bypass: "Authentication bypass signal",
  cors_misconfiguration: "CORS misconfiguration",
  credentialed_cors: "Credentialed CORS reflection",
  parameter_reflection: "Parameter reflection",
  open_redirect: "Open redirect",
  information_disclosure: "Information disclosure",
  subdomain_takeover: "Subdomain takeover signal",
  weak_tls_configuration: "Weak TLS configuration",
  sourcemap_exposure: "Source map exposure",
  wordpress_surface: "WordPress surface observation",
  sql_error_oracle: "SQL error oracle",
  graphql_surface: "GraphQL surface observation",
  jwt_algorithm_confusion: "JWT algorithm confusion signal",
  session_fixation: "Session fixation signal",
  cms_plugin_vulnerability: "CMS plugin vulnerability signal",
  cors_idor_compound: "CORS + IDOR compound chain",
  api_versioning_sprawl: "API version sprawl",
  http_method_manipulation: "HTTP method manipulation",
  dependency_confusion: "Dependency confusion signal",
  manifest_exposure: "Manifest exposure",
  parameter_integrity: "Parameter integrity gap",
  object_mapping_anomaly: "Object mapping anomaly",
  state_transition_anomaly: "State transition anomaly",
  attack_surface_delta: "Attack surface delta",
  cross_finding_chain: "Cross-finding chain",
  static_secret_exposure: "Static secret exposure",
  dependency_vulnerability: "Dependency vulnerability",
  static_route_extraction: "Static route extraction",
  oob_canary_interaction: "Out-of-band canary interaction",
  blind_ssrf: "Blind SSRF signal",
  blind_xss: "Blind XSS signal",
  custom_difference: "Response difference (review)",
};

const KIND_WHY: Readonly<Record<string, string>> = {
  missing_security_headers:
    "Hardening gap only — does not prove an exploitable vulnerability by itself.",
  idor_access_control:
    "Different identities may reach the same resource; this can mean unauthorized data access.",
  auth_bypass:
    "A request without proper auth may still receive privileged content.",
  cors_misconfiguration:
    "Browsers may be tricked into reading responses from another origin.",
  credentialed_cors:
    "Reflected origin with credentials enables cross-origin authenticated theft.",
  parameter_reflection:
    "Unescaped reflection can become XSS if the sink is executable.",
  open_redirect:
    "Attackers can bounce users through your domain to a malicious site.",
  information_disclosure:
    "Leaked internals help attackers map the stack; stack traces matter more than banners.",
  subdomain_takeover:
    "An abandoned hostname may be claimable by a third party.",
  weak_tls_configuration:
    "Weak protocols/ciphers weaken transport confidentiality.",
  sourcemap_exposure:
    "Source maps can leak original source structure (usually low urgency).",
  wordpress_surface:
    "Surface observation for optional review — not an auto-finding.",
  sql_error_oracle:
    "Database errors can confirm injectable input handling.",
  graphql_surface:
    "GraphQL features observed — review whether introspection/batching is intentional.",
  jwt_algorithm_confusion:
    "Token algorithm confusion can bypass signature checks.",
  session_fixation:
    "Fixed session IDs can let an attacker hijack a login.",
  cms_plugin_vulnerability:
    "Outdated plugins are a common remote compromise path.",
  cors_idor_compound:
    "CORS plus access-control gap compounds into cross-origin data theft.",
  http_method_manipulation:
    "Override tricks may expose privileged verbs without auth.",
  dependency_confusion:
    "Unclaimed public packages can be hijacked for supply-chain install.",
  static_secret_exposure:
    "Embedded secrets can unlock accounts, APIs, or repos.",
  blind_ssrf:
    "Confirmed out-of-band fetch means the server contacted an attacker-controlled host.",
  blind_xss:
    "Confirmed callback means stored/reflected XSS reached a browser context.",
  oob_canary_interaction:
    "Confirmed callback interaction strengthens the related finding.",
};

export function draftPlainTitle(
  detectionKind: string | undefined,
  suggestedEvidenceType: string
): string {
  if (detectionKind && KIND_TITLES[detectionKind]) {
    return KIND_TITLES[detectionKind]!;
  }
  return suggestedEvidenceType.replace(/_/g, " ");
}

export function draftWhyItMatters(
  detectionKind: string | undefined,
  safeRationale: string
): string {
  if (detectionKind && KIND_WHY[detectionKind]) {
    return KIND_WHY[detectionKind]!;
  }
  return safeRationale;
}
