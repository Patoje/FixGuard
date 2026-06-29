import type { EgressPolicyDecision } from '../policy/EgressPolicyContracts.js';
import type { ActiveReconProbeKind, ActiveReconProbeResult, SafeActiveReconObservation } from './ActiveReconContracts.js';

export function mapActiveReconResult(
  capabilityId: ActiveReconProbeKind,
  decision: EgressPolicyDecision,
  observations: SafeActiveReconObservation[] = []
): ActiveReconProbeResult {
  const classification = {
    finding: false as const,
    evidence: false as const,
    vulnerability: false as const,
    riskClaim: false as const,
  };

  const getSafeScheme = (scheme: string) => scheme.replace(':', '') as 'http' | 'https';
  const getSafeOrigin = (nt: { scheme: string; hostname: string; port: string }) => {
    const s = getSafeScheme(nt.scheme);
    const p = nt.port;
    const isDefault = (s === 'http' && p === '80') || (s === 'https' && p === '443');
    return `${s}://${nt.hostname}${isDefault ? '' : ':' + p}`;
  };

  const target = {
    safeDisplayUrl: decision.safeDisplayUrl || 'unknown',
    ...(decision.decision === 'allow' || decision.decision === 'block'
      ? (decision.normalizedTarget && {
          scheme: getSafeScheme(decision.normalizedTarget.scheme),
          hostname: decision.normalizedTarget.hostname,
          normalizedOrigin: getSafeOrigin(decision.normalizedTarget)
        })
      : {})
  };

  return {
    capabilityId,
    status: decision.decision === 'allow' ? 'observed' : (decision.decision === 'block' ? 'blocked' : decision.decision),
    policyDecision: decision.decision,
    target,
    observations: decision.decision === 'allow' ? observations : [],
    classification
  };
}
