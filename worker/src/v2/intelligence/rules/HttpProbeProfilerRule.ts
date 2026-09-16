import type { CorrelatedFinding } from '../CorrelatedFinding';
import type { TargetProfile } from '../TargetProfile';
import type { ProfilerRule } from '../ProfilerRule';

interface HttpServiceMetadata {
  url: string;
  host: string;
  statusCode: number;
  title: string | undefined;
  webserver: string | undefined;
  technologies: string[];
  scheme: string;
  finalUrl: string | undefined;
  sourceFindingIds: string[];
}

export class HttpProbeProfilerRule implements ProfilerRule {
  readonly id = 'PR-HTTP-PROBE-001';
  readonly description = 'Extracts live HTTP services into the profile';

  applies(findings: CorrelatedFinding[]): boolean {
    return findings.some(f => f.type === 'http_live_host');
  }

  enrich(profile: TargetProfile, findings: CorrelatedFinding[]): TargetProfile {
    const probeFindings = findings.filter(f => f.type === 'http_live_host');
    if (probeFindings.length === 0) {
      return profile;
    }

    const newExposedCapabilities = Array.from(new Set([...profile.exposedCapabilities, 'http_service_detected']));
    
    // Deep copy technologies so we don't mutate the existing array directly
    const updatedTechnologies = [...profile.technologies];
    
    const existingHttpServices: HttpServiceMetadata[] = Array.isArray(profile.metadata.httpServices) 
      ? [...(profile.metadata.httpServices as HttpServiceMetadata[])] 
      : [];

    const newSourceFindingIds = [...profile.sourceFindingIds];

    for (const f of probeFindings) {
      const meta = f.representativeFinding.metadata;
      const metaRecord = meta?.kind === 'discovery_finding_metadata' ? meta : undefined;
      const url = f.representativeFinding.target;

      const techList: string[] = metaRecord?.technologies ? [...metaRecord.technologies] : [];
      for (const t of techList) {
        const existingTech = updatedTechnologies.find(tech => tech.name === t);
        if (!existingTech) {
          updatedTechnologies.push({
            name: t,
            confidence: f.combinedConfidence
          });
        }
      }

      for (const id of f.sourceFindingIds) {
        if (!newSourceFindingIds.includes(id)) {
          newSourceFindingIds.push(id);
        }
      }

      const existingIndex = existingHttpServices.findIndex(s => s.url === url);
      const serviceData: HttpServiceMetadata = {
        url,
        host: typeof metaRecord?.host === 'string' ? metaRecord.host : '',
        statusCode: typeof metaRecord?.statusCode === 'number' ? metaRecord.statusCode : 0,
        title: typeof metaRecord?.title === 'string' ? metaRecord.title : undefined,
        webserver: typeof metaRecord?.webserver === 'string' ? metaRecord.webserver : undefined,
        technologies: techList,
        scheme: typeof metaRecord?.scheme === 'string' ? metaRecord.scheme : '',
        finalUrl: typeof metaRecord?.finalUrl === 'string' ? metaRecord.finalUrl : undefined,
        sourceFindingIds: [...f.sourceFindingIds]
      };

      if (existingIndex >= 0) {
        existingHttpServices[existingIndex] = serviceData;
      } else {
        existingHttpServices.push(serviceData);
      }
    }

    return {
      ...profile,
      technologies: updatedTechnologies,
      exposedCapabilities: newExposedCapabilities,
      sourceFindingIds: newSourceFindingIds,
      metadata: {
        ...profile.metadata,
        httpServices: existingHttpServices
      }
    };
  }
}
