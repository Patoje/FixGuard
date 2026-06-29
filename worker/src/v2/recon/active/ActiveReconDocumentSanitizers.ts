import type { SafeRobotsTxtMetadata, SafeSecurityTxtMetadata } from './ActiveReconContracts.js';

export interface SanitizerContextOptions {
  reachable?: boolean;
  contentTypeLookedTextLike?: boolean;
  bodyTruncated?: boolean;
}

export function sanitizeRobotsTxtMetadata(
  body: string,
  context: SanitizerContextOptions
): SafeRobotsTxtMetadata {
  const lines = body.split(/\r?\n/);
  
  let recognizedDirectiveLineCount = 0;
  let hasUserAgentDirective = false;
  let hasDisallowDirective = false;
  let hasAllowDirective = false;
  let hasSitemapDirective = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const lowerLine = trimmed.toLowerCase();
    
    if (lowerLine.startsWith('user-agent:')) {
      hasUserAgentDirective = true;
      recognizedDirectiveLineCount++;
    } else if (lowerLine.startsWith('disallow:')) {
      hasDisallowDirective = true;
      recognizedDirectiveLineCount++;
    } else if (lowerLine.startsWith('allow:')) {
      hasAllowDirective = true;
      recognizedDirectiveLineCount++;
    } else if (lowerLine.startsWith('sitemap:')) {
      hasSitemapDirective = true;
      recognizedDirectiveLineCount++;
    }
  }

  return {
    reachable: context.reachable,
    contentTypeLookedTextLike: context.contentTypeLookedTextLike,
    bodyTruncated: context.bodyTruncated,
    recognizedDirectiveLineCount,
    hasUserAgentDirective,
    hasDisallowDirective,
    hasAllowDirective,
    hasSitemapDirective,
  };
}

export function sanitizeSecurityTxtMetadata(
  body: string,
  context: SanitizerContextOptions
): SafeSecurityTxtMetadata {
  const lines = body.split(/\r?\n/);

  let recognizedFieldLineCount = 0;
  let hasContactField = false;
  let hasExpiresField = false;
  let hasEncryptionField = false;
  let hasAcknowledgmentsField = false;
  let hasPreferredLanguagesField = false;
  let hasCanonicalField = false;
  let hasPolicyField = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const lowerLine = trimmed.toLowerCase();
    
    if (lowerLine.startsWith('contact:')) {
      hasContactField = true;
      recognizedFieldLineCount++;
    } else if (lowerLine.startsWith('expires:')) {
      hasExpiresField = true;
      recognizedFieldLineCount++;
    } else if (lowerLine.startsWith('encryption:')) {
      hasEncryptionField = true;
      recognizedFieldLineCount++;
    } else if (lowerLine.startsWith('acknowledgments:')) {
      hasAcknowledgmentsField = true;
      recognizedFieldLineCount++;
    } else if (lowerLine.startsWith('preferred-languages:')) {
      hasPreferredLanguagesField = true;
      recognizedFieldLineCount++;
    } else if (lowerLine.startsWith('canonical:')) {
      hasCanonicalField = true;
      recognizedFieldLineCount++;
    } else if (lowerLine.startsWith('policy:')) {
      hasPolicyField = true;
      recognizedFieldLineCount++;
    }
  }

  return {
    reachable: context.reachable,
    contentTypeLookedTextLike: context.contentTypeLookedTextLike,
    bodyTruncated: context.bodyTruncated,
    recognizedFieldLineCount,
    hasContactField,
    hasExpiresField,
    hasEncryptionField,
    hasAcknowledgmentsField,
    hasPreferredLanguagesField,
    hasCanonicalField,
    hasPolicyField,
  };
}
