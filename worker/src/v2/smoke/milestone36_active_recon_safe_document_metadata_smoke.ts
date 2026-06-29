import assert from 'node:assert';
import { sanitizeRobotsTxtMetadata, sanitizeSecurityTxtMetadata } from '../recon/active/ActiveReconDocumentSanitizers.js';
import { FakeActiveReconAdapter } from '../recon/active/FakeActiveReconAdapter.js';
import type { AuthorizedScope } from '../recon/policy/EgressPolicyContracts.js';

function runSanitizerTests() {
  console.log('[*] Testing hostile robots.txt sanitizer...');
  const hostileRobots = `
User-agent: sensitive-bot-name
Disallow: /admin?token=SECRET
Allow: /private/path
Sitemap: https://example.com/sitemap.xml?api_key=SECRET
  `;

  const robotsOutput = sanitizeRobotsTxtMetadata(hostileRobots, {
    reachable: true,
    contentTypeLookedTextLike: true,
    bodyTruncated: false
  });

  const robotsJson = JSON.stringify(robotsOutput);
  
  assert.ok(!robotsJson.includes('SECRET'), 'Must not leak SECRET');
  assert.ok(!robotsJson.includes('token'), 'Must not leak token keyword');
  assert.ok(!robotsJson.includes('api_key'), 'Must not leak api_key keyword');
  assert.ok(!robotsJson.includes('sensitive-bot-name'), 'Must not leak actual user agent');
  assert.ok(!robotsJson.includes('/admin'), 'Must not leak actual path');
  assert.ok(!robotsJson.includes('/private'), 'Must not leak actual path');
  assert.ok(!robotsJson.includes('sitemap.xml'), 'Must not leak actual URLs');
  assert.ok(!robotsJson.includes('User-agent:'), 'Must not leak raw lines');

  assert.strictEqual(robotsOutput.hasUserAgentDirective, true);
  assert.strictEqual(robotsOutput.hasDisallowDirective, true);
  assert.strictEqual(robotsOutput.hasAllowDirective, true);
  assert.strictEqual(robotsOutput.hasSitemapDirective, true);
  assert.strictEqual(robotsOutput.recognizedDirectiveLineCount, 4);

  console.log('[+] Hostile robots.txt safely serialized to fixed shape.');

  console.log('[*] Testing hostile security.txt sanitizer...');
  const hostileSecurityTxt = `
Contact: mailto:security@example.com
Contact: https://example.com/report?token=SECRET
Encryption: https://example.com/pgp-key.txt
Policy: https://example.com/security-policy?secret=TOKEN
Canonical: https://example.com/.well-known/security.txt
Acknowledgments: https://example.com/hall-of-fame
Preferred-Languages: en, es
Expires: 2030-12-31T23:59:59Z
# fake PGP public key block or key-like secret
-----BEGIN PGP PUBLIC KEY BLOCK-----
xyzSECRET_KEY_MATERIAL
-----END PGP PUBLIC KEY BLOCK-----
  `;

  const securityTxtOutput = sanitizeSecurityTxtMetadata(hostileSecurityTxt, {
    reachable: true,
    contentTypeLookedTextLike: true,
    bodyTruncated: false
  });

  const securityTxtJson = JSON.stringify(securityTxtOutput);
  
  assert.ok(!securityTxtJson.includes('SECRET'), 'Must not leak SECRET');
  assert.ok(!securityTxtJson.includes('TOKEN'), 'Must not leak TOKEN');
  assert.ok(!securityTxtJson.includes('secret'), 'Must not leak secret keyword');
  assert.ok(!securityTxtJson.includes('mailto:'), 'Must not leak mailto scheme');
  assert.ok(!securityTxtJson.includes('security@example.com'), 'Must not leak email');
  assert.ok(!securityTxtJson.includes('example.com/report'), 'Must not leak report URL');
  assert.ok(!securityTxtJson.includes('pgp-key'), 'Must not leak PGP key path');
  assert.ok(!securityTxtJson.includes('security-policy'), 'Must not leak policy URL');
  assert.ok(!securityTxtJson.includes('.well-known/security.txt'), 'Must not leak canonical URL');
  assert.ok(!securityTxtJson.includes('hall-of-fame'), 'Must not leak hall of fame URL');
  assert.ok(!securityTxtJson.includes('PGP'), 'Must not leak PGP keywords');
  assert.ok(!securityTxtJson.includes('xyzSECRET_KEY_MATERIAL'), 'Must not leak raw body/keys');
  assert.ok(!securityTxtJson.includes('Contact:'), 'Must not leak raw field values');

  assert.strictEqual(securityTxtOutput.hasContactField, true);
  assert.strictEqual(securityTxtOutput.hasEncryptionField, true);
  assert.strictEqual(securityTxtOutput.hasPolicyField, true);
  assert.strictEqual(securityTxtOutput.hasCanonicalField, true);
  assert.strictEqual(securityTxtOutput.hasAcknowledgmentsField, true);
  assert.strictEqual(securityTxtOutput.hasPreferredLanguagesField, true);
  assert.strictEqual(securityTxtOutput.hasExpiresField, true);
  assert.strictEqual(securityTxtOutput.recognizedFieldLineCount, 8); // Contact is there twice

  console.log('[+] Hostile security.txt safely serialized to fixed shape.');
}

async function runFakeAdapterIntegrationTest() {
  console.log('[*] Testing FakeActiveReconAdapter integration...');
  const adapter = new FakeActiveReconAdapter();
  
  const scope: AuthorizedScope = {
    allowedOrigins: ['https://example.com'],
    allowSameHostPaths: true,
    allowSubdomains: false
  };

  const obsRobots = await adapter.probe({
    capabilityId: 'http.robots.inspect',
    targetUrl: 'https://example.com/robots.txt',
    authorizedScope: scope,
    requestedAtMs: Date.now()
  });

  const obsRobotsJson = JSON.stringify(obsRobots);
  assert.ok(!obsRobotsJson.includes('"body":'), 'Must not contain raw body');
  assert.ok(!obsRobotsJson.includes('"headers":'), 'Must not contain headers');
  assert.ok(!obsRobotsJson.includes('"raw":'), 'Must not contain raw');
  assert.ok(!obsRobotsJson.includes('"request":'), 'Must not contain request');
  assert.ok(!obsRobotsJson.includes('"response":'), 'Must not contain response');
  assert.ok(!obsRobotsJson.includes('"payload":'), 'Must not contain payload');
  assert.ok(!obsRobotsJson.includes('"evidence":'), 'Must not contain evidence');
  assert.ok(!obsRobotsJson.includes('"finding":'), 'Must not contain finding');
  assert.ok(!obsRobotsJson.includes('"risk":'), 'Must not contain risk');
  assert.ok(!obsRobotsJson.includes('"severity":'), 'Must not contain severity');
  assert.ok(!obsRobotsJson.includes('"impact":'), 'Must not contain impact');
  assert.ok(!obsRobotsJson.includes('"exploit":'), 'Must not contain exploit');
  assert.ok(!obsRobotsJson.includes('/admin'), 'Fake fixture string must not leak');

  const obsSecurity = await adapter.probe({
    capabilityId: 'http.security_txt.inspect',
    targetUrl: 'https://example.com/.well-known/security.txt',
    authorizedScope: scope,
    requestedAtMs: Date.now()
  });

  const obsSecurityJson = JSON.stringify(obsSecurity);
  assert.ok(!obsSecurityJson.includes('"body":'), 'Must not contain body');
  assert.ok(!obsSecurityJson.includes('"headers":'), 'Must not contain headers');
  assert.ok(!obsSecurityJson.includes('"raw":'), 'Must not contain raw');
  assert.ok(!obsSecurityJson.includes('security@example.com'), 'Fake fixture string must not leak');
  
  console.log('[+] Fake adapter safely integrates fixed shape metadata only.');
}

async function runRealM36Validation() {
  console.log('--- V2 Active Recon Safe Document Metadata Smoke Test ---');
  
  runSanitizerTests();
  await runFakeAdapterIntegrationTest();

  console.log('--- DB-free and Network-free M36 Smoke Completed Successfully ---');
}

runRealM36Validation().catch(err => {
  console.error(err);
  process.exit(1);
});
