/**
 * R9 — HTML fields already in a downloaded body. No form submit and no action fetch.
 */
import assert from 'node:assert/strict';
import { Socket } from 'node:net';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import { factsFromCapturedRecon } from '../observation/CapturedHostFacts.js';
import { extractHtmlDocumentFields } from '../recon/analysis/HtmlRouteExtractionService.js';

const COOKIE_SECRET = 'fg_cookie_secret_r9';
const ACTION = '/login';
const METHOD = 'POST';
const INPUT_NAME = 'email';
const INPUT_TYPE = 'email';
const COMMENT_PATH = '/admin/health';
const OBSERVED_AT = '2026-09-28T12:00:00.000Z';

function lineage(): AuthorizedExecutionLineageTuple {
  return {
    assessmentId: 'asmt_r9_001',
    scanId: 'scn_r9_001',
    authorizationGrantId: 'grnt_r9_001',
    authorizationDecisionId: 'dec_r9_001',
    actorId: 'usr_secops_api',
  };
}

function assertNoSocket(run: () => void): void {
  const originalConnect = Socket.prototype.connect;
  const originalFetch = globalThis.fetch;
  let opened = 0;
  let fetched = 0;
  function countingConnect(this: Socket): Socket {
    opened += 1;
    return this;
  }
  Socket.prototype.connect = countingConnect as typeof Socket.prototype.connect;
  globalThis.fetch = async () => {
    fetched += 1;
    throw new Error('transport must not run');
  };
  try {
    run();
  } finally {
    Socket.prototype.connect = originalConnect;
    globalThis.fetch = originalFetch;
  }
  assert.equal(opened, 0);
  assert.equal(fetched, 0);
}

function main(): void {
  const body = [
    `<form action="${ACTION}" method="${METHOD}">`,
    `<input name="${INPUT_NAME}" type="${INPUT_TYPE}" value="${COOKIE_SECRET}">`,
    `</form>`,
    `<!-- keep ${COOKIE_SECRET} off the fact; path ${COMMENT_PATH} -->`,
  ].join('');
  assertNoSocket(() => {
    const extracted = extractHtmlDocumentFields(body);
    assert.equal(extracted.inputs.length, 1);
    assert.equal(extracted.inputs[0]?.action, ACTION);
    assert.equal(extracted.inputs[0]?.method, METHOD);
    assert.equal(extracted.inputs[0]?.name, INPUT_NAME);
    assert.equal(extracted.inputs[0]?.type, INPUT_TYPE);
    assert.equal(extracted.comments.includes(COMMENT_PATH), true);
    const facts = factsFromCapturedRecon({
      webs: [{ url: 'https://app.example.com/', bodyText: body, headers: {} }],
      dns: [],
      tls: [],
      externalDependencies: [],
      technologies: [],
      lineage: lineage(),
      observedAt: OBSERVED_AT,
    });
    const fields = facts.filter((fact) => fact.factKind === 'observed_html_field');
    const joined = fields.map((fact) => fact.value).join('\n');
    assert.equal(joined.includes(`action=${ACTION}`), true);
    assert.equal(joined.includes(`method=${METHOD}`), true);
    assert.equal(joined.includes(`name=${INPUT_NAME}`), true);
    assert.equal(joined.includes(`type=${INPUT_TYPE}`), true);
    assert.equal(joined.includes(`comment=${COMMENT_PATH}`), true);
    assert.equal(joined.includes(COOKIE_SECRET), false);
    const plain = '<html><p>no form</p><!-- nothing useful --></html>';
    const skipped = extractHtmlDocumentFields(plain);
    assert.equal(skipped.inputs.length, 0);
    assert.equal(skipped.comments.length, 0);
  });
  console.log('[milestone_r9_html_fields_smoke] ALL PASSED');
}

main();
