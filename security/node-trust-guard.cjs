'use strict';

// Load before application HTTP clients in every Node thread. This replaces
// only the incident's exact trust anchors and preserves private/custom CAs.
// tls.setDefaultCACertificates is available from Node 22.19.0.
const tls = require('node:tls');
const https = require('node:https');
const { X509Certificate } = require('node:crypto');
const blocked = new Set([
  '7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D',
  'F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5',
  'D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4',
  '86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B',
]);
function fingerprint(pem) {
  return new X509Certificate(pem).fingerprint256.replaceAll(':', '').toUpperCase();
}
function install() {
  if (typeof tls.setDefaultCACertificates !== 'function' || typeof tls.getCACertificates !== 'function') {
    throw new Error('Security trust guard requires Node >=22.19 with default CA replacement support');
  }
  const before = tls.getCACertificates('default');
  const after = before.filter((pem) => !blocked.has(fingerprint(pem)));
  if (!after.length) throw new Error('Refusing an empty TLS trust store');
  tls.setDefaultCACertificates(after);
  // Agents constructed later inherit the new TLS defaults. Set the global
  // HTTPS agent explicitly too, before it can cache any application sessions.
  https.globalAgent.options.ca = after;
  if (tls.getCACertificates('default').some((pem) => blocked.has(fingerprint(pem)))) {
    throw new Error('Incident roots remain after default trust replacement');
  }
  return Object.freeze({ policy: 'emudhra-exact-roots-20261022', node: process.version, removed: before.length - after.length, certificates: after.length });
}
const receipt = install();
module.exports = { install, receipt };
