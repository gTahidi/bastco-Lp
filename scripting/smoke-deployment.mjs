import assert from 'node:assert/strict';

const base = new URL(process.argv[2] || 'https://bastco.org');
assert.equal(base.protocol, 'https:', 'Live deployment checks require HTTPS');
assert.equal(
  base.username + base.password,
  '',
  'Do not put credentials in the URL',
);

async function get(path, options = {}) {
  return fetch(new URL(path, base), {
    signal: AbortSignal.timeout(20000),
    ...options,
  });
}

function checkHeaders(response) {
  assert.match(
    response.headers.get('content-security-policy') || '',
    /script-src 'self'/,
  );
  assert.match(
    response.headers.get('content-security-policy') || '',
    /frame-ancestors 'none'/,
  );
  assert.match(
    response.headers.get('content-security-policy-report-only') || '',
    /default-src 'self'/,
  );
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(
    response.headers.get('strict-transport-security'),
    'max-age=31536000',
  );
}

const home = await get('/');
assert.equal(home.status, 200);
checkHeaders(home);
assert.ok(!home.headers.get('cache-control')?.includes('immutable'));
assert.ok(home.headers.get('cache-control')?.includes('no-transform'));
const html = await home.text();
assert.match(html, /<link rel="canonical" href="https:\/\/bastco\.org\/"/);
assert.match(html, /<title>Kifaru, your AI red teammate \| Bastco<\/title>/);
assert.doesNotMatch(html, /<astro-island\b|<iframe\b/);
if (base.hostname.endsWith('.workers.dev')) {
  assert.equal(home.headers.get('x-robots-tag'), 'noindex');
} else {
  assert.notEqual(home.headers.get('x-robots-tag'), 'noindex');
}

for (const path of ['/kifaru/', '/blog/', '/security/', '/privacy/']) {
  const response = await get(path);
  assert.equal(response.status, 200, path);
  checkHeaders(response);
  assert.ok(
    response.headers.get('cache-control')?.includes('no-transform'),
    path,
  );
}

const asset = html.match(/href="(\/_astro\/[^" ]+\.css)"/)?.[1];
assert.ok(asset, 'Expected a hashed stylesheet');
const stylesheet = await get(asset);
assert.equal(stylesheet.status, 200);
assert.equal(
  stylesheet.headers.get('cache-control'),
  'public, max-age=31536000, immutable',
);

const missing = await get('/this-page-does-not-exist');
assert.equal(missing.status, 404);
checkHeaders(missing);
assert.match(await missing.text(), /Let’s get you/);

const cleanPath = await get('/kifaru', { redirect: 'manual' });
assert.equal(cleanPath.status, 307);
assert.equal(
  new URL(cleanPath.headers.get('location'), base).pathname,
  '/kifaru/',
);
console.log(
  `Deployment checks passed: ${base.origin} (pages, CSP, headers, caching, routing, 404)`,
);
