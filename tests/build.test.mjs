import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, mkdtemp, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const read = (path) => readFile(path, 'utf8');
async function htmlFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (
    await Promise.all(
      entries.map((entry) =>
        entry.isDirectory()
          ? htmlFiles(join(directory, entry.name))
          : entry.name.endsWith('.html')
            ? [join(directory, entry.name)]
            : [],
      ),
    )
  ).flat();
}

test('the built artifact ships Workers security controls and a real 404 page', async () => {
  const source = await read('public/_headers');
  assert.equal(await read('dist/_headers'), source);
  assert.match(source, /X-Content-Type-Options: nosniff/);
  assert.match(source, /X-Frame-Options: DENY/);
  assert.match(source, /Content-Security-Policy: script-src 'self';/);
  assert.match(source, /frame-ancestors 'none'/);
  assert.match(source, /object-src 'none'/);
  assert.doesNotMatch(source, /unsafe-eval/);
  assert.match(source, /frame-src https:\/\/cal.com https:\/\/app.cal.com/);
  assert.match(source, /Cache-Control: public, max-age=31536000, immutable/);
  const config = JSON.parse(await read('wrangler.json'));
  assert.equal(config.assets.directory, './dist');
  assert.equal(config.assets.not_found_handling, '404-page');
  assert.equal(config.assets.html_handling, 'auto-trailing-slash');
  assert.equal(config.workers_dev, true);
  assert.equal(config.env.production.workers_dev, false);
  assert.deepEqual(config.env.production.routes, [
    { pattern: 'bastco.org', custom_domain: true },
  ]);
  assert.match(await read('dist/404.html'), /Page not found/);
  await assert.rejects(read('dist/staticwebapp.config.json'));
});

test('all internal page links and local assets resolve in the static artifact', async () => {
  const files = await htmlFiles('dist');
  assert.ok(files.length >= 13);
  for (const file of files) {
    const html = await read(file);
    for (const [, url] of html.matchAll(
      /(?:href|src)="(\/[^"?#]*)(?:[?#][^"]*)?"/g,
    )) {
      const path = decodeURIComponent(url).replace(/^\//, '');
      if (path.startsWith('/')) continue;
      const candidates = [join('dist', path), join('dist', path, 'index.html')];
      let found = false;
      for (const candidate of candidates) {
        try {
          await readFile(candidate);
          found = true;
          break;
        } catch {
          /* try directory route */
        }
      }
      assert.ok(found, `${file} has a missing link or asset: ${url}`);
    }
  }
});

test('new blog scaffolding leaves the page title to the layout', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'bastco-blog-'));
  try {
    const result = spawnSync(
      process.execPath,
      [
        resolve('scripting/new-blog-post.mjs'),
        '--title',
        'Assessment notes',
        '--description',
        'A scoped assessment.',
        '--tags',
        'security',
      ],
      { cwd: directory, encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    const markdown = await read(
      join(directory, 'src/content/blog/assessment-notes.md'),
    );
    assert.match(markdown, /title: "Assessment notes"/);
    assert.doesNotMatch(markdown, /^# /m);
    assert.match(markdown, /^## Introduction/m);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('published pages have no automatic calendar embed, client islands, or template claims', async () => {
  for (const file of await htmlFiles('dist')) {
    const html = await read(file);
    assert.doesNotMatch(html, /<iframe\b|<astro-island\b/);
    assert.doesNotMatch(
      html,
      /Blackspike Theme|117 Bastion|117 Moody|reduced containment windows|Client logo|founder speaking/,
    );
  }
  const kifaru = await read('dist/kifaru/index.html');
  assert.match(kifaru, /A BASTCO PRODUCT/);
  assert.match(kifaru, /does not create a technical sandbox/);
});
