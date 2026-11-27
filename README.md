# Bastco website

Static Astro website for Bastco’s security and engineering services and Kifaru,
a Bastco product. Production runs on **Cloudflare Workers Static Assets** at
**https://bastco.org**. No React runtime, framework adapter, or application server
is required.

## Local development

Use Node 24 (see `.nvmrc` and `package.json`).

```sh
nvm use
npm ci
npm run dev
```

Open http://localhost:4321. Development binds to loopback, not the LAN.
On hosts where Astro backgrounds agent-launched servers, use
`npm run astro -- dev status` or `npm run astro -- dev stop` to inspect or stop it.

To exercise the actual Workers asset router, headers, and custom 404 handling:

```sh
npm run build
npm run preview
# http://127.0.0.1:4322
```

## Validation

```sh
npx playwright install --with-deps chromium
npm run validate
npm audit --audit-level=high
```

`validate` runs Astro type checking, a production build, static-artifact checks,
and Chromium/axe tests against the local Workers runtime. It checks desktop/mobile
pages, additional narrow widths, navigation with and without JavaScript, duplicate
IDs, metadata, optional calendar activation, and pre-interaction network requests.
The CSP test uses **real response headers**, not a mocked policy. Routing tests
verify immutable hashed assets, HTML revalidation, trailing slashes, and a true
HTTP 404.

Use `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` to select an existing compatible Chromium
binary when needed. Browser artifacts and Wrangler local state are ignored by Git.
Automated accessibility checks do not replace manual assistive-technology testing.

## Deployment

Wrangler is a locked local development dependency; no global install is required.
The existing `cf` CLI can inspect account and DNS resources. Authenticate with the
intended Cloudflare account, then check access:

```sh
cf auth whoami
npx wrangler whoami
```

`wrangler.json` has separate targets:

| Command                  | Target                | Public hostname                     |
| ------------------------ | --------------------- | ----------------------------------- |
| `npm run deploy:preview` | `bastco-site-preview` | Wrangler prints a `workers.dev` URL |
| `npm run deploy:check`   | Production dry run    | No network deployment or DNS change |
| `npm run deploy`         | `bastco-site`         | `bastco.org` custom domain          |

Both deployment commands build before uploading. The default target is a preview,
so an unqualified Wrangler deployment does not take over a production hostname.
Production explicitly disables `workers.dev` and version preview URLs. Preview
responses carry `X-Robots-Tag: noindex`; canonical and social URLs always use
`https://bastco.org`.

Production uses the existing Cloudflare account/zone. Only the apex hostname is
managed by this configuration: it does **not** change mail, `install.bastco.org`,
Kifaru services, other subdomains, zone-wide settings, or account authentication.
`bastco.com` was not found in the authenticated account and is not configured here.
`www.bastco.org` is not automatically provisioned by an apex custom domain.

### Automatic deployment from GitHub

`.github/workflows/cloudflare-workers.yml` runs on main pushes and pull requests.
Validation uses pinned actions, read-only permissions, checksum-verified Gitleaks
history scanning, an npm audit gate, and the complete local validation suite.
Only a successful **push to main** deploys production; pull requests cannot deploy
or access the deployment token.

Configure a **`CLOUDFLARE_API_TOKEN`** secret in the repository or its `production`
environment. Use a scoped deployment token for the configured account with Workers
Scripts edit, Workers Routes edit, and Zone read permissions for `bastco.org`.
Check current Cloudflare permission requirements when provisioning the token.
Do not copy a personal OAuth session into GitHub secrets. The workflow fails with
an explicit setup message if the token is missing. Branch protection and any
production environment approvals must be configured in GitHub separately.

The old hosting workflow and configuration have been removed. The former Azure
application and its remote deployment secret were intentionally not deleted;
they are no longer used by this repository’s new workflow and can be retired
separately after the migration is accepted.

### Verify and roll back

```sh
npm run test:deployment
npm run test:deployment -- https://bastco-site-preview.square-mouse-69aa.workers.dev
```

These read-only checks verify live pages, canonical URLs, headers, asset caching,
and 404 status. Browser tests mock scheduling; also exercise the real calendar
without submitting sensitive details before approving changes.

For an established production Worker, inspect versions/deployments with Wrangler
and roll back to a reviewed version using `npx wrangler rollback --env production`.
A code rollback does not restore a previous external hosting provider’s DNS.

The previous apex CNAME was `polite-island-007c8670f.2.azurestaticapps.net`, DNS-only.
A private DNS snapshot was saved outside the checkout before the initial cutover.
Returning to that origin requires removing the Workers custom domain and restoring
the previous apex record; do not modify mail or application subdomains. Removing a
custom domain may leave its managed certificate behind, so inspect the certificate
inventory separately. Do not run DNS rollback unless the old origin is still
available and the exact change is approved.

## Security controls

`public/_headers` is copied to `dist/_headers` and interpreted by Workers Static
Assets. The file itself is not publicly served.

- Enforced CSP allows only first-party scripts, prevents framing, disables object
  embeds, restricts base/form targets, and upgrades insecure requests.
- A broader resource policy remains **report-only**. It allows first-party assets
  and optional Cal.com frames. There is no remote CSP report collector; inspect
  browser console/policy events before promoting it to enforcement.
- MIME sniffing, referrer leakage, and unnecessary browser capabilities are restricted.
- HSTS covers this hostname only, without `includeSubDomains` or preload.
- Hashed Astro assets receive immutable caching; HTML retains revalidation.
- Canonical HTML responses use `no-transform` to prevent edge-injected scripts,
  including the zone’s existing automatic analytics beacon, without changing
  analytics settings for other subdomains.

Small first-party scripts are emitted as files, without `unsafe-inline` or
`unsafe-eval` for scripts. Inline styles remain allowed in the report-only policy
because Markdown syntax highlighting and some layout styles use them.

The calendar iframe is created only after explicit activation, with a no-referrer
policy and a normal scheduling-link fallback. Passive page loads must not contact
Cal.com. No booking credentials belong in this codebase.

## Content and design

- `src/pages/index.astro`: homepage and services/product hierarchy.
- `src/pages/kifaru.astro`: Kifaru capabilities, boundaries, and setup links.
- `src/components/`: shared navigation, footer, cards, booking, workflow illustration.
- `src/assets/css/site.css`: shared visual system and responsive layouts.
- `src/assets/css/visual.css`: light, visual-first shared page styling.
- `src/assets/css/editorial.css`: capabilities overview, research index, and article
  reading layouts. Service-detail routes retain their dark theme.
- `src/components/blog/`, `src/layouts/BlogPostLayout.astro`: research cards,
  publication metadata, preserved authorship, and readable long-form content.
- `src/components/ProductShowcase.astro`: interactive sample workbench. The homepage
  opens the task; the product page opens its finding. All views work without JavaScript.
- `src/components/PricingPreview.astro`: explicitly proposed Community/Pro/Team
  pricing, with monthly/annual totals and enterprise contact only. This is not a
  checkout, license activation flow, or finalized product offer.
- `src/assets/images/`: decorative artwork from the supplied concept, with source
  notes and responsive image processing.
- `src/data/services.json`, `src/data/opensource.json`: service/tool summaries.
- `src/content.config.ts`, `src/content/blog/`: research articles and schema.
- `src/pages/security.astro`, `src/pages/privacy.astro`: factual security/privacy notices.
- `src/assets/brand/`: original supplied brand assets, retained as design sources.

Unused theme images, placeholder portfolio data, legacy UI helpers, and their
React/animation dependencies have been removed. The `/portfolio` URL remains as a
capabilities overview, not a list of unverified case studies.

Kifaru’s interactive graphic is explicitly a workflow illustration, not a screenshot
or a live assessment. Replace it only with reviewed, sanitized product images.
The pricing preview does not promise plan-specific features, an SLA, or availability.
Confirm license terms, fulfilment, support commitments, and artwork publishing rights
before turning this direction into a live commercial offer. No provider-cost
calculator or fixed per-assessment estimate is published without sourced rates and
validated usage assumptions. Preserve human
authorship on research. Do not invent client logos, metrics, addresses, service
promises, certifications, or product isolation guarantees.

A private vulnerability-reporting contact still needs confirmation before a formal
disclosure policy or `security.txt` is published. Review privacy language against
actual hosting settings and contractual requirements. No production security or
compliance guarantee follows solely from a successful build or these tests.
