import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const routes = [
  '/',
  '/kifaru',
  '/portfolio',
  '/services/cybersecurity-consulting',
  '/services/enterprise-software',
  '/services/infrastructure-automation',
  '/services/ai-gateways',
  '/blog',
  '/blog/when-vulnerability-reports-stop-being-special',
  '/blog/a-deep-dive-into-verifier-testing----windows-ebpf-case',
  '/security',
  '/privacy',
  '/404',
];

for (const width of [390, 1440]) {
  test.describe(`${width}px viewport`, () => {
    test.use({ viewport: { width, height: 900 } });
    for (const route of routes) {
      test(`${route} is accessible, contained, and private before interaction`, async ({
        page,
      }) => {
        const errors: string[] = [];
        const thirdPartyRequests: string[] = [];
        page.on('pageerror', (error) => errors.push(error.message));
        await page.route('**/*', async (request) => {
          if (
            new URL(request.request().url()).origin !== 'http://127.0.0.1:4322'
          ) {
            thirdPartyRequests.push(request.request().url());
            await request.abort();
          } else await request.continue();
        });
        const response = await page.goto(route);
        expect(response?.status()).toBe(200);
        await page.evaluate(() => document.fonts.ready);
        await expect(page.locator('h1')).toHaveCount(1);
        await expect(page.locator('main')).toHaveCount(1);
        expect(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= innerWidth,
          ),
        ).toBe(true);
        const duplicateIds = await page
          .locator('[id]')
          .evaluateAll((elements) => {
            const ids = elements.map((element) => element.id);
            return ids.filter((id, index) => ids.indexOf(id) !== index);
          });
        expect(duplicateIds).toEqual([]);
        await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
          'href',
          /^https:\/\/bastco\.org\//,
        );
        await expect(page.locator('meta[property="og:image"]')).toHaveAttribute(
          'content',
          'https://bastco.org/bastco-social.png',
        );
        const a11y = await new AxeBuilder({ page })
          .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
          .analyze();
        expect(a11y.violations).toEqual([]);
        expect(errors).toEqual([]);
        expect(thirdPartyRequests).toEqual([]);
      });
    }
  });
}

test('mobile menu opens by keyboard, closes with Escape, and follows links', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  const summary = page.locator('.mobile-menu summary');
  await summary.focus();
  await page.keyboard.press('Enter');
  await expect(
    page.getByRole('navigation', { name: 'Mobile navigation' }),
  ).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(summary).toBeFocused();
  await expect(
    page.getByRole('navigation', { name: 'Mobile navigation' }),
  ).toBeHidden();
  await summary.click();
  await page
    .getByRole('navigation', { name: 'Mobile navigation' })
    .getByRole('link', { name: 'Services', exact: true })
    .click();
  await expect(page).toHaveURL(/#services$/);
  await expect(page.locator('.mobile-menu')).not.toHaveAttribute('open', '');
  await summary.click();
  await page
    .getByRole('navigation', { name: 'Mobile navigation' })
    .getByRole('link', { name: 'Kifaru', exact: true })
    .click();
  await expect(page).toHaveURL(/\/kifaru\/?$/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText(
    'See the risk.',
  );
});

for (const route of ['/', '/kifaru']) {
  test(`${route} loads exactly one calendar only on activation`, async ({
    page,
  }) => {
    const calls: string[] = [];
    await page.route('https://cal.com/**', async (request) => {
      calls.push(request.request().url());
      await request.fulfill({
        contentType: 'text/html',
        body: '<h1>Mock calendar</h1>',
      });
    });
    await page.goto(route);
    await expect(page.locator('iframe')).toHaveCount(0);
    expect(calls).toEqual([]);
    const button = page.locator('[data-load-booking]');
    await button.click();
    await expect(page.locator('iframe')).toHaveAttribute(
      'title',
      'Book a 15-minute introduction with Bastco on Cal.com',
    );
    await expect(page.locator('iframe')).toHaveAttribute(
      'referrerpolicy',
      'no-referrer',
    );
    await expect(button).toHaveAttribute('aria-expanded', 'true');
    await button.click();
    await expect(page.locator('iframe')).toHaveCount(1);
    await expect.poll(() => calls.length).toBe(1);
  });
}

test('navigation and booking links work without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({
    javaScriptEnabled: false,
    viewport: { width: 390, height: 844 },
  });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:4322/');
  await page.locator('.mobile-menu summary').click();
  await expect(
    page
      .getByRole('navigation', { name: 'Mobile navigation' })
      .getByRole('link', { name: 'Kifaru', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Open Cal.com', exact: false }),
  ).toHaveAttribute('href', 'https://cal.com/bastco/15min');
  await expect(page.locator('iframe')).toHaveCount(0);
  await context.close();
});

test('configured CSP permits first-party interactions and blocks injected inline scripts', async ({
  page,
}) => {
  // Exercise the actual static-asset headers served by the local Workers runtime.
  await page.addInitScript(() => {
    (window as any).__policyViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      (window as any).__policyViolations.push({
        directive: event.effectiveDirective,
        disposition: event.disposition,
      });
    });
  });
  await page.route('https://cal.com/**', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<h1>Mock calendar</h1>' }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.locator('.mobile-menu summary').click();
  await page.keyboard.press('Escape');
  await expect(page.locator('.mobile-menu')).not.toHaveAttribute('open', '');
  await page.locator('[data-load-booking]').click();
  await expect(page.locator('iframe')).toHaveCount(1);
  expect(await page.evaluate(() => (window as any).__policyViolations)).toEqual(
    [],
  );
  await page.evaluate(() => {
    const script = document.createElement('script');
    script.textContent = 'window.__injectedScriptRan = true';
    document.body.append(script);
  });
  expect(
    await page.evaluate(() => (window as any).__injectedScriptRan),
  ).toBeUndefined();
  await expect
    .poll(() => page.evaluate(() => (window as any).__policyViolations))
    .toContainEqual({ directive: 'script-src-elem', disposition: 'enforce' });
});

test('Workers serves security headers, immutable assets, and a true 404', async ({
  request,
}) => {
  const home = await request.get('/');
  expect(home.status()).toBe(200);
  const headers = home.headers();
  expect(headers['content-security-policy']).toContain("script-src 'self'");
  expect(headers['content-security-policy-report-only']).toContain(
    "default-src 'self'",
  );
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['strict-transport-security']).toBe('max-age=31536000');
  expect(headers['cache-control']).not.toContain('immutable');
  expect(headers['cache-control']).toContain('no-transform');
  const product = await request.get('/kifaru/');
  expect(product.headers()['cache-control']).toContain('no-transform');
  const html = await home.text();
  const asset = html.match(/href="(\/_astro\/[^" ]+\.css)"/)?.[1];
  expect(asset).toBeTruthy();
  const response = await request.get(asset!);
  expect(response.headers()['cache-control']).toBe(
    'public, max-age=31536000, immutable',
  );
  const missing = await request.get('/this-page-does-not-exist');
  expect(missing.status()).toBe(404);
  expect(await missing.text()).toContain('Let’s get you');
  expect(missing.headers()['x-content-type-options']).toBe('nosniff');
  const calendar = await request.get('/kifaru', { maxRedirects: 0 });
  expect(calendar.status()).toBe(307);
  expect(calendar.headers()['location']).toBe('/kifaru/');
});

test('workflow explorer supports buttons and keyboard without making network requests', async ({
  page,
}) => {
  await page.goto('/kifaru/');
  const explorer = page.locator('[data-workflow]');
  const evidence = explorer.getByRole('button', { name: '03 Evidence' });
  await evidence.click();
  await expect(evidence).toHaveAttribute('aria-pressed', 'true');
  await expect(
    explorer.getByRole('heading', { name: 'A lead is not yet a finding.' }),
  ).toBeVisible();
  await expect(explorer.locator('[data-panel]:visible')).toHaveCount(1);
  await evidence.press('ArrowRight');
  await expect(
    explorer.getByRole('button', { name: '04 Report' }),
  ).toBeFocused();
  await expect(
    explorer.getByRole('heading', {
      name: 'A clearer handoff. Not a black box.',
    }),
  ).toBeVisible();
  await page.keyboard.press('Home');
  await expect(
    explorer.getByRole('button', { name: '01 Scope' }),
  ).toBeFocused();
  await expect(explorer.locator('[data-panel="0"]')).toBeVisible();
});

test('proposed pricing shows annual totals and remains explicitly non-purchasable', async ({
  page,
}) => {
  await page.goto('/kifaru/');
  const pricing = page.locator('[data-pricing]');
  await expect(pricing).toContainText('not a live offer');
  const prices = pricing.locator('[data-monthly]');
  await expect(prices).toHaveText(['$0', '$19', '$79']);
  await pricing.getByRole('button', { name: /Yearly/ }).click();
  await expect(prices).toHaveText(['$0', '$190', '$790']);
  await expect(pricing.locator('[data-price-period]')).toHaveText([
    '/year',
    '/year',
    '/year',
  ]);
  await pricing.getByRole('button', { name: 'Monthly', exact: true }).click();
  await expect(prices).toHaveText(['$0', '$19', '$79']);
  await expect(
    pricing.getByRole('link', { name: /Contact Bastco/ }),
  ).toHaveAttribute('href', '#demo');
  await expect(pricing).toContainText(
    'No purchase or subscription is created here',
  );
});

test('workflow and proposed pricing remain readable without JavaScript', async ({
  browser,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await page.goto('http://127.0.0.1:4322/kifaru/');
    await expect(page.locator('[data-panel]:visible')).toHaveCount(4);
    await expect(page.locator('.workflow-controls')).toBeHidden();
    await expect(page.locator('.billing-toggle')).toBeHidden();
    await expect(page.locator('[data-monthly]')).toHaveText([
      '$0',
      '$19',
      '$79',
    ]);
    await expect(
      page.getByRole('link', { name: /Explore installation/ }),
    ).toBeVisible();
  } finally {
    await context.close();
  }
});

test('narrow viewports remain contained', async ({ page }) => {
  for (const width of [320, 360, 768, 1024]) {
    await page.setViewportSize({ width, height: 900 });
    for (const route of ['/', '/kifaru', '/portfolio']) {
      await page.goto(route);
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `${route} at ${width}px`,
      ).toBe(true);
    }
  }
});
