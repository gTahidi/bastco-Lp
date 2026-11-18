import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://bastco.org',
  output: 'static',
  markdown: { shikiConfig: { theme: 'github-dark-high-contrast' } },
  vite: { plugins: [tailwindcss()], build: { assetsInlineLimit: 0 } },
  server: { host: '127.0.0.1' },
});
