#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

function usage() {
  console.error(`Usage: npm run blog:new -- --title "Post title" [options]

Options:
  --title <title>          Required post title
  --description <text>     Frontmatter description
  --author <name>          Defaults to "addcontent"
  --category <name>        Defaults to "Cybersecurity"
  --tags <a,b,c>           Comma-separated tags
  --date <YYYY-MM-DD>      Defaults to today
  --slug <slug>            Defaults to a slug from the title
  --draft <path>           Optional Markdown draft body to append
`);
}

function parseArgs(argv) {
  const args = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      throw new Error(`Unexpected argument: ${arg}`);
    }

    const key = arg.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }

    args[key] = value;
    i += 1;
  }

  return args;
}

function slugify(input) {
  return input
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 96);
}

function yamlString(value) {
  return JSON.stringify(value);
}

async function readDraft(draftPath) {
  if (!draftPath) {
    return null;
  }

  const { readFile } = await import('node:fs/promises');
  const draft = await readFile(draftPath, 'utf8');
  return draft.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, '');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const title = args.title?.trim();

  if (!title) {
    usage();
    process.exitCode = 1;
    return;
  }

  const pubDate = args.date ?? new Date().toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(pubDate)) {
    throw new Error('--date must use YYYY-MM-DD');
  }

  const slug = slugify(args.slug ?? title);
  if (!slug) {
    throw new Error('Unable to create a slug from the title');
  }

  const description = args.description?.trim() || 'TODO: add a concise summary for listings and meta tags.';
  const author = args.author?.trim() || 'addcontent';
  const category = args.category?.trim() || 'Cybersecurity';
  const tags = (args.tags ?? 'TODO')
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
  const draft = await readDraft(args.draft);

  const frontmatter = [
    '---',
    `title: ${yamlString(title)}`,
    `description: ${yamlString(description)}`,
    `pubDate: ${pubDate}`,
    `author: ${yamlString(author)}`,
    'tags:',
    ...tags.map((tag) => `  - ${yamlString(tag)}`),
    `category: ${yamlString(category)}`,
    '---',
    '',
    '',
  ];

  const body = draft?.trimStart() || `# ${title}

## Introduction

TODO: Open with the concrete problem, result, or lesson.

## What We Found

TODO: Explain the evidence and technical details.

## Why It Matters

TODO: Connect the finding to operator, engineering, or security impact.

## Next Steps

TODO: End with pragmatic guidance or what BastCo will do next.
`;

  const outputDir = path.join(process.cwd(), 'src', 'content', 'blog');
  const outputPath = path.join(outputDir, `${slug}.md`);

  await mkdir(outputDir, { recursive: true });
  await writeFile(outputPath, `${frontmatter.join('\n')}${body.trimEnd()}\n`, { flag: 'wx' });

  console.log(outputPath);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
