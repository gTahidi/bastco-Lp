---
name: bastco-blog-writer
description: Write and publish BastCo blog posts in this Astro repo. Use when asked to turn a GitHub blog issue, rough notes, research findings, security write-up, infrastructure playbook, or draft Markdown into a polished post under src/content/blog, then commit and push it for deployment.
---

# BastCo Blog Writer

## Overview

Produce a published BastCo blog post, not just a local draft. The site uses Astro content collections, so every post must be a Markdown or MDX file in `src/content/blog/` with the frontmatter defined in `src/content/config.ts`.

## Workflow

1. Read the blog issue, prompt, notes, or draft. Extract the working title, audience, technical claim, evidence, category, tags, and publish date.
2. Inspect the existing blog collection before writing:
   - `src/content/config.ts` for required frontmatter.
   - `src/pages/blog/[slug].astro` for slug behavior and reading-time handling.
   - `src/layouts/BlogPostLayout.astro` for displayed metadata.
   - At least one current file in `src/content/blog/` for tone and structure.
3. Create the post with `npm run blog:new -- --title "..." --description "..." --category "..." --tags "tag-one,tag-two"`. Add `--date YYYY-MM-DD` when the issue provides a date, and `--draft path/to/draft.md` when starting from an existing Markdown draft.
4. Replace all generated `TODO` sections with the final post. Keep the first Markdown heading aligned with the frontmatter title.
5. Run `npm run build` before claiming the post is ready.
6. Commit only the blog workflow/post files relevant to the request.
7. Push the commit to the appropriate remote branch. In the normal publishing path for this repo, push `main` to `origin/main` so the Azure Static Web Apps workflow can deploy the post. Do not stop after a local commit unless the user explicitly asks for a draft, local-only change, or PR-only workflow.
8. Verify the publish handoff after pushing: check that the local branch is no longer ahead of its upstream, and when publishing to `main`, check that the GitHub Actions deploy workflow started or completed.

## Frontmatter Contract

Use this shape:

```yaml
---
title: "Clear, specific title"
description: "One sentence for listings and meta tags."
pubDate: 2026-06-24
author: "addcontent"
tags:
  - cybersecurity
  - ebpf
category: "Cybersecurity"
---
```

Optional fields allowed by the schema: `updatedDate` and `heroImage`. Do not add unsupported fields.

## Writing Standard

Write for senior technical buyers and builders: security engineers, platform engineers, founders, and operators who value concrete evidence. Prefer a direct technical narrative over marketing copy.

Every post needs:

- A specific opening that states the problem, result, or lesson.
- Evidence before conclusions. Cite commands, observed behavior, architecture facts, test results, or operational constraints.
- Sections with clear `##` headings. Use `###` only when a section has enough detail to justify it.
- Short paragraphs. Use bullets for checklists, test categories, or trade-offs.
- Practical closing guidance: what to monitor, repeat, automate, harden, or decide next.

Avoid:

- Unsupported vulnerability claims.
- Generic AI or cybersecurity filler.
- Sales-heavy copy.
- Long code blocks unless the code is the evidence.
- Duplicate author/date text in the body; the layout already renders metadata.

## Issue Intake

When the work starts from a GitHub issue created with `.github/ISSUE_TEMPLATE/blog-post.yml`, map fields as follows:

- `Working title` -> frontmatter `title` and the first `#` heading.
- `Source material` -> factual source of the post. Preserve claims, but rewrite structure and prose.
- `Category` -> frontmatter `category`.
- `Tags` -> frontmatter `tags`, normalized to concise lowercase tags unless the tag is a proper noun.
- `Audience and angle` -> introduction, framing, and conclusion.
- `Publish date` -> frontmatter `pubDate`; omit `--date` when blank.

## Automation

Use the repo script for file creation:

```bash
npm run blog:new -- --title "A Deep Dive into Verifier Testing" --description "Verifier testing lessons from Windows eBPF." --category "Cybersecurity" --tags "ebpf,windows,verifier"
```

The script writes `src/content/blog/<slug>.md` and refuses to overwrite an existing file. If the script reports that a file exists, inspect the existing post instead of forcing an overwrite.

## Publishing

Publishing means the relevant commit has left the local machine. After the build passes:

```bash
git status --short --branch
git add src/content/blog/<slug>.md
git commit -m "Add <short blog title> post"
git push origin main
git status --short --branch
gh run list --workflow "Azure Static Web Apps CI/CD" --branch main --limit 3
```

Adjust the `git add` paths when the request also changes blog tooling, templates, or issue metadata. If the current branch is not `main`, push the current branch and tell the user whether a PR or merge to `main` is still required before the live site can deploy. If push or deploy verification fails because of authentication, permissions, branch protection, or CI failures, report that the post is locally built but not fully published, with the exact blocking command and error.

## Quality Bar

Before finishing:

- Verify there are no `TODO` placeholders in the post.
- Verify frontmatter matches `src/content/config.ts`.
- Run `npm run build`.
- Verify the blog commit was pushed, or state exactly why it could not be pushed.
- Summarize the created slug, category, tags, build result, pushed commit, and deploy workflow status.
