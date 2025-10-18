#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "Usage: $0 <markdown-file>..." >&2
  exit 1
fi

default_author=${AUTHOR:-addcontent}
default_category=${CATEGORY:-TODO}
default_description=${DESCRIPTION:-TODO: add description}

for md_file in "$@"; do
  if [[ ! -f "$md_file" ]]; then
    echo "Skipping ${md_file} (not a file)" >&2
    continue
  fi

  if [[ "$(head -n 1 "$md_file")" == "---" ]]; then
    echo "Skipping ${md_file} (frontmatter already present)"
    continue
  fi

  raw_title=$(grep -m1 '^# ' "$md_file" | sed 's/^#[[:space:]]*//')
  if [[ -z "${raw_title}" ]]; then
    raw_title=$(basename "$md_file")
    raw_title="${raw_title%.md}"
    raw_title="${raw_title//_/ }"
    raw_title="${raw_title//-/ }"
  fi

  # Collapse repeated spaces and trim leading/trailing whitespace
  title=$(echo "$raw_title" | awk '{$1=$1; print}')
  title="${title:-Untitled Post}"
  title_escaped=${title//\"/\\\"}

  pub_date=${PUBDATE:-$(date +%Y-%m-%d)}

  tmp_file=$(mktemp)
  {
    printf '%s\n' '---'
    printf 'title: "%s"\n' "$title_escaped"
    printf 'description: "%s"\n' "$default_description"
    printf 'pubDate: %s\n' "$pub_date"
    printf 'author: "%s"\n' "$default_author"
    printf 'tags:\n'
    printf '  - TODO\n'
    printf 'category: "%s"\n' "$default_category"
    printf '%s\n' '---'
    printf '\n'
    cat "$md_file"
  } >"$tmp_file"

  mv "$tmp_file" "$md_file"
  echo "Added frontmatter to ${md_file}"
done
