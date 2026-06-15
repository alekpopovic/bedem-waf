# BedemWAF Docs Site

This directory contains the lightweight static docs site source for GitHub Pages.

The site is generated from:

- `README.md`
- `docs/*.md`

Build locally:

```bash
python3 scripts/build-docs-site.py
```

Output is written to `_site/`.

Design notes:

- Tailwind is loaded from the browser CDN for the static site.
- Mermaid is loaded from the browser CDN for Markdown charts.
- The generator intentionally uses Python standard library only, so GitHub
  Actions can build the docs without installing project dependencies.
