#!/usr/bin/env python3
"""Build the BedemWAF GitHub Pages docs site from Markdown files."""

from __future__ import annotations

import html
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = ROOT / "_site"


@dataclass(frozen=True)
class Page:
    source: Path
    title: str
    slug: str
    section: str


PAGES = [
    Page(ROOT / "README.md", "Overview", "index", "Start"),
    Page(DOCS / "architecture.md", "Architecture", "architecture", "Core"),
    Page(DOCS / "data-plane.md", "Data Plane", "data-plane", "Core"),
    Page(DOCS / "control-plane.md", "Control Plane", "control-plane", "Core"),
    Page(DOCS / "request-flow.md", "Request Flow", "request-flow", "Core"),
    Page(DOCS / "implementation-plan.md", "Implementation Plan", "implementation-plan", "Core"),
    Page(DOCS / "policy-model.md", "Policy Model", "policy-model", "Models"),
    Page(DOCS / "event-schema.md", "Event Schema", "event-schema", "Models"),
    Page(DOCS / "deployment-model.md", "Deployment Model", "deployment-model", "Operations"),
    Page(DOCS / "local-development.md", "Local Development", "local-development", "Operations"),
    Page(DOCS / "threat-model.md", "Threat Model", "threat-model", "Security"),
]


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"`([^`]+)`", r"\1", value)
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "section"


def inline_markdown(value: str) -> str:
    escaped = html.escape(value)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)

    def link(match: re.Match[str]) -> str:
        label = match.group(1)
        href = match.group(2)
        href = href.replace("docs/", "").replace(".md", ".html")
        if href == "README.html":
            href = "index.html"
        return f'<a href="{html.escape(href)}">{label}</a>'

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, escaped)


def close_list(parts: list[str], list_type: str | None) -> None:
    if list_type:
        parts.append(f"</{list_type}>")


def markdown_to_html(markdown: str) -> tuple[str, list[tuple[int, str, str]]]:
    parts: list[str] = []
    headings: list[tuple[int, str, str]] = []
    in_code = False
    code_lang = ""
    code_lines: list[str] = []
    list_type: str | None = None

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()

        if line.startswith("```"):
            fence_lang = line[3:].strip()
            if not in_code:
                close_list(parts, list_type)
                list_type = None
                in_code = True
                code_lang = fence_lang
                code_lines = []
            else:
                code = "\n".join(code_lines)
                if code_lang == "mermaid":
                    parts.append(f'<pre class="mermaid">{html.escape(code)}</pre>')
                else:
                    parts.append(
                        f'<pre><code class="language-{html.escape(code_lang)}">'
                        f"{html.escape(code)}</code></pre>"
                    )
                in_code = False
                code_lang = ""
            continue

        if in_code:
            code_lines.append(raw_line)
            continue

        if not line.strip():
            close_list(parts, list_type)
            list_type = None
            continue

        heading = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading:
            close_list(parts, list_type)
            list_type = None
            level = len(heading.group(1))
            text = heading.group(2).strip()
            anchor = slugify(text)
            headings.append((level, text, anchor))
            parts.append(
                f'<h{level} id="{anchor}">'
                f'<a class="anchor" href="#{anchor}" aria-label="Link to section">#</a>'
                f"{inline_markdown(text)}</h{level}>"
            )
            continue

        item = re.match(r"^-\s+(.+)$", line)
        if item:
            if list_type != "ul":
                close_list(parts, list_type)
                parts.append("<ul>")
                list_type = "ul"
            parts.append(f"<li>{inline_markdown(item.group(1))}</li>")
            continue

        numbered = re.match(r"^\d+\.\s+(.+)$", line)
        if numbered:
            if list_type != "ol":
                close_list(parts, list_type)
                parts.append("<ol>")
                list_type = "ol"
            parts.append(f"<li>{inline_markdown(numbered.group(1))}</li>")
            continue

        close_list(parts, list_type)
        list_type = None
        parts.append(f"<p>{inline_markdown(line)}</p>")

    close_list(parts, list_type)
    return "\n".join(parts), headings


def page_url(page: Page) -> str:
    return "index.html" if page.slug == "index" else f"{page.slug}.html"


def navigation(current: Page) -> str:
    sections: dict[str, list[Page]] = {}
    for page in PAGES:
        sections.setdefault(page.section, []).append(page)

    chunks: list[str] = []
    for section, pages in sections.items():
        chunks.append(f'<p class="nav-section">{html.escape(section)}</p>')
        for page in pages:
            active = " active" if page.slug == current.slug else ""
            chunks.append(
                f'<a class="nav-link{active}" href="{page_url(page)}">'
                f"{html.escape(page.title)}</a>"
            )
    return "\n".join(chunks)


def table_of_contents(headings: list[tuple[int, str, str]]) -> str:
    items = [
        f'<a class="toc-link toc-level-{level}" href="#{anchor}">{html.escape(text)}</a>'
        for level, text, anchor in headings
        if level in (2, 3)
    ]
    if not items:
        return '<p class="toc-empty">No sections.</p>'
    return "\n".join(items)


def render_page(page: Page) -> str:
    body, headings = markdown_to_html(page.source.read_text(encoding="utf-8"))
    nav = navigation(page)
    toc = table_of_contents(headings)
    title = html.escape(f"{page.title} | BedemWAF Docs")

    return f"""<!doctype html>
<html lang="en" class="scroll-smooth">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <meta name="description" content="BedemWAF technical documentation">
    <script>
      window.tailwind = window.tailwind || {{}};
      window.tailwind.config = {{
        darkMode: 'class',
        theme: {{
          extend: {{
            colors: {{
              bedem: {{
                ink: '#101820',
                steel: '#295264',
                mint: '#3fbf9f',
                amber: '#f3b23c'
              }}
            }}
          }}
        }}
      }};
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      const storedTheme = localStorage.getItem('bedemwaf-theme');
      if (storedTheme === 'dark') {{
        document.documentElement.classList.add('dark');
      }}
    </script>
    <link rel="stylesheet" href="assets/site.css">
  </head>
  <body class="bg-white text-slate-950 antialiased dark:bg-slate-950 dark:text-slate-100">
    <div class="min-h-screen lg:grid lg:grid-cols-[18rem_minmax(0,1fr)_16rem]">
      <aside class="sidebar">
        <div class="brand">
          <a href="index.html" class="brand-mark">BedemWAF</a>
          <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle color theme">
            <span class="dark:hidden">Dark</span>
            <span class="hidden dark:inline">Light</span>
          </button>
        </div>
        <p class="tagline">Self-hosted managed WAF for NGINX origins.</p>
        <nav class="nav">{nav}</nav>
      </aside>

      <main class="content">
        <div class="doc-shell">
          <div class="doc-kicker">BedemWAF Documentation</div>
          <article class="doc-content">{body}</article>
        </div>
      </main>

      <aside class="toc">
        <p class="toc-title">On This Page</p>
        {toc}
      </aside>
    </div>

    <script type="module">
      import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
      mermaid.initialize({{
        startOnLoad: true,
        theme: document.documentElement.classList.contains('dark') ? 'dark' : 'default'
      }});
    </script>
    <script src="assets/site.js"></script>
  </body>
</html>
"""


def write_assets() -> None:
    assets = OUT / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "site.css").write_text(
        """
.sidebar {
  background: rgb(255 255 255);
  border-bottom: 1px solid rgb(226 232 240);
  padding: 1rem;
}
.dark .sidebar {
  background: rgb(2 6 23);
  border-color: rgb(30 41 59);
}
@media (min-width: 1024px) {
  .sidebar {
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
    border-right: 1px solid rgb(226 232 240);
    border-bottom: 0;
    padding: 1.5rem;
  }
  .toc {
    display: block;
  }
}
.brand {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}
.brand-mark {
  font-weight: 800;
  font-size: 1.25rem;
  color: rgb(15 23 42);
  text-decoration: none;
}
.dark .brand-mark {
  color: rgb(248 250 252);
}
.theme-toggle {
  background: rgb(255 255 255);
  border: 1px solid rgb(203 213 225);
  border-radius: 0.375rem;
  color: rgb(15 23 42);
  padding: 0.375rem 0.625rem;
  font-size: 0.8125rem;
  font-weight: 700;
}
.dark .theme-toggle {
  background: rgb(15 23 42);
  border-color: rgb(51 65 85);
  color: rgb(248 250 252);
}
.tagline {
  margin-top: 0.5rem;
  color: rgb(71 85 105);
  font-size: 0.875rem;
  line-height: 1.5;
}
.dark .tagline {
  color: rgb(148 163 184);
}
.nav {
  margin-top: 1.5rem;
}
.nav-section {
  margin: 1.25rem 0 0.375rem;
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.nav-link {
  display: block;
  border-radius: 0.375rem;
  padding: 0.45rem 0.625rem;
  color: rgb(51 65 85);
  font-size: 0.925rem;
  font-weight: 650;
  text-decoration: none;
}
.nav-link:hover,
.nav-link.active {
  background: rgb(226 232 240);
  color: rgb(15 23 42);
}
.dark .nav-link {
  color: rgb(203 213 225);
}
.dark .nav-link:hover,
.dark .nav-link.active {
  background: rgb(30 41 59);
  color: rgb(248 250 252);
}
.content {
  background: rgb(255 255 255);
  min-width: 0;
  padding: 1.25rem;
}
.dark .content {
  background: rgb(2 6 23);
}
@media (min-width: 768px) {
  .content {
    padding: 2.5rem;
  }
}
.doc-shell {
  max-width: 54rem;
  margin: 0 auto;
}
.doc-kicker {
  color: rgb(20 184 166);
  font-size: 0.8125rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.doc-content {
  margin-top: 0.75rem;
}
.doc-content h1 {
  margin: 0 0 1rem;
  font-size: clamp(2rem, 4vw, 3.5rem);
  line-height: 1.05;
  font-weight: 850;
}
.doc-content h2 {
  margin-top: 2.5rem;
  padding-top: 1rem;
  border-top: 1px solid rgb(226 232 240);
  font-size: 1.5rem;
  line-height: 1.25;
  font-weight: 800;
}
.dark .doc-content h2 {
  border-color: rgb(30 41 59);
}
.doc-content h3 {
  margin-top: 1.75rem;
  font-size: 1.125rem;
  font-weight: 800;
}
.doc-content p,
.doc-content li {
  color: rgb(51 65 85);
  line-height: 1.75;
}
.dark .doc-content p,
.dark .doc-content li {
  color: rgb(203 213 225);
}
.doc-content ul,
.doc-content ol {
  margin: 0.75rem 0 1rem 1.25rem;
}
.doc-content ul {
  list-style: disc;
}
.doc-content ol {
  list-style: decimal;
}
.doc-content a {
  color: rgb(13 148 136);
  font-weight: 700;
  text-decoration: none;
}
.doc-content a:hover {
  text-decoration: underline;
}
.doc-content code {
  border-radius: 0.25rem;
  background: rgb(241 245 249);
  border: 1px solid rgb(226 232 240);
  color: rgb(15 23 42);
  padding: 0.1rem 0.3rem;
  font-size: 0.9em;
}
.dark .doc-content code {
  background: rgb(30 41 59);
  border-color: rgb(51 65 85);
  color: rgb(226 232 240);
}
.doc-content pre {
  margin: 1.25rem 0;
  overflow-x: auto;
  border: 1px solid rgb(203 213 225);
  border-radius: 0.5rem;
  background: rgb(248 250 252);
  color: rgb(15 23 42);
  padding: 1rem;
  font-size: 0.875rem;
  line-height: 1.55;
}
.dark .doc-content pre {
  border-color: rgb(51 65 85);
  background: rgb(15 23 42);
  color: rgb(226 232 240);
}
.doc-content pre code {
  background: transparent;
  border: 0;
  color: inherit;
  padding: 0;
}
.doc-content pre.mermaid {
  background: rgb(255 255 255);
  color: inherit;
}
.dark .doc-content pre.mermaid {
  background: rgb(15 23 42);
}
.anchor {
  opacity: 0;
  margin-left: -1.1rem;
  padding-right: 0.35rem;
  color: rgb(20 184 166);
  text-decoration: none;
}
h1:hover .anchor,
h2:hover .anchor,
h3:hover .anchor,
h4:hover .anchor {
  opacity: 1;
}
.toc {
  display: none;
  background: rgb(255 255 255);
  border-left: 1px solid rgb(226 232 240);
  padding: 1.5rem 1rem;
}
.dark .toc {
  background: rgb(2 6 23);
  border-color: rgb(30 41 59);
}
@media (min-width: 1024px) {
  .toc {
    display: block;
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
  }
}
.toc-title {
  margin-bottom: 0.75rem;
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.toc-link {
  display: block;
  padding: 0.35rem 0;
  color: rgb(71 85 105);
  font-size: 0.875rem;
  text-decoration: none;
}
.toc-link:hover {
  color: rgb(13 148 136);
}
.toc-level-3 {
  padding-left: 0.75rem;
}
.dark .toc-link {
  color: rgb(148 163 184);
}
.toc-empty {
  color: rgb(100 116 139);
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (assets / "site.js").write_text(
        """
const toggle = document.getElementById('theme-toggle');
if (toggle) {
  toggle.addEventListener('click', () => {
    const root = document.documentElement;
    const dark = root.classList.toggle('dark');
    localStorage.setItem('bedemwaf-theme', dark ? 'dark' : 'light');
  });
}
""".strip()
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    write_assets()

    for page in PAGES:
        if not page.source.exists():
            raise FileNotFoundError(page.source)
        (OUT / page_url(page)).write_text(render_page(page), encoding="utf-8")

    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    print(f"Built docs site at {OUT}")


if __name__ == "__main__":
    main()
