# SAP Security Notes MCP Server

Ask questions about SAP Security Note metadata — Patch Day releases, CVSS
scores, CVEs, affected components, and actively-exploited status — via the
Model Context Protocol (MCP).

**Server URL:** `https://notes.syntaai.com/mcp`

## Features

- **10 Tools** — Patch Day summaries, note/CVE lookup, component exposure
  checks, exploited-in-the-wild status, month comparisons (all read-only)
- **4 Resources** — Catalog info, latest Patch Day summary, component
  list, priority definitions
- **4 Prompts** — Monthly patch briefing, exposure check, patch backlog
  prioritizer, CVE investigation
- **No authentication required — public read-only data.**
- **stdio transport** — run it locally with Claude Desktop or any MCP
  client

## Example Interactions

### Example 1: Patch Day Summary

**User prompt:** "What came out in July's SAP Patch Day?"

**What happens:**
- Returns counts by priority for 2026-07, the HotNews list with CVSS
  scores, top affected components, and new vs. updated notes

**Tool used:** `get_patch_day_summary`

---

### Example 2: Active Exploitation

**User prompt:** "Are any SAP vulnerabilities actively exploited right now?"

**What happens:**
- Cross-references the catalog's CVEs against the CISA Known Exploited
  Vulnerabilities (KEV) snapshot and returns matches with KEV dates
- A zero-match answer is reported honestly, with what that does and does
  not mean

**Tool used:** `get_exploited_notes`

---

### Example 3: Component Exposure

**User prompt:** "Here is my stack: SAP S/4HANA 2023, SAP_BASIS 758,
BC-JAS-WEB — what applies to me?"

**What happens:**
- Each item is classified: application component (`BC-JAS-WEB`), software
  component optionally with a version (`SAP_BASIS 758`), or product/stack
  name from Maintenance Planner (`SAP S/4HANA 2023`)
- Software components match primarily against SAP's own **published**
  affected-component/version lists; a curated mapping fills in notes that
  have no published list. Application components match directly
  (exact + prefix)
- A pasted version gets a tier per matched note:
  1. **Affected version confirmed** — the version is in SAP's published list
  2. **Component listed, your version not in the published list** — not
     proof of safety, published lists can be summarized
  3. **Component affected, version not assessed** — no version given, or
     no published list to check (exact-string match only — never a range
     or "close enough" inference)
- Returns matching notes grouped by provenance, plus an honest "not
  assessed" bucket for anything that could not be classified or matched

**Tool used:** `check_component_exposure`

## Tools Reference

### Patch Day & Search
| Tool | Description | Annotations |
|------|-------------|-------------|
| `get_patch_day_summary` | Priority counts, HotNews list, top components, new vs. updated for a month | Read-only |
| `search_notes` | Keyword search over titles/components with priority, CVSS, month filters, ranked by CVSS | Read-only |
| `compare_patch_months` | Note counts, severity mix, and HotNews delta between two months | Read-only |
| `get_catalog_info` | Catalog version, note count, coverage window, data sources | Read-only |

### Lookup
| Tool | Description | Annotations |
|------|-------------|-------------|
| `get_note_details` | Full metadata record for one note number | Read-only |
| `lookup_cve` | SAP note(s) addressing a CVE ID | Read-only |
| `get_notes_by_component` | Notes for a component, exact + prefix matching | Read-only |

### Risk Views
| Tool | Description | Annotations |
|------|-------------|-------------|
| `get_hot_news` | All HotNews notes, ranked by CVSS | Read-only |
| `get_exploited_notes` | Notes with CISA-KEV-listed CVEs, with KEV dates | Read-only |
| `check_component_exposure` | Match a pasted list (app components, software components — optionally versioned — or product names) against the catalog | Read-only |

## Data Sources & Honesty

- **Canonical source: SAP's public Patch Day pages.** As of v2.1, the
  catalog is built primarily from SAP's public, no-login Security Patch
  Day pages (`support.sap.com/.../security-notes-news/<month>-<year>.html`),
  not a private export. Each page publishes, per note: title (with CVE
  prefix), CVE ID(s), priority, CVSS, the affected product name(s), and
  the affected software-component/version list. Raw pages are cached in
  `data/pages/` for reproducible rebuilds.
- **Public metadata only.** The catalog never contains SAP note body text
  or correction instructions — only what SAP already publishes openly:
  note numbers, titles, CVSS scores/vectors, CVE IDs, priorities, affected
  software components and their published version lists, dates, and
  public note URLs.
- **Coverage window is stated, not implied.** Current catalog:
  January 2026 – July 2026 (`get_catalog_info` always tells you exactly).
- **Null-evidence rule.** Absence from this catalog does not mean absence
  of vulnerability. Every tool says so on every not-found answer, and no
  tool ever fabricates a note, CVE, score, date, or version.
- **Exploitation data** comes from the public CISA KEV feed; the snapshot
  version and fetch date are recorded in the catalog for reproducibility.
- **Public-evidence date policy.** Exact release days ship only when
  publicly evidenced without login: the page's own stated Patch Day date
  for notes in its main table, or a date matching the CVE's public NVD
  `published` date. Everything else ships as `null`, with `release_month`
  retained (a note's presence on its public month page is the evidence
  for the month).
- **Version lists are exact and verbatim.** `affected[].versions` are kept
  exactly as SAP published them — no numeric coercion, no range expansion,
  no normalization (`758`, `75A`, `2008_1_700`, `10.0` are all real,
  unmodified formats). A version line SAP publishes in a form the parser
  can't parse cleanly (a typo, a "< X.Y.Z" threshold instead of a discrete
  list, a component name containing a space) is kept verbatim in
  `versions_unparsed` — never partially guessed.
- **Matching behavior & provenance labels.** `check_component_exposure`
  accepts application components (the legacy per-note header field, e.g.
  `BC-MID-RFC` — not published by pages, so it's `null` for notes added
  from pages only, never fabricated), software components (System →
  Status, e.g. `SAP_BASIS`, optionally versioned like `SAP_BASIS 758`),
  and product names (Maintenance Planner, e.g. "SAP S/4HANA 2023"). For a
  software component, matching is **two-tier by provenance**: PRIMARY is
  a direct, exact match against SAP's own published affected-component
  list (`match_type: published_affected_list`); FALLBACK is a curated,
  rationale-documented mapping (`data/component_mapping.yaml`) to
  application-component prefixes, used only for notes with no published
  list (`match_type: mapped_software_component`). Every match says which
  it is. When a version is given, each matched note also gets an
  exact-string-match tier (1 confirmed / 2 listed-but-version-mismatch /
  3 not assessed) — never a range or "close enough" inference. Products
  resolve through the same software-component chain; release years in
  product names are echoed back only. Which support package level fixes
  a note always requires the full SAP note.
- **Monthly updates** on SAP Patch Tuesday: `scripts/monthly_update.py
  <page-url>` fetches and caches the new page, rebuilds the catalog fresh
  from every cached page, re-runs KEV, validates the schema, and runs a CI
  gate requiring every application component to have an explicit mapping
  disposition before the build is considered commit-ready.
- **Community corrections welcome** — open a PR against
  `data/notes_catalog.json` or `data/component_mapping.yaml`.

## Quick Start

### claude.ai (hosted)

Add a custom connector with URL (no login needed):

```
https://notes.syntaai.com/mcp
```

### Claude Desktop (local, stdio)

```json
{
  "mcpServers": {
    "sap-security-notes": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/sap-security-notes-mcp/server.py"],
      "env": { "MCP_TRANSPORT": "stdio" }
    }
  }
}
```

## Deployment

```bash
git clone https://github.com/SYNTAAI/sap-security-notes-mcp
cd sap-security-notes-mcp
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Local stdio
MCP_TRANSPORT=stdio python server.py

# HTTP (this is how the hosted server runs — no authentication,
# the catalog is public read-only data)
MCP_NO_AUTH=1 PORT=8003 python server.py

# HTTP with OAuth (optional, if you self-host and want a login gate)
PORT=8003 SYNTAAI_ISSUER_URL=https://your-host python server.py
```

Adding a new month once its Patch Day page is live:

```bash
pip install -r requirements-dev.txt
python scripts/monthly_update.py \
  https://support.sap.com/en/my-support/knowledge-base/security-notes-news/<month>-<year>.html
pytest
```

This fetches and caches the page, rebuilds the catalog from every cached
page in `data/pages/` plus a fresh KEV pull, validates the schema, and
runs the CI disposition gate (fails loudly if a new application component
has no mapping decision in `data/component_mapping.yaml` yet).

One-time historical rebuild from all cached pages (used to migrate off the
original xlsx-derived catalog in v2.1):

```bash
python scripts/backfill_from_pages.py --offline
```

## License

[Apache 2.0](LICENSE) — see also [PRIVACY.md](PRIVACY.md) and
[TERMS.md](TERMS.md).

---

Want to know which of these notes are actually implemented in your SAP
systems, and what's exposed right now? That's what Syntasec does —
[syntaai.com](https://syntaai.com).
