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

**User prompt:** "Here is my stack: SAP S/4HANA 2023, SAP_BASIS,
BC-JAS-WEB — what applies to me?"

**What happens:**
- Each item is classified: application component (`BC-JAS-WEB`), software
  component from System → Status (`SAP_BASIS`), or product/stack name from
  Maintenance Planner (`SAP S/4HANA 2023`)
- Application components match directly (exact + prefix); software
  components and products resolve through a curated, rationale-documented
  mapping to application-component prefixes
- Returns matching notes grouped by provenance, plus an honest "not
  assessed" bucket for anything that could not be classified or mapped
- Always includes the caveat: version applicability is not assessed —
  confirm against the full SAP note

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
| `check_component_exposure` | Match a pasted list (app components, software components, or product names) against the catalog | Read-only |

## Data Sources & Honesty

- **Public metadata only.** The catalog holds note numbers, titles, CVSS
  scores/vectors, CVE IDs, priorities, components, dates, and public note
  URLs — built from SAP Security Patch Day publications. It never
  contains SAP note body text or correction instructions.
- **Coverage window is stated, not implied.** Current catalog:
  January 2026 – July 2026 (`get_catalog_info` always tells you exactly).
- **Null-evidence rule.** Absence from this catalog does not mean absence
  of vulnerability. Every tool says so on every not-found answer, and no
  tool ever fabricates a note, CVE, score, or date.
- **Exploitation data** comes from the public CISA KEV feed; the snapshot
  version and fetch date are recorded in the catalog for reproducibility.
- **Matching behavior & provenance labels.** The catalog is indexed by SAP
  **application component** (the component in each note's header, e.g.
  `BC-MID-RFC`). `check_component_exposure` also accepts **software
  components** (System → Status, e.g. `SAP_BASIS`) and **product names**
  (Maintenance Planner, e.g. "SAP S/4HANA 2023"), resolved through a
  curated mapping (`data/component_mapping.yaml`) in which every entry
  carries a rationale and anything uncertain is listed as unmapped rather
  than guessed. Every returned note carries a `match_type` — `direct`,
  `prefix`, `mapped_software_component`, or `mapped_product` — and
  mapping-derived results are labeled as such ("Matched via curated
  mapping (…) — mapping-derived, confirm applicability against the full
  SAP note"). Release years in product names are echoed back only.
- **Version caveat.** Component matching is component-level only; version
  applicability is not assessed. Always confirm against the full SAP note
  via your SAP support access.
- **Monthly updates** on SAP Patch Tuesday (second Tuesday of the month).
- **Community corrections welcome** — open a PR against
  `data/notes_catalog.json`.

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

Rebuilding the catalog from a fresh SAP export:

```bash
pip install -r requirements-dev.txt
python scripts/build_catalog.py input/security-notes-result-YYYYMMDD.xlsx
pytest
```

## License

[Apache 2.0](LICENSE) — see also [PRIVACY.md](PRIVACY.md) and
[TERMS.md](TERMS.md).

---

Want to know which of these notes are actually implemented in your SAP
systems, and what's exposed right now? That's what Syntasec does —
[syntaai.com](https://syntaai.com).
