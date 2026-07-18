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
- **OAuth 2.0** — PKCE and Dynamic Client Registration for the hosted
  server
- **stdio transport** — run it locally with no auth for Claude Desktop or
  any MCP client

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

**User prompt:** "Here are my components: SAP_BASIS, BC-JAS-WEB, CEC-SCC —
what applies to me?"

**What happens:**
- Each component is matched against the catalog (exact + prefix matching,
  so `CEC-SCC` also finds `CEC-SCC-PLA-PL`)
- Returns matching notes prioritized by severity, plus an honest list of
  components with no catalog matches
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
| `check_component_exposure` | Match a pasted component list against the catalog | Read-only |

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
- **Version caveat.** Component matching is component-level only; version
  applicability is not assessed. Always confirm against the full SAP note
  via your SAP support access.
- **Monthly updates** on SAP Patch Tuesday (second Tuesday of the month).
- **Community corrections welcome** — open a PR against
  `data/notes_catalog.json`.

## Quick Start

### claude.ai (hosted)

Add a custom connector with URL:

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

# Local stdio (no auth)
MCP_TRANSPORT=stdio python server.py

# HTTP without auth (development)
MCP_NO_AUTH=1 PORT=8003 python server.py

# HTTP with OAuth (production)
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
