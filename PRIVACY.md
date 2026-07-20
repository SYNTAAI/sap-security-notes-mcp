# Privacy Policy

**SAP Security Notes MCP Server**
*Last updated: July 18, 2026*

## Overview

The SAP Security Notes MCP Server ("the Service") is a Model Context
Protocol (MCP) server that answers questions about publicly available SAP
Security Note **metadata** (note numbers, titles, CVSS scores, CVE IDs,
components, release dates, and CISA KEV exploitation status). This privacy
policy describes how data is handled when using the Service.

## Data Collection

### What the Service Serves
The Service answers queries from a static, versioned catalog of public
metadata built from SAP Security Patch Day publications and the public
CISA Known Exploited Vulnerabilities (KEV) feed. It does not connect to
any SAP system.

### What You Provide
The only user-provided system information the Service accepts is a
**pasted component list** (e.g. `SAP_BASIS, BC-JAS-WEB`) for the
`check_component_exposure` tool. This list is **processed in-memory for
the duration of the request and is never stored or logged**.

### What We Do NOT Collect
- **No SAP system connection** — the Service never connects to, reads
  from, or writes to your SAP systems
- **No personal data is stored** — queries are answered from the static
  catalog and discarded
- **No credentials for your systems** — OAuth 2.0 tokens authenticate you
  to this Service only, and are managed per-session
- **No tracking** — no cookies, pixels, or tracking scripts
- **No data shared with third parties** — your queries are never
  transmitted to any party other than the authenticated AI assistant
  session

### Operational Usage Logging
The hosted Service keeps a minimal operational log per tool call
containing exactly three fields: a UTC timestamp, the tool name (e.g.
`get_patch_day_summary`), and a SHA-256-hashed session identifier.
**Tool arguments, request bodies, pasted component lists, and IP
addresses are never logged.** Logs rotate daily and are used solely for
service-health and aggregate usage statistics. Running the server
yourself (stdio or self-hosted) writes such logs only on your own
machine.

## Data Sources

- SAP Security Note metadata from SAP Security Patch Day publications.
  The catalog contains **only metadata** — never SAP note body text,
  correction instructions, or any content behind SAP support login.
- Exploitation status from the public CISA KEV feed
  (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Authentication

- Hosted mode uses **OAuth 2.0** with PKCE and dynamic client registration
- Access tokens are scoped to read-only catalog queries
- You can revoke access at any time by disconnecting the connector
- Local stdio mode runs without authentication on your own machine

## Data Residency

- **Local (stdio):** everything runs on your machine; nothing leaves it.
- **Hosted (notes.syntaai.com):** queries pass through the server hosted
  on AWS (Mumbai region, ap-south-1) but are not stored. Component lists
  are processed in-memory only.

## Your Rights

You have the right to:
- **Disconnect** — remove the MCP connector from your AI assistant at any
  time
- **Audit** — the entire catalog and server source are open (Apache 2.0),
  so you can verify exactly what the Service does
- **Delete** — no user data is stored, so there is nothing to delete on
  our side

## Children's Privacy

This Service is intended for use by security and SAP operations
professionals. It is not directed at children under 13 (or applicable age
in your jurisdiction).

## Changes to This Policy

We may update this privacy policy from time to time. Changes will be
posted to this repository with an updated "Last updated" date.

## Contact

- **Email:** contact@syntaai.com
- **Company:** SyntaAI
- **Website:** [www.syntaai.com](https://www.syntaai.com)

---

*SAP is a registered trademark of SAP SE. This project is not affiliated
with or endorsed by SAP SE.*
