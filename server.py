"""SAP Security Notes MCP Server.

A free, open-source MCP server answering questions about SAP Security Note
METADATA: Patch Day releases, CVSS, CVEs, components, and CISA-KEV
exploitation status. It serves only public metadata — never SAP note body
text or correction instructions.

Transports:
    MCP_TRANSPORT=http   (default) Streamable HTTP on $PORT (default 8003)
    MCP_TRANSPORT=stdio  stdio for local use (auth is disabled)

Auth (http mode): OAuth 2.0 with PKCE and Dynamic Client Registration via
oauth_provider.SyntaAIOAuthProvider. Disable with MCP_NO_AUTH=1.
"""

import logging
import os

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.types import ToolAnnotations

from catalog import Catalog, NULL_EVIDENCE

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("notes-mcp.server")

# --- Configuration (env) ---
TRANSPORT = os.getenv("MCP_TRANSPORT", "http").lower()
PORT = int(os.getenv("PORT", os.getenv("MCP_PORT", "8003")))
HOST = os.getenv("MCP_HOST", "0.0.0.0")
ISSUER_URL = os.getenv("SYNTAAI_ISSUER_URL", "https://notes.syntaai.com")
NO_AUTH = (
    os.getenv("MCP_NO_AUTH", "").lower() in ("1", "true", "yes")
    or TRANSPORT == "stdio"
)

CATALOG = Catalog()

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                             openWorldHint=False)

_TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*",
                   "notes.syntaai.com", "notes.syntaai.com:*"],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*",
                     "http://[::1]:*", "https://notes.syntaai.com",
                     "https://notes.syntaai.com:*"],
)

_INSTRUCTIONS = (
    "SAP Security Notes MCP server: query SAP Security Note METADATA "
    "(Patch Day releases, CVSS scores, CVEs, components, CISA KEV "
    "exploitation status) for the coverage window reported by "
    "get_catalog_info. All tools are read-only over a static public "
    "catalog.\n\n"
    "Honesty rules that apply to every answer:\n"
    "- Absence from this catalog does NOT mean absence of vulnerability.\n"
    "- This is public metadata only; users must review the full SAP note "
    "via their own SAP support access before acting.\n"
    "- Never invent notes, CVEs, scores, or dates that the tools did not "
    "return."
)

if NO_AUTH:
    if TRANSPORT != "stdio":
        logger.warning("Running WITHOUT authentication (MCP_NO_AUTH=1)")
    mcp = FastMCP(
        "SAP Security Notes",
        instructions=_INSTRUCTIONS,
        host=HOST,
        port=PORT,
        transport_security=_TRANSPORT_SECURITY,
    )
else:
    from oauth_provider import SyntaAIOAuthProvider

    oauth_provider = SyntaAIOAuthProvider()

    mcp = FastMCP(
        "SAP Security Notes",
        instructions=_INSTRUCTIONS,
        auth_server_provider=oauth_provider,
        auth=AuthSettings(
            issuer_url=ISSUER_URL,
            resource_server_url=ISSUER_URL,
            revocation_options=RevocationOptions(enabled=True),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["notes:read"],
                default_scopes=["notes:read"],
            ),
        ),
        host=HOST,
        port=PORT,
        transport_security=_TRANSPORT_SECURITY,
    )


# ============================================================================
# TOOLS (10, all read-only)
# ============================================================================

@mcp.tool(annotations=_READ_ONLY)
def get_patch_day_summary(month: str | None = None) -> dict:
    """Summarize an SAP Security Patch Day month: counts by priority, the
    HotNews list, top components, and new vs. updated notes.

    Args:
        month: 'YYYY-MM' (e.g. '2026-07'). Defaults to the latest month in
            the catalog.

    Absence from this catalog does not mean absence of vulnerability; the
    catalog covers a fixed window only (see get_catalog_info).
    """
    return CATALOG.patch_day_summary(month)


@mcp.tool(annotations=_READ_ONLY)
def search_notes(
    query: str,
    component: str | None = None,
    priority: str | None = None,
    min_cvss: float | None = None,
    month: str | None = None,
) -> dict:
    """Keyword search over note titles and components, ranked by CVSS
    (descending). Optional filters: component prefix, priority
    (HotNews/High/Medium/Low), minimum CVSS score, and month ('YYYY-MM').

    An empty result means no MATCH IN THIS CATALOG — never proof that no
    vulnerability exists.
    """
    return CATALOG.search(query, component, priority, min_cvss, month)


@mcp.tool(annotations=_READ_ONLY)
def get_note_details(note_number: str) -> dict:
    """Full catalog record for one SAP Security Note number.

    If the note is not in the catalog you get an explicit not-in-catalog
    message — that does not mean the note doesn't exist or that no
    vulnerability exists.
    """
    return CATALOG.note_details(note_number)


@mcp.tool(annotations=_READ_ONLY)
def get_notes_by_component(component: str, since: str | None = None) -> dict:
    """Notes for an SAP application component, using exact match AND prefix
    match (e.g. 'BC-JAS' also matches 'BC-JAS-WEB' and 'BC-JAS-SEC-UME').
    The response states which match mode applied.

    Args:
        component: SAP component, e.g. 'BC-BSP' or a prefix like 'BC-JAS'.
        since: optional cutoff, 'YYYY-MM' or 'YYYY-MM-DD'.

    No matches means no notes IN THIS CATALOG for that component — not that
    the component has no vulnerabilities.
    """
    return CATALOG.notes_by_component(component, since)


@mcp.tool(annotations=_READ_ONLY)
def get_hot_news(since: str | None = None) -> dict:
    """All HotNews (highest-severity) notes in the catalog, ranked by CVSS.

    Args:
        since: optional cutoff, 'YYYY-MM' or 'YYYY-MM-DD'.

    Covers only the catalog window; absence here is not evidence of absence.
    """
    return CATALOG.hot_news(since)


@mcp.tool(annotations=_READ_ONLY)
def lookup_cve(cve_id: str) -> dict:
    """Find the SAP Security Note(s) addressing a CVE ID.

    Not-found is reported explicitly and does not mean the CVE is
    unaddressed or nonexistent — notes tagged '[Multiple CVEs]' don't list
    individual CVE IDs in the source metadata.
    """
    return CATALOG.lookup_cve(cve_id)


@mcp.tool(annotations=_READ_ONLY)
def check_component_exposure(
    components: list[str], since: str | None = None
) -> dict:
    """Match a pasted list of SAP components against the catalog. Accepts
    three input formats and classifies each item:

    - application components (BC-JAS-WEB, BI-BIP) — direct + prefix match
    - software components from System → Status (SAP_BASIS, S4CORE, SAP_UI) —
      resolved via a curated mapping to application-component prefixes
    - product/stack names from Maintenance Planner ('SAP S/4HANA 2023',
      'ABAP PLATFORM 2023') — resolved product → software components →
      application-component prefixes

    Every returned note carries a match_type (direct, prefix,
    mapped_software_component, mapped_product) and results are grouped by
    provenance; mapping-derived matches say so explicitly. Items that cannot
    be classified or mapped land in an explicit 'not assessed' bucket — no
    bucket ever implies safety.

    Release years in product names are echoed back, but version
    applicability is NOT assessed — confirm against the full SAP note.

    Args:
        components: e.g. ['SAP_BASIS', 'BC-JAS-WEB', 'SAP S/4HANA 2023'].
        since: optional cutoff, 'YYYY-MM' or 'YYYY-MM-DD'.
    """
    return CATALOG.component_exposure(components, since)


@mcp.tool(annotations=_READ_ONLY)
def get_exploited_notes(since: str | None = None) -> dict:
    """Notes whose CVEs appear in the CISA Known Exploited Vulnerabilities
    (KEV) catalog, with KEV date-added.

    A zero count means none of THIS catalog's CVEs were KEV-listed at
    snapshot time — not that exploitation is impossible.
    """
    return CATALOG.exploited_notes(since)


@mcp.tool(annotations=_READ_ONLY)
def compare_patch_months(month_a: str, month_b: str) -> dict:
    """Compare two Patch Day months: note counts, severity mix, HotNews
    delta. Months must be 'YYYY-MM' within the catalog window; anything
    else returns an explicit not-in-catalog message.
    """
    return CATALOG.compare_months(month_a, month_b)


@mcp.tool(annotations=_READ_ONLY)
def get_catalog_info() -> dict:
    """Catalog metadata: version, note count, coverage window, data
    sources, KEV snapshot info, and the null-evidence rule verbatim.
    """
    return CATALOG.catalog_info()


# ============================================================================
# RESOURCES (4)
# ============================================================================

@mcp.resource("catalog://info")
def resource_info() -> str:
    """Catalog version, coverage window, and data sources."""
    import json
    return json.dumps(CATALOG.catalog_info(), indent=1)


@mcp.resource("catalog://latest-patch-day")
def resource_latest_patch_day() -> str:
    """Pre-rendered summary of the latest Patch Day month in the catalog."""
    s = CATALOG.patch_day_summary()
    lines = [
        f"SAP Security Patch Day — {s['month']}",
        f"Total notes: {s['total_notes']} "
        f"({s['new_notes']} new, {s['updated_notes']} updates)",
        "By priority: " + ", ".join(
            f"{k}: {v}" for k, v in sorted(s["counts_by_priority"].items())
        ),
        "",
        "HotNews:",
    ]
    for n in s["hot_news"] or []:
        lines.append(
            f"  - Note {n['note_number']} ({n['component']}, "
            f"CVSS {n['cvss_score']}): {n['title']}"
        )
    if not s["hot_news"]:
        lines.append("  (none this month)")
    lines += [
        "",
        "Top components: " + ", ".join(
            f"{c['component']} ({c['note_count']})" for c in s["top_components"]
        ),
        "",
        NULL_EVIDENCE,
    ]
    return "\n".join(lines)


@mcp.resource("catalog://components")
def resource_components() -> str:
    """Distinct SAP components in the catalog (helps query construction)."""
    return "\n".join(CATALOG.distinct_components())


@mcp.resource("catalog://priority-definitions")
def resource_priority_definitions() -> str:
    """What the SAP note priority levels mean, in plain language."""
    return (
        "SAP Security Note priorities (as normalized in this catalog):\n\n"
        "- HotNews: SAP's highest severity class, typically CVSS 9.0+. "
        "These are the notes SAP expects customers to treat as emergencies "
        "and implement as soon as possible.\n"
        "- High: serious vulnerabilities ('correction with high priority') "
        "that should be scheduled into the next maintenance window, ahead "
        "of routine patching.\n"
        "- Medium: vulnerabilities with meaningful but more limited impact "
        "or harder exploitation; patch as part of the regular Patch Day "
        "cycle.\n"
        "- Low: minor security corrections; include with normal maintenance."
        "\n\nPriority is SAP's classification of the note, not a substitute "
        "for your own risk assessment. " + NULL_EVIDENCE
    )


# ============================================================================
# PROMPTS (4)
# ============================================================================

_PROMPT_FOOTER = (
    "\n\nGround rules for your answer:\n"
    "- Absence from this catalog does not mean absence of vulnerability; "
    "say so wherever it applies.\n"
    "- This is public metadata only — tell the user to review the full SAP "
    "note via their SAP support access before acting.\n"
    "- Analysis only: do not execute, simulate, or suggest exploit steps.\n"
    "- Never invent notes, CVEs, scores, or dates the tools did not return."
)


@mcp.prompt()
def monthly_patch_briefing(month: str = "") -> str:
    """CISO-level briefing for an SAP Security Patch Day month."""
    target = month or "the latest month in the catalog"
    return (
        f"Prepare a CISO-level briefing on SAP Security Patch Day for "
        f"{target}, using get_patch_day_summary"
        + (f" with month='{month}'" if month else "")
        + " (and get_note_details / get_exploited_notes where useful).\n\n"
        "Structure:\n"
        "1. HotNews first — what they affect and why they matter, in plain "
        "business language (no jargon without a one-line explanation).\n"
        "2. Call out anything CISA-KEV-listed (actively exploited) "
        "explicitly; if nothing is KEV-listed, say so and explain what "
        "that does and does not mean.\n"
        "3. Recommended prioritization order: KEV-listed first, then "
        "HotNews, then High, then the rest — with the reasoning.\n"
        "4. Notable component clusters or updates to previously released "
        "notes." + _PROMPT_FOOTER
    )


@mcp.prompt()
def exposure_check(components: str = "") -> str:
    """Check a pasted SAP component list against the catalog."""
    intro = (
        "Help the user check their SAP component list against this "
        "catalog.\n\n"
    )
    if components:
        intro += (
            f"The user provided this list: {components}\n"
            "Parse it into items and call check_component_exposure.\n\n"
        )
    else:
        intro += (
            "First ask the user to paste their list. All three formats "
            "work, mixed freely:\n"
            "- Software components from SAP GUI: System → Status → "
            "Component information (SAP_BASIS, S4CORE, SAP_UI, ...)\n"
            "- Product/stack lines from Maintenance Planner "
            "('SAP S/4HANA 2023', 'ABAP PLATFORM 2023', 'SAP FIORI FES')\n"
            "- SAP application components (BC-JAS-WEB, BI-BIP, ...) — the "
            "taxonomy this catalog is indexed by; each note's header "
            "carries one\n"
            "Then call check_component_exposure with that list.\n\n"
        )
    return intro + (
        "Produce a prioritized report:\n"
        "1. State how each pasted item was classified (application "
        "component / software component / product) and how it was matched "
        "— keep the tool's provenance labels: direct/prefix matches vs. "
        "'matched via curated mapping (...)'. Mapping-derived results must "
        "say they are mapping-derived.\n"
        "2. Matched items ordered by worst finding (KEV-listed, then "
        "HotNews, then CVSS); for each note: number, title, priority, "
        "CVSS, link, match_type.\n"
        "3. The 'not assessed' bucket, stated honestly: could not map or "
        "no notes in this catalog — this does NOT mean no vulnerabilities "
        "exist. Explain the taxonomy difference where relevant (software "
        "components vs application components).\n"
        "4. Echo any product release years ('your stack: S/4HANA 2023') "
        "and repeat prominently: version applicability is not assessed — "
        "the user must confirm against each full SAP note.\n"
        "5. Relay any 'hints' the tool returns verbatim — e.g. for an "
        "S/4HANA product paste: if the landscape runs HCM (SAP_HR / H4S4), "
        "the user should add SAP_HR to their list to include HR notes."
        + _PROMPT_FOOTER
    )


@mcp.prompt()
def patch_backlog_prioritizer(note_numbers: str = "") -> str:
    """Rank a pasted list of SAP note numbers into a patching order."""
    return (
        "The user wants their SAP security note backlog prioritized.\n\n"
        + (
            f"Note numbers provided: {note_numbers}\n"
            if note_numbers
            else "Ask the user to paste the SAP security note numbers in "
                 "their backlog.\n"
        )
        + "Call get_note_details for each number (and get_exploited_notes "
        "for KEV context), then rank by:\n"
        "1. KEV-listed (actively exploited) — always first.\n"
        "2. CVSS score (higher first; treat unscored/null honestly as "
        "'not scored', not as zero).\n"
        "3. SAP priority (HotNews > High > Medium > Low).\n"
        "4. Age (older unpatched notes first, using released_on).\n\n"
        "Show the ranking with one line of reasoning per note. Any number "
        "not found in the catalog must be flagged honestly as "
        "not-in-catalog (which does not mean the note doesn't exist or "
        "doesn't matter) — never guess its contents." + _PROMPT_FOOTER
    )


@mcp.prompt()
def cve_investigation(cve_id: str = "") -> str:
    """Investigate a CVE: SAP note, component, severity, KEV status."""
    return (
        "Investigate an SAP-related CVE for the user.\n\n"
        + (
            f"CVE to investigate: {cve_id}\n"
            if cve_id
            else "Ask the user which CVE ID they want to investigate.\n"
        )
        + "Call lookup_cve, then get_note_details for each matching note.\n\n"
        "Report:\n"
        "1. Which SAP Security Note(s) address the CVE, with links.\n"
        "2. Affected component(s) and what they are, in plain language.\n"
        "3. Severity: CVSS score and vector (flag malformed vectors as "
        "published-as-is), SAP priority.\n"
        "4. CISA KEV status and date added, if listed.\n"
        "5. If the CVE is not in the catalog, say so explicitly, mention "
        "that '[Multiple CVEs]' notes don't enumerate individual CVE IDs, "
        "and do not speculate." + _PROMPT_FOOTER
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    if TRANSPORT == "stdio":
        mcp.run(transport="stdio")
        raise SystemExit(0)

    import anyio
    import uvicorn
    from starlette.routing import Route

    logger.info("Starting SAP Security Notes MCP on %s:%s", HOST, PORT)
    logger.info("OAuth: %s", "DISABLED" if NO_AUTH else "ENABLED")
    logger.info("Catalog: %s notes, %s → %s",
                CATALOG.meta["note_count"],
                CATALOG.meta["coverage_start"], CATALOG.meta["coverage_end"])

    app = mcp.streamable_http_app()

    if not NO_AUTH:
        from oauth_provider import login_page_handler
        app.routes.insert(
            0, Route("/syntaai-login", login_page_handler,
                     methods=["GET", "POST"])
        )
        app.state.oauth_provider = oauth_provider

    # ---- Middleware: force public-client registration for PKCE-only clients.
    # Some connectors register without token_endpoint_auth_method; the MCP SDK
    # then defaults to "client_secret_post" and requires a secret the client
    # never sends. Inject "none" (public client + PKCE) when omitted.
    from starlette.types import Receive, Scope, Send
    _inner_app = app

    async def request_middleware(scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            method = scope.get("method", "?")
            path = scope.get("path", "?")
            if method == "POST" and path == "/register":
                body_parts = []

                async def reg_receive():
                    msg = await receive()
                    if msg.get("type") == "http.request":
                        body_parts.append(msg.get("body", b""))
                    return msg

                await reg_receive()
                raw = b"".join(body_parts)
                try:
                    import json as _json
                    payload = _json.loads(raw)
                    if "token_endpoint_auth_method" not in payload:
                        payload["token_endpoint_auth_method"] = "none"
                        raw = _json.dumps(payload).encode()
                        logger.info(
                            "register: injected token_endpoint_auth_method="
                            "none for %s", payload.get("client_name", "?"))
                except Exception:
                    pass  # not JSON — let the SDK produce the error

                body_sent = False

                async def patched_receive():
                    nonlocal body_sent
                    if not body_sent:
                        body_sent = True
                        return {"type": "http.request", "body": raw,
                                "more_body": False}
                    return await receive()

                scope["headers"] = [
                    (k, str(len(raw)).encode() if k == b"content-length" else v)
                    for k, v in scope.get("headers", [])
                ]
                await _inner_app(scope, patched_receive, send)
                return

        await _inner_app(scope, receive, send)

    config = uvicorn.Config(request_middleware, host=HOST, port=PORT,
                            log_level="info")
    anyio.run(uvicorn.Server(config).serve)
