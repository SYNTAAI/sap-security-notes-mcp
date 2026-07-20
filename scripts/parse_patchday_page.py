#!/usr/bin/env python3
"""Parse a public SAP Security Patch Day page (support.sap.com, no login)
into structured note records, including affected software components and
their published version lists.

Public page grammar (reverse-engineered from the Jan-Jul 2026 pages, see
scripts/build_catalog.py's public-evidence date policy for the sibling
date-verification work):

  <tr><td>NUMBER</td><td>
    ["Update to Security Note released on <Month> <Year> Patch Day:"]?
    "[" (CVE-YYYY-NNNNN | "Multiple CVEs") "]"?  "<b>TITLE</b>"
    ["Related CVEs - " CVE, CVE, ...]?
    ["Product - " PRODUCT_NAME]?
    ["Version(s) - " | "Versions - " VERSION_LINE]?
  </td><td>PRIORITY</td><td>CVSS</td></tr>

Not every note has every optional part (e.g. the npm-malicious-packages
notes have no CVE and use "Package versions:" instead of "Version(s) -",
which is a different grammar we deliberately do NOT parse).

Version-line grammar (the hard part): comma-separated tokens where a token
that CONTAINS A SPACE splits into (COMPONENT, VERSION) if the first half
looks like a component name (starts with a letter) and the second half
looks like a version (starts with a digit); a token with NO space is a
continuation version for the current component (also must start with a
digit). Any token that doesn't fit lands the WHOLE version line in
versions_unparsed with zero partial component/version emitted — see
parse_versions_line().
"""

import argparse
import html
import json
import re
import sys
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
NOTE_URL_RE = re.compile(r"me\.sap\.com/notes/(\d+)")
TAG_RE = re.compile(r"<[^>]+>")
MONTH_NAMES = ["january", "february", "march", "april", "may", "june",
               "july", "august", "september", "october", "november",
               "december"]

COMPONENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-/]*$")
VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9_.\-]*$")

TRAILING_PRIORITY_RE = re.compile(
    r"(Critical|High|Medium|Low)\s+([0-9]+(?:\.[0-9]+)?)\s*$"
)
CVSS_VECTOR_HREF_RE = re.compile(
    r"first\.org/cvss/calculator/[\d.]*#(CVSS:[^\"']*)"
)
LEADING_NOTE_RE = re.compile(r"^\s*(\d{6,8})\s*")
UPDATE_MARKER_RE = re.compile(
    r"^Update to Security Note released on\s+"
    r"([A-Za-z]+\s+\d{4})\s+Patch Day:\s*"
)
BRACKET_RE = re.compile(r"^\[\s*(Multiple CVEs|CVE-\d{4}-\d{4,7})\s*\]\s*")
# SAP uses several synonyms for a follow-up CVE list: "Related CVEs",
# "Additional CVE(s)", or a bare "CVEs" label.
RELATED_CVES_RE = re.compile(
    r"(?:Related CVEs|Additional CVEs?|CVEs)\s*[-–]\s*"
    r"((?:CVE-\d{4}-\d{4,7}\s*,?\s*)+)"
)
# "Library -" is used instead of "Product -" for a few npm/node.js-packaged
# components (e.g. SAP Approuter).
PRODUCT_RE = re.compile(r"(?:Product|Library)\s*[-–]?\s*")
VERSION_MARKER_RE = re.compile(r"(?:Version\(s\)|Versions)\s*[-–]\s*")


def parse_versions_line(raw: str) -> tuple[list[dict], str | None]:
    """Parse a 'Version(s) - ...' payload into affected components.

    Conservative by design: on ANY token that doesn't fit the grammar, the
    whole line is returned unparsed with no partial component/version
    guesses. Version tokens are kept verbatim (no numeric coercion, no
    range expansion).
    """
    raw = raw.strip()
    if not raw:
        return [], None

    tokens = [t.strip() for t in raw.split(",")]
    order: list[str] = []
    versions: dict[str, list[str]] = {}
    current: str | None = None

    for tok in tokens:
        if not tok:
            return [], raw
        if " " in tok:
            name, _, ver = tok.partition(" ")
            name, ver = name.strip(), ver.strip()
            if not COMPONENT_RE.match(name) or not VERSION_RE.match(ver):
                return [], raw
            if name not in versions:
                versions[name] = []
                order.append(name)
            if ver not in versions[name]:
                versions[name].append(ver)
            current = name
        else:
            if current is None or not VERSION_RE.match(tok):
                return [], raw
            if tok not in versions[current]:
                versions[current].append(tok)

    affected = [{"software_component": n, "versions": versions[n]}
                for n in order]
    return affected, None


def _flatten(row_html: str) -> str:
    text = TAG_RE.sub(" ", row_html)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def parse_row(row_html: str, source_url: str, month: str) -> dict | None:
    vm = CVSS_VECTOR_HREF_RE.search(row_html)
    cvss_vector = html.unescape(vm.group(1)) if vm else None

    text = _flatten(row_html)
    if not text:
        return None

    m = TRAILING_PRIORITY_RE.search(text)
    if not m:
        return None  # not a note row (e.g. header row)
    priority_raw = m.group(1)
    cvss_score = float(m.group(2))
    if cvss_score == 0.0:
        cvss_score = None
    body = text[:m.start()].strip()

    m = LEADING_NOTE_RE.match(body)
    if not m:
        return None
    note_number = m.group(1)
    body = body[m.end():].strip()

    section = "new"
    update_hint = None
    m = UPDATE_MARKER_RE.match(body)
    if m:
        section = "updated"
        update_hint = m.group(1)
        body = body[m.end():].strip()

    cve_ids: list[str] = []
    multiple_cves = False
    m = BRACKET_RE.match(body)
    if m:
        if m.group(1) == "Multiple CVEs":
            multiple_cves = True
        else:
            cve_ids = [m.group(1)]
        body = body[m.end():].strip()

    m = RELATED_CVES_RE.search(body)
    if m:
        related = CVE_RE.findall(m.group(1))
        for c in related:
            if c not in cve_ids:
                cve_ids.append(c)
        if len(cve_ids) > 1:
            multiple_cves = True
        title = body[:m.start()].strip()
        rest = body[m.end():].strip()
    else:
        pm = PRODUCT_RE.search(body)
        if pm:
            title = body[:pm.start()].strip()
            rest = body[pm.start():]
        else:
            title = body
            rest = ""

    product_names: list[str] = []
    affected: list[dict] = []
    versions_unparsed: str | None = None

    pm = PRODUCT_RE.match(rest) if rest else None
    if pm:
        after_product = rest[pm.end():]
        vm = VERSION_MARKER_RE.search(after_product)
        if vm:
            product_name = after_product[:vm.start()].strip().rstrip(".,;")
            if product_name:
                product_names = [product_name]
            version_line = after_product[vm.end():].strip()
            affected, versions_unparsed = parse_versions_line(version_line)
        else:
            leftover = after_product.strip()
            if leftover:
                versions_unparsed = leftover
    elif rest.strip():
        versions_unparsed = rest.strip()

    return {
        "note_number": note_number,
        "title": title,
        "cve_ids": cve_ids,
        "multiple_cves": multiple_cves,
        "priority_raw": priority_raw,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "product_names": product_names,
        "affected": affected,
        "versions_unparsed": versions_unparsed,
        "section": section,
        "update_hint_month": update_hint,
        "note_url": f"https://me.sap.com/notes/{note_number}",
        "source_url": source_url,
        "month": month,
    }


def parse_page(page_html: str, source_url: str, month: str) -> list[dict]:
    records = []
    for t_idx, table in enumerate(re.findall(r"<table.*?</table>", page_html, re.S)):
        for row in re.findall(r"<tr.*?</tr>", table, re.S):
            if "<th" in row and "<td" not in row:
                continue
            rec = parse_row(row, source_url, month)
            if rec:
                rec["table_index"] = t_idx
                records.append(rec)
    return records


PATCH_DAY_INTRO_RE = re.compile(
    r"On\s+(\d{1,2})\s*(?:st|nd|rd|th)?\s+of\s+([A-Za-z]+)\s+(\d{4}),?\s+"
    r"SAP security patch day"
)


def parse_patch_day_date(page_html: str) -> str | None:
    """Extract the literal patch-day date SAP states in the page's intro
    paragraph (e.g. 'On 13th of January 2026, SAP security patch day...').
    This is the explicit public date for every 'new' row in the first
    (main) table — used in preference to computing the 2nd-Tuesday formula
    ourselves, since the page's own words are the public evidence."""
    text = _flatten(page_html[:20000])
    m = PATCH_DAY_INTRO_RE.search(text)
    if not m:
        return None
    day, month_name, year = m.group(1), m.group(2).lower(), m.group(3)
    if month_name not in MONTH_NAMES:
        return None
    mm = MONTH_NAMES.index(month_name) + 1
    return f"{year}-{mm:02d}-{int(day):02d}"


def coverage_report(records: list[dict]) -> dict:
    total = len(records)
    unparsed = sum(1 for r in records if r["versions_unparsed"] is not None)
    return {
        "total": total,
        "parsed": total - unparsed,
        "unparsed": unparsed,
        "unparsed_notes": [r["note_number"] for r in records
                           if r["versions_unparsed"] is not None],
    }


def month_from_url(url: str) -> str:
    m = re.search(r"([a-z]+)-(\d{4})\.html", url.lower())
    if not m:
        raise ValueError(f"Cannot infer month from URL: {url}")
    name, year = m.group(1), m.group(2)
    return f"{year}-{MONTH_NAMES.index(name) + 1:02d}"


def load_page(source: str) -> tuple[str, str]:
    """Return (html, source_url) for a URL or local file path."""
    if source.startswith("http"):
        import httpx
        resp = httpx.get(source, timeout=60, follow_redirects=True)
        resp.raise_for_status()
        return resp.text, source
    path = Path(source)
    return path.read_text(errors="ignore"), source


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", help="Page URL or local HTML file path")
    ap.add_argument("--month", help="YYYY-MM (inferred from URL if omitted)")
    ap.add_argument("--out", help="Write JSON records to this path")
    args = ap.parse_args()

    page_html, source_url = load_page(args.source)
    month = args.month or month_from_url(source_url)
    records = parse_page(page_html, source_url, month)
    cov = coverage_report(records)

    print(f"{month}: {cov['total']} rows, {cov['parsed']} parsed, "
          f"{cov['unparsed']} unparsed {cov['unparsed_notes']}",
          file=sys.stderr)

    if args.out:
        Path(args.out).write_text(json.dumps(records, indent=1))
    else:
        json.dump(records, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
