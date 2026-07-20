# v2.1 Backfill Discrepancy Report

Catalog rebuilt from public SAP Security Patch Day pages (Jan-Jul 2026) as primary source, cross-checked against the prior xlsx-derived catalog.

## Parse coverage per month

| Month | Rows | Parsed (affected data) | Unparsed | Unparsed notes |
|---|---|---|---|---|
| 2026-01 | 19 | 18 | 1 | 3666061 |
| 2026-02 | 32 | 32 | 0 | - |
| 2026-03 | 17 | 17 | 0 | - |
| 2026-04 | 21 | 20 | 1 | 3747787 |
| 2026-05 | 19 | 19 | 0 | - |
| 2026-06 | 16 | 16 | 0 | - |
| 2026-07 | 19 | 15 | 4 | 3747367, 3720138, 3758101, 3741519 |

## New notes added from public pages (16)

These were on a public Patch Day page but absent from the prior xlsx export — the xlsx export missed them. Added; `component` (legacy SAP application component) is null for these since pages don't publish it — never fabricated. They remain fully reachable via the affected[] software-component/version data.

- **3687749** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3668679** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3694242** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3691059** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3675151** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3565506** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3688703** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3681523** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3687372** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3666061** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3638716** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3655227** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3655229** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3677111** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3657998** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.
- **3593356** — On public page(s) ['https://support.sap.com/en/my-support/knowledge-base/security-notes-news/january-2026.html'] but absent from the prior xlsx-derived catalog.

## In prior catalog but not found on any public page (0)

Kept as-is for human review — absence from the pages we fetched does not mean the note doesn't exist.


## Field-level differences: public page wins (8)

| Note | Field | Old (xlsx) | New (public page) |
|---|---|---|---|
| 3678417 | cve_ids | `['CVE-2026-0505']` | `['CVE-2026-0505', 'CVE-2026-24323']` |
| 3700960 | cve_ids | `[]` | `['CVE-2025-9230', 'CVE-2025-9232']` |
| 3747787 | release_month | `2026-05` | `2026-04` |
| 3733064 | title | `Missing authentication check in SAP Commerce Cloud configuration` | `Missing authentication check in SAP Commerce cloud configuration` |
| 3747484 | cve_ids | `['CVE-2026-29145']` | `['CVE-2026-29145', 'CVE-2025-66614', 'CVE-2026-24734']` |
| 3758101 | cve_ids | `['CVE-2026-40860']` | `['CVE-2026-40860', 'CVE-2026-40453', 'CVE-2026-33454']` |
| 3763800 | cve_ids | `[]` | `['CVE-2026-43512', 'CVE-2026-41293', 'CVE-2026-43515']` |
| 3732522 | title | `- Information Disclosure vulnerability in SAP HANA Extended Application Services classic model (User Self Service)` | `Information Disclosure vulnerability in SAP HANA Extended Application Services classic model (User Self Service)` |
