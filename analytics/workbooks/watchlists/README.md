# TAM EWI watchlists — sample data

Sixteen sample watchlists for the TAM EWI workbook. They exist so the board
renders with believable numbers before an account's real systems are wired in.
**Replace the contents before using any of this with a client.** The data
describes a fictional account (`Contoso Ltd`) and is anchored to 2026-11-17.

## Why these are needed

The 24 indicators read their input from these watchlists, not from live tables
(A01–A04, A07–A09 are the exceptions). With no watchlists, those indicators
report `State = "No data"` and the Watchlist A/B tabs are a wall of em-dashes:
the workbook renders, but there is nothing to look at and no way to tell a
threshold bug from a missing feed.

## Creating them

Sentinel → Configuration → Watchlists → New. The **alias must match the file
name exactly** (case-sensitive) — that is the string `_GetWatchlist()` is
called with. Use these search keys:

| Watchlist | Search key | Feeds |
|---|---|---|
| `TAM_EWIConfig` | `Key` | every indicator (thresholds), G01 |
| `TAM_EstateInventory` | `Hostname` | A01 |
| `TAM_ContractedSources` | `SourceName` | A02 |
| `TAM_DetectionInventory` | `RuleName` | A05 |
| `TAM_ThreatProfile` | `TechniqueId` | A05, coverage drill-down |
| `TAM_Tickets` | `TicketId` | A06 |
| `TAM_ClientRequests` | `RequestId` | B02 |
| `TAM_Runbooks` | `Name` | A10 |
| `TAM_Changes` | `ChangeId` | A02 (context), A10 |
| `TAM_ServiceReviews` | `MeetingDate` | B01 |
| `TAM_Contacts` | `Role` | B03 |
| `TAM_CSAT` | `SurveyDate` | B04, A09 |
| `TAM_Contract` | `ContractEnd` | B05, B06 |
| `TAM_Entitlement` | `Service` | B05 |
| `TAM_PSA` | `Month` | B09, B10 |
| `TAM_Signals` | `SignalDate` | B07, B08, B09 |

Create all sixteen even if a file is left empty. Every value arrives as a
string and the functions convert; booleans accept `TRUE`/`yes`/`y`/`1`.

## What this sample data produces

Verified by replaying each function's state logic against these CSVs as at
2026-11-17:

| | State | Why |
|---|---|---|
| A05 Detection coverage | Green | all 6 `Top` techniques covered, 1 rule added in 60d |
| A06 Tuning backlog | Green | oldest open item 28 days, backlog not growing |
| A10 Runbook currency | **Red** | `Ransomware containment` last tested 2026-06-30, before the major change on 2026-08-14 |
| B01 Review attendance | Green | sponsor attended 2 of the last 3, one deputy |
| B02 Client response | Green | median 2 working days, nothing blocking |
| B03 Sponsor change | Green | sponsor and champion both current, no changes in 90d |
| B04 CSAT pulse | **Amber** | last pulse 3.8 against a 4.0 threshold; rolling 4.3 |
| B05 Entitlement | Green | 78% used, 63% of term elapsed |
| B06 Contract runway | **Amber** | 134 days to renewal (amber at 180), conversation held |
| B07 Estate change | **Amber** | one open signal: VDI pool outside DCR scope |
| B08 Competitive | Green | the one competitive signal is closed |
| B09 Cross-service | Green | 20h of OffSec/Advisory work in the last 6 months |
| B10 Scope drift | Green | no non-contracted effort last month, margin 31.2% |
| G01 Governance | Green | all 42 thresholds reviewed 2026-11-17 |

The Red and three Ambers are deliberate: they exercise the RAG formatters, and
each one is a realistic finding rather than a broken feed. To get an all-green
board, set `Ransomware containment`'s `LastTested` to a date after 2026-08-14,
raise the 2026-11-10 CSAT score above 4.0, push `ContractEnd` past 180 days,
and close the estate-change signal.

Note that G01 turns Amber once these thresholds are 92 days old — around
2027-02-17 — which is the indicator doing its job, not a fault.

## One caveat on A02

`TAM_ContractedSources` is the one file whose sample content is likely to read
Red in your workspace. A02 compares the list against tables that have actually
received data in the last 14 days, so any source listed here that your
workspace does not have counts as quiet, and two quiet sources are enough for
Red. Trim this file to the tables you really ingest before judging A02.

The `Match` column is what separates appliances sharing one table: the
drill-down builds a key of `vendor|product|computer|devicename` (lowercased)
for `CommonSecurityLog` and `computer|hostname` for `Syslog`, then tests
`Key contains Match`. Leave `Match` empty and the source is only checked at
table level, so one silent firewall stays hidden inside a busy table.

## Still external to the repo

`TAM_Vulns_CL` (daily Defender Vulnerability Management exposure snapshots,
feeds A11) and `TAM_EWISnapshot_CL` (the daily EWI snapshot, feeds the
Portfolio and History tabs) are custom tables, not watchlists. A11 reports
"No data" and the Portfolio tab errors until those exist.
