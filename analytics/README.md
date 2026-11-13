# Detection analytics — Defender XDR / Microsoft Sentinel

Six detection analytics written in KQL against **standard, commonly available
tables** in Microsoft Defender XDR advanced hunting and Microsoft Sentinel. No
custom tables, no ASIM, no third-party connectors, no watchlists required (a
couple are suggested as optional tuning aids).

Each analytic targets one of the attack behaviours that sit at the top of
Red Canary's Threat Detection Report year after year — the techniques that
appear across the largest share of confirmed threats, rather than the ones that
are merely interesting.

## Sourcing note

The URL supplied with the request (`https://redcanary.com/the-red-canary-difference/`)
could not be retrieved from the environment this was authored in — `redcanary.com`
is not in the session's outbound network allowlist, so DNS resolution was
refused. Technique selection therefore reflects the behaviours Red Canary's
published Threat Detection Report has consistently ranked highest
(command and scripting interpreters, signed binary proxy execution,
masquerading, credential dumping from LSASS, ingress tool transfer, and
identity/MFA abuse) rather than a quotation from that specific page. If you
want the ranking cross-checked against the current report, allow
`redcanary.com` for the session and the selection and ordering can be
re-validated against it.

## The six analytics

| # | File | Detects | Primary ATT&CK | Tables |
|---|------|---------|----------------|--------|
| A1 | `kql/01-powershell-suspicious-execution.kql` | Encoded, downloading, hidden-window or in-memory PowerShell | T1059.001, T1027, T1105 | `DeviceProcessEvents` |
| A2 | `kql/02-signed-binary-proxy-execution.kql` | rundll32 / mshta / regsvr32 / msiexec LOLBin execution, incl. squiblydoo and Office-spawned | T1218.011, T1218.005, T1218.010, T1218.007 | `DeviceProcessEvents` |
| A3 | `kql/03-masquerading-renamed-system-binary.kql` | Native tools renamed or run from outside system directories (PE metadata vs on-disk name) | T1036.003, T1036.005 | `DeviceProcessEvents` |
| A4 | `kql/04-lsass-credential-access.kql` | LSASS dumping, SAM/SECURITY hive theft, NTDS.dit extraction, credential-store theft | T1003.001, T1003.002, T1003.003, T1555 | `DeviceProcessEvents`, `DeviceFileEvents` (+ optional `DeviceEvents`) |
| A5 | `kql/05-ingress-tool-transfer-lolbin-download.kql` | certutil / bitsadmin / curl / msiexec payload download, **correlated with observed egress** | T1105, T1071.001 | `DeviceProcessEvents`, `DeviceNetworkEvents` |
| A6 | `kql/06-identity-mfa-fatigue-and-anomalous-signin.kql` | MFA push fatigue or spray that ends in a successful sign-in from an unfamiliar ASN/country | T1621, T1110.003, T1078.004 | `SigninLogs` (+ `AADSignInEventsBeta` / `IdentityLogonEvents` alternatives noted inline) |

A1–A5 run unchanged in Defender XDR advanced hunting, and in Sentinel wherever
the Defender XDR connector is streaming the `Device*` tables. A6 is a Sentinel
query against the Entra ID connector; the file documents the Defender-only
substitute.

## Design decisions worth knowing

**Multi-signal scoring, not single-string matching.** A1, A2, A5 and A6 build a
`Signals` array and alert on co-occurrence. One indicator (`-nop`, a URL in a
command line, five MFA denials) is background noise in any real estate; two or
three together is a detection. This keeps the queries tunable by *threshold*
instead of by deleting coverage.

**Behaviour over atomic IOCs.** No hashes, no domains, no tool names that break
the moment an operator recompiles. Where tool names do appear (A4's `mimikatz`,
`nanodump`) they are additive bonus signals, not the sole condition.

**Correlation where it buys fidelity.** A5 joins process execution to
`DeviceNetworkEvents` on the same process ID so a "suspicious command line"
becomes an "observed transfer". A6 joins the denial burst to the success and
then to a 30-day sign-in baseline, so the alert fires on the outcome rather
than on noisy failure volume.

**Exclusions belong in the environment, not the logic.** Each file ends with a
`--- Tuning ---` block describing the benign sources you should expect and the
tuple to exclude on (usually parent process + path + signer, or user + host).
Exclude on a full tuple; do not delete a signal from the scoring array, and do
not allow-list a whole account or an entire interpreter.

## Deploying in Sentinel

1. Validate in the Logs blade (or Defender advanced hunting) over the
   `lookback` already set in each file, and check the hit volume.
2. Work the `--- Tuning ---` block until the daily volume is one an analyst can
   actually triage.
3. Create the Scheduled Analytics Rule. Suggested cadence:

| Analytic | Query frequency | Lookup period | In-file `lookback` to set |
|---|---|---|---|
| A1, A2, A5 | 1 h | 1 h | `1h` (ships as 7d for hunting) |
| A3 | 1 h | 1 h | `1h` (ships as 14d for hunting) |
| A4 | 15 min | 1 h | `1h` (ships as 14d for hunting) |
| A6 | 1 h | **30 d** | `3d`, and see the baseline note below |

**Every file ships with a hunting-width `lookback` (3–14 days). You must reduce
it to the rule's lookup period before scheduling it**, or each run re-evaluates
the whole window and every historical hit re-alerts on every run — at A4's
15-minute cadence that is 96 duplicate alerts a day, and the rule gets muted
within a day.

**A6's baseline needs the long lookup period.** A Sentinel scheduled rule
constrains the entire query to its configured lookup period, which clips A6's
30-day `KnownAsns` / `KnownCountries` baseline to nothing. With an empty
baseline the `UnfamiliarAsn` and `UnfamiliarCountry` signals can never fire. Two
supported options: set the rule's lookup period to 30 days (expensive on a busy
tenant), or maintain the baseline in a Sentinel summary rule or watchlist and
join against that instead. Either way the query emits `BaselineAvailable` and a
`BaselineUnavailable-CheckRuleLookupPeriod` signal, so a clipped baseline shows
up in the alert rather than silently downgrading every hit.

4. Set entity mappings so incidents correlate:
   - Host → `DeviceName`, Host `HostID` → `DeviceId`
   - Account → `AccountName` / `AccountDomain` (A6: `UserPrincipalName`, `UserId`)
   - Process → `ProcessCommandLine`, `ProcessId`
   - IP → `RemoteIPs` (A5), `SuccessIp` (A6)
   - File / FileHash → `FileName`, `SHA256` (A3, A4)
5. Use the `Severity` column each query emits to drive rule severity, or split
   one rule per severity tier if your SOC routes High and Medium differently.
6. Enable incident grouping on the Host or Account entity over 5 h — these
   techniques chain, and you want one incident for the intrusion, not six.

## Validation status

These queries have been reviewed for schema and KQL-semantic correctness but
**not executed against a live tenant** — there was no Defender or Sentinel
workspace available when they were authored. Run each one interactively over
its shipped `lookback` and check the hit volume before promoting any of them to
a scheduled rule.

Two KQL semantics worth knowing before you edit them:

- **`has` / `has_any` match whole indexed terms, not substrings.** Indicators
  that depend on punctuation — `` ` ``, `${`, `[char]`, `'+'`, `https://`,
  `/qn` — must use `contains` or `matches regex`. Several signals in A1, A2 and
  A5 are written that way on purpose; "simplifying" them back to `has_any`
  stops them matching.
- **`in` wants a constant list or a tabular expression, not a per-row dynamic
  column.** Membership against a `make_set()` column uses
  `set_has_element()` (see A6).

## Deliberate omissions

Two Red Canary top-ranked techniques are **not** covered here, because doing
them properly needs tables that are not universally onboarded:

- **T1055 Process Injection** — needs `DeviceEvents`
  (`CreateRemoteThreadApiCall`, `ProcessPrimaryTokenModified`) or Sysmon
  events 8/10 for anything better than a command-line guess.
- **T1053.005 / T1543.003 / T1547.001 Persistence** — covered partly by A1/A2
  as a side effect; a dedicated analytic wants `DeviceRegistryEvents` plus
  scheduled-task operational logs to keep the false-positive rate sane.

Both are straightforward follow-ons if those tables are available.

## Also in this folder

- `workbooks/tam-account-health.kql` — a separate pack of account-health
  queries for a Microsoft Sentinel workbook (telemetry and connector health,
  detection coverage vs a client threat profile, noise/escalation trends,
  governance trackers and an EWI RAG board). One query per workbook step, with
  the suggested visualization noted inline. Unlike the six detection analytics
  above, it does require Sentinel auditing and health monitoring to be enabled
  and several watchlists; prerequisites are listed in the header of the file.
