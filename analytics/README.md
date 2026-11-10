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

| Analytic | Query frequency | Lookup period | Notes |
|---|---|---|---|
| A1, A2, A3, A5 | 1 h | 1 h | Reduce `lookback` in the file to match the lookup period |
| A4 | 15 min | 1 h | Credential access warrants a tighter loop |
| A6 | 1 h | 4 h | Needs ≥ `burstWindow` + `successWindow` of overlap |

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
