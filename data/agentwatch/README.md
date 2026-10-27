# agent-watch — data

`runs/<date>.json` holds one daily run. `feed.json` and `manifest.json` are generated from the runs by `scripts/aw_update.py`; never edit them by hand.

## A run

```jsonc
{
  "date": "2026-10-28",                 // run date; also the file name
  "run_at": "2026-10-28T17:47:00-07:00",
  "window_from": "2026-10-27",          // disclosures collected from this day ...
  "window_to": "2026-10-28",            // ... through this day
  "title": "plain-words headline for the day",
  "summary": "two or three sentences on what changed",
  "sources_note": "which sources were read, and any that could not be",
  "backfill": false,                    // true only for the initial load
  "aiid_checked_to": 1745,              // highest AI Incident Database record number checked so far
  "items": [ /* zero or more items; an empty list is a quiet day */ ]
}
```

## An item

```jsonc
{
  "date": "2026-10-23",          // when the source first published it
  "track": "vuln",               // incident | vuln | capability | evaluator
  "severity": "high",            // critical | high | medium | low | info
  "title": "…", "summary": "…",  // own words; no quoted phrase longer than 10 words
  "publisher": "GitHub Advisory Database",
  "vendors": ["Anthropic"],      // whose AI system is affected or tested
  "products": "claude-agent-sdk (pip)",
  "technique": "code-execution", // see below
  "cve": "CVE-2026-96620", "ghsa": "GHSA-h4mw-j7qp-8mwm", "cvss": 9.8,
  "status": "confirmed",         // incident and vuln only: confirmed | reported | disputed; "" otherwise
  "url": "https://…",            // the page the item was taken from
  "source_name": "GitHub",
  "aiid": null,                  // AI Incident Database record number, if there is one
  "note": ""                     // caveats
}
```

`technique` is one of `prompt-injection`, `jailbreak`, `sandbox-escape`, `unsanctioned-action`, `destructive-action`, `credential-theft`, `data-exposure`, `supply-chain`, `code-execution`, `auth-bypass`, `denial-of-service`, `ai-assisted-intrusion`, `misuse`, `eval-gaming`, `cyber-capability`, `other`.

## Tracks

- **incident**: an AI model or agent acted outside its scope on real systems, or was exploited or used to run a real attack. Not deepfakes, scams or fraud by people, and not lawsuits over chatbot advice.
- **vuln**: a disclosed flaw or working exploit in an AI product, agent framework, MCP server or SDK, model-serving stack or AI dev tool.
- **capability**: measurements of models' offensive cyber ability, and of models gaming or recognizing evaluations.
- **evaluator**: other findings, methods, funding, deals and policy from the organizations that evaluate AI safety.

## Severity

| severity | when |
|---|---|
| critical | confirmed compromise of a real third party or production system by or through an AI system; actively exploited; CVSS 9.0+ |
| high | unsanctioned or destructive action on live systems; working exploit against a shipped AI product; CVSS 7.0–8.9; a large measured jump in offensive capability |
| medium | CVSS 4.0–6.9; a new attack technique shown in research; routine capability results |
| low | CVSS below 4.0; minor issues |
| info | analysis, follow-ups, methods, funding, policy |

A vulnerability with a published CVSS score takes that score's band, and `aw_update.py` refuses one that doesn't.

## Rules the script enforces

- Every field above is present, with values from the lists.
- Dates are real `YYYY-MM-DD` days, no item is dated after its run, and the window ends by the run date.
- A new run is dated after the latest run, and an existing run is never replaced.
- A source URL appears once across all runs. A later development on the same story needs its own source.
- URLs are https.

Run `scripts/aw_update.py` with no arguments to re-validate everything and rebuild the generated files.
