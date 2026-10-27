# agent-watch

**Live:** https://mehrabiani.com/projects/agent-watch/

A daily threat feed on AI agents and models, in four tracks:

- **Agent incidents**: AI models or agents acting outside their scope on real systems, or exploited or used to run real attacks. Includes the AI Incident Database's records of that kind.
- **AI vulnerabilities**: disclosed flaws and working exploits in AI products, agent frameworks, MCP servers, model-serving stacks and AI dev tools, from the GitHub Advisory Database and researchers' disclosures.
- **Cyber capability**: measurements of models' offensive cyber ability, and of models gaming or recognizing evaluations, from AI security institutes and evaluators.
- **Evaluator news**: other findings, methods, funding, deals and policy from the organizations that evaluate AI safety.

Every item has a severity (critical, high, medium, low, info) from a fixed rubric, a technique, the vendors affected, and a link to the page it came from. The rubric is on the page and in [`data/agentwatch/README.md`](data/agentwatch/README.md).

## Files

- `index.html`: the page, as deployed on mehrabiani.com. Plain HTML with no build step; it reads `data/agentwatch/` beside it when served from this repo, and otherwise reads the same files from this repo over raw.githubusercontent.com, so a merged run is live within about five minutes with no deploy.
- `scripts/aw_update.py`: validates a day's run, installs it as `data/agentwatch/runs/<date>.json`, and rebuilds `feed.json` and `manifest.json`.
- `data/agentwatch/`: one JSON file per daily run, plus the two generated files the page reads.

## Publishing

A scheduled job collects what was disclosed since the previous run. A separate checker then re-opens every source and confirms each item is supported. The run is published as a pull request into `main` that adds one file under `data/agentwatch/runs/`.

The `agent-watch-guard` check rejects a pull request that touches anything outside `data/agentwatch/`, edits or deletes an earlier run, fails `scripts/aw_update.py`, or leaves the generated files out of date. With that check required on `main`, a run goes live only after it passes.
