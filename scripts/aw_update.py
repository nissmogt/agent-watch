#!/usr/bin/env python3
"""Install one agent-watch daily run, then rebuild feed.json and manifest.json.

    scripts/aw_update.py --run new-run.json     # validate, install as runs/<date>.json, rebuild
    scripts/aw_update.py                        # validate every run on disk and rebuild

The page reads only data/agentwatch/manifest.json and data/agentwatch/feed.json,
both generated here from data/agentwatch/runs/*.json. Never hand-edit them.
"""
import argparse, json, os, re, sys
from datetime import date as Date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "agentwatch")
RUNS = os.path.join(DATA, "runs")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TRACKS = ["incident", "vuln", "capability", "evaluator"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
TECHNIQUES = ["prompt-injection", "jailbreak", "sandbox-escape", "unsanctioned-action", "destructive-action",
              "credential-theft", "data-exposure", "supply-chain", "code-execution", "auth-bypass",
              "denial-of-service", "ai-assisted-intrusion", "misuse", "eval-gaming", "cyber-capability", "other"]
STATUSES = ["confirmed", "reported", "disputed"]
FIELDS = ["date", "track", "severity", "title", "summary", "publisher", "vendors", "products", "technique",
          "cve", "ghsa", "cvss", "status", "url", "source_name", "aiid", "note"]
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
GHSA = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")


def die(msg):
    sys.exit("aw_update: " + msg)


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        die("cannot read %s: %s" % (path, e))


def cvss_band(score):
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:48].strip("-")


def check_run(doc, where):
    for field in ("date", "run_at", "window_from", "window_to", "title", "summary", "items"):
        if field not in doc:
            die("%s: run is missing %r" % (where, field))
    for field in ("date", "window_from", "window_to"):
        if not DAY.match(str(doc[field])):
            die("%s: %s must be YYYY-MM-DD, got %r" % (where, field, doc[field]))
    if doc["window_from"] > doc["window_to"] or doc["window_to"] > doc["date"]:
        die("%s: window must run forward and end by the run date" % where)
    if not isinstance(doc["items"], list):
        die("%s: items must be a list (an empty list is a quiet day)" % where)
    seen = set()
    for n, it in enumerate(doc["items"]):
        at = "%s item %d" % (where, n + 1)
        extra = sorted(set(it) - set(FIELDS) - {"id"})
        if extra:
            die("%s: unknown fields %s" % (at, ", ".join(extra)))
        for f in FIELDS:
            if f not in it:
                die("%s: missing %r" % (at, f))
        if not DAY.match(str(it["date"])):
            die("%s: date must be YYYY-MM-DD" % at)
        try:
            Date.fromisoformat(it["date"])
        except ValueError:
            die("%s: %r is not a real date" % (at, it["date"]))
        if it["date"] > doc["date"]:
            die("%s: dated %s, after the run date %s" % (at, it["date"], doc["date"]))
        if it["track"] not in TRACKS:
            die("%s: track %r not in %s" % (at, it["track"], TRACKS))
        if it["severity"] not in SEVERITIES:
            die("%s: severity %r not in %s" % (at, it["severity"], SEVERITIES))
        if it["technique"] not in TECHNIQUES:
            die("%s: technique %r not in the list" % (at, it["technique"]))
        if it["track"] in ("incident", "vuln"):
            if it["status"] not in STATUSES and it["severity"] != "info":
                die("%s: incidents and vulnerabilities need status in %s" % (at, STATUSES))
        elif it["status"] not in ("", None):
            die("%s: status applies only to incidents and vulnerabilities" % at)
        for f, lim in (("title", 160), ("summary", 480)):
            if not isinstance(it[f], str) or not it[f].strip():
                die("%s: %s is empty" % (at, f))
            if len(it[f]) > lim:
                die("%s: %s is %d characters, limit %d" % (at, f, len(it[f]), lim))
        if not str(it["url"]).startswith("https://"):
            die("%s: url must be https" % at)
        if not isinstance(it["vendors"], list) or not all(isinstance(v, str) and v for v in it["vendors"]):
            die("%s: vendors must be a list of names" % at)
        if it["cve"] and not CVE.match(it["cve"]):
            die("%s: malformed CVE %r" % (at, it["cve"]))
        if it["ghsa"] and not GHSA.match(it["ghsa"]):
            die("%s: malformed GHSA id %r" % (at, it["ghsa"]))
        if it["cvss"] is not None:
            if not isinstance(it["cvss"], (int, float)) or not 0 <= it["cvss"] <= 10:
                die("%s: cvss must be a number from 0 to 10" % at)
            if it["track"] == "vuln" and it["severity"] != cvss_band(it["cvss"]):
                die("%s: CVSS %.1f is %s, but severity says %s" % (at, it["cvss"], cvss_band(it["cvss"]), it["severity"]))
        if it["aiid"] is not None and not (isinstance(it["aiid"], int) and it["aiid"] > 0):
            die("%s: aiid must be a record number or null" % at)
        key = it["url"]
        if key in seen:
            die("%s: the same url appears twice in this run" % at)
        seen.add(key)
    return doc


def rebuild():
    files = sorted(f for f in os.listdir(RUNS) if f.endswith(".json"))
    if not files:
        die("no runs in %s" % RUNS)
    runs, feed, urls = [], [], {}
    for f in files:
        doc = check_run(load(os.path.join(RUNS, f)), "runs/" + f)
        if f != doc["date"] + ".json":
            die("runs/%s holds a run dated %s" % (f, doc["date"]))
        ids = set()
        for it in doc["items"]:
            if it["url"] in urls:
                die("runs/%s repeats %s, already in runs/%s" % (f, it["url"], urls[it["url"]]))
            urls[it["url"]] = f
            base = "%s-%s" % (it["date"], slug(it["title"]))
            iid, k = base, 2
            while iid in ids:
                iid, k = "%s-%d" % (base, k), k + 1
            ids.add(iid)
            feed.append(dict(it, id=doc["date"] + "/" + iid, added=doc["date"]))
        sev = {s: sum(1 for it in doc["items"] if it["severity"] == s) for s in SEVERITIES}
        runs.append({"date": doc["date"], "run_at": doc["run_at"], "window_from": doc["window_from"],
                     "window_to": doc["window_to"], "title": doc["title"], "summary": doc["summary"],
                     "sources_note": doc.get("sources_note", ""), "backfill": bool(doc.get("backfill")),
                     "count": len(doc["items"]), "by_severity": sev})
    order = {s: i for i, s in enumerate(SEVERITIES)}
    feed.sort(key=lambda it: (it["date"], -order[it["severity"]], it["id"]), reverse=True)
    runs.sort(key=lambda r: r["date"], reverse=True)
    updated = runs[0]["date"]
    manifest = {"updated": updated, "run_at": runs[0]["run_at"], "items": len(feed), "runs": runs,
                "vocab": {"tracks": TRACKS, "severities": SEVERITIES, "techniques": TECHNIQUES, "statuses": STATUSES}}
    with open(os.path.join(DATA, "feed.json"), "w") as fh:
        json.dump({"updated": updated, "items": feed}, fh, ensure_ascii=False, indent=0)
        fh.write("\n")
    with open(os.path.join(DATA, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    return updated, len(runs), len(feed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", help="a new run file to install")
    a = ap.parse_args()
    os.makedirs(RUNS, exist_ok=True)
    if a.run:
        doc = check_run(load(a.run), a.run)
        dest = os.path.join(RUNS, doc["date"] + ".json")
        if os.path.exists(dest):
            die("runs/%s.json already exists; a run is never replaced" % doc["date"])
        latest = sorted(f for f in os.listdir(RUNS) if f.endswith(".json"))
        if latest and doc["date"] <= latest[-1][:-5]:
            die("run date %s is not after the latest run %s" % (doc["date"], latest[-1][:-5]))
        with open(dest, "w") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
            fh.write("\n")
    updated, n_runs, n_items = rebuild()
    print("aw_update: ok — %d runs, %d items, latest %s" % (n_runs, n_items, updated))


if __name__ == "__main__":
    main()
