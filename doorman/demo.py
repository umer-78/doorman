"""Builds the demo page's data: every suite attack against every configuration, with the
PDF each one arrived in and what each layer did about it.

The benchmark's applicants are real resumes, which this repository does not republish,
so the demo carries each payload in a fictional resume instead. The outcomes shown are
from running the demo's own PDFs through the pipeline, so what you open is what was tested.

    python -m doorman demo     writes docs/data.json and docs/pdfs/
"""
import json
from pathlib import Path

from . import bench
from .attacks import GOALS, LOCATIONS, PHRASINGS, succeeded, suite
from .pdfs import parse
from .pipeline import CONFIGS, GullibleModel, screen

SAMPLE = """Sam Rivera
Backend Engineer, Leeds, United Kingdom
Summary
Backend engineer with six years of building web services in Python and Django, mostly on PostgreSQL.
I like small, well-tested services and boring deployments.
Experience
Senior Software Engineer, Harbour Logistics, 2021 to present
Built the shipment tracking API in Django REST Framework, serving 30 million requests a day.
Moved nightly batch jobs from cron scripts to a queue, which cut failed runs from weekly to none in a year.
Software Engineer, Meadow Health, 2018 to 2021
Wrote the appointment booking service in Flask with a PostgreSQL database.
Ran the team's code review rota and wrote the onboarding guide for new engineers.
Education
BSc Computer Science, University of Leeds, 2018
Skills
Python, Django, Flask, PostgreSQL, Git, REST APIs"""
OUT = Path(__file__).resolve().parent.parent / "docs"


def build(out=OUT):
    (out / "pdfs").mkdir(parents=True, exist_ok=True)
    guard = bench.train_guard()
    scenario = bench.Scenario.__new__(bench.Scenario)   # the others in the tracking system, without the corpus
    scenario.others = [bench.application(k + 1, text) for k, text in enumerate(
        ["Alex Morgan\nData engineer with SQL and AWS experience.", "Jordan Lee\nFrontend developer, JavaScript and REST.",
         "Casey Patel\nSite reliability engineer, Linux, Docker and Kubernetes."])]
    attacks = []
    for attack in suite():
        app, page = bench.application(4, SAMPLE, attack=attack)
        (out / "pdfs" / f"{attack.id}.pdf").write_bytes(app.pdf)
        parsed = parse(app.pdf)
        results = {}
        for config in CONFIGS:
            world = scenario.world(app, page)
            outcome = screen(world, app, config, GullibleModel(attack), guard)
            results[config.name] = {"worked": succeeded(attack.goal, world, app.id), "held": outcome.held,
                                    "events": outcome.events, "score": world.scores.get(app.id),
                                    "status": world.status[app.id], "mail": [m["to"] for m in world.outbox]}
        attacks.append({"id": attack.id, "location": attack.location, "goal": attack.goal, "phrasing": attack.phrasing,
                        "payload": attack.payload, "pdf": f"pdfs/{attack.id}.pdf",
                        "visible": parsed.visible[-400:], "hidden": parsed.hidden, "subject": parsed.metadata.get("subject", ""),
                        "page": page if attack.location == "tool result" else "", "results": results})
    summary = json.loads((out.parent / "results" / "baseline.json").read_text())
    data = {"configs": [c.name for c in CONFIGS], "locations": list(LOCATIONS), "goals": list(GOALS), "phrasings": list(PHRASINGS),
            "attacks": attacks, "bench": {k: summary[k] for k in ("configs", "guard", "bypass", "benign_hidden_text", "per_location")}}
    (out / "data.json").write_text(json.dumps(data, indent=1))
    return data
