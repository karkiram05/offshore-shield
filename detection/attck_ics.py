"""A small, hand-curated subset of MITRE ATT&CK for ICS techniques.

Only techniques this lab's detection rules actually map to are listed here
-- this is not an attempt to reproduce the full framework (79 techniques +
18 sub-techniques as of the current matrix). IDs and names verified against
https://attack.mitre.org/matrices/ics/ ; re-verify before adding entries,
since MITRE does renumber/retire techniques between matrix versions.
"""

TECHNIQUES = {
    "T0846": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T0846/",
    },
    "T0840": {
        "name": "Network Connection Enumeration",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T0840/",
    },
    "T0888": {
        "name": "Remote System Information Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T0888/",
    },
    "T0886": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T0886/",
    },
    "T0859": {
        "name": "Valid Accounts",
        "tactic": "Initial Access, Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T0859/",
    },
    "T0836": {
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "url": "https://attack.mitre.org/techniques/T0836/",
    },
    "T0814": {
        "name": "Denial of Service",
        "tactic": "Inhibit Response Function",
        "url": "https://attack.mitre.org/techniques/T0814/",
    },
}


def describe(technique_id: str) -> dict:
    entry = TECHNIQUES.get(technique_id)
    if entry is None:
        raise KeyError(
            f"{technique_id} is not in this lab's curated ATT&CK-for-ICS subset "
            f"(detection/attck_ics.py) -- add it there with a verified name/tactic "
            f"before referencing it, don't invent an entry inline."
        )
    return {"id": technique_id, **entry}
