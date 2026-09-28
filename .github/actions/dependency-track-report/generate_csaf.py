import json
import os
from datetime import datetime, timezone
from pathlib import Path
from dependency_track import get_analysis, validate_config

INPUT = Path(
    os.environ.get(
        "DTRACK_FINDINGS_FILE",
        "/tmp/dtrack-findings.json",
    )
)
OUTPUT = Path(
    os.environ.get(
        "CSAF_OUTPUT",
        "/tmp/csaf-vex.json",
    )
)

STATE_MAP = {
    "IN_TRIAGE": "under_investigation",
    "NOT_AFFECTED": "known_not_affected",
    "EXPLOITABLE": "known_affected",
}

CSAF_SELF_URL = os.environ.get("CSAF_SELF_URL")
CSAF_PUBLISHER_NAME = os.environ.get(
    "CSAF_PUBLISHER_NAME",
    "mundialis"
)

CSAF_PUBLISHER_NAMESPACE = os.environ.get(
    "CSAF_PUBLISHER_NAMESPACE",
    "https://mundialis.de"
)
CSAF_DOCUMENT_ID = os.environ.get("CSAF_DOCUMENT_ID")


def build_product_tree(
    project_name,
    project_version,
    product_id,
):
    return {
        "branches": [
            {
                "category": "vendor",
                "name": CSAF_PUBLISHER_NAME,
                "branches": [
                    {
                        "category": "product_name",
                        "name": project_name,
                        "branches": [
                            {
                                "category": "product_version",
                                "name": project_version,
                                "product": {
                                    "name": f"{project_name} {project_version}",
                                    "product_id": product_id,
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }


def build_document_content(
    project_name,
    project_version,
    product_id,
    vulnerabilities,
):
    document = {
        "category": "csaf_vex",
        "csaf_version": "2.0",
        "distribution": {
            "tlp": {
                "label": "WHITE"
            }
        },
        "lang": "en",
        "notes": [
            {
                "category": "description",
                "title": "Description",
                "text": f"VEX document for {project_name}.",
            }
        ],
        "publisher": {
            "category": "vendor",
            "name": CSAF_PUBLISHER_NAME,
            "namespace": CSAF_PUBLISHER_NAMESPACE,
        },
        "title": f"VEX for {project_name}",
    }

    if CSAF_SELF_URL:
        document["references"] = [
            {
                "category": "self",
                "summary": "Canonical URL for this CSAF advisory",
                "url": CSAF_SELF_URL,
            }
        ]

    return {
        "document": document,
        "product_tree": build_product_tree(
            project_name,
            project_version,
            product_id,
        ),
        "vulnerabilities": vulnerabilities,
    }

def build_tracking(document_id, now):
    return {
        "current_release_date": now,
        "id": str(document_id),
        "initial_release_date": now,
        "revision_history": [
            {
                "date": now,
                "number": "1",
                "summary": "Initial release",
            }
        ],
        "status": "draft",
        "version": "1",
    }


def apply_in_triage(entry, analysis, _product_id, _vulnerability):
    details = (
        analysis.get("analysisDetails")
        or "The vulnerability is currently under investigation."
    )

    entry["notes"].append(
        {
            "category": "details",
            "title": "Investigation status",
            "text": details,
        }
    )


def apply_not_affected(
    entry,
    analysis,
    product_id,
    _vulnerability,
):
    justification = analysis.get("analysisJustification")
    details = analysis.get("analysisDetails")

    parts = []

    if justification and justification != "NOT_SET":
        parts.append(f"Justification: {justification}.")

    if details:
        parts.append(details)

    if not parts:
        parts.append(
            "The product has been assessed as not affected."
        )

    entry["threats"] = [
        {
            "category": "impact",
            "details": " ".join(parts),
            "product_ids": [product_id],
        }
    ]


def apply_exploitable(
    entry,
    analysis,
    product_id,
    vulnerability,
):
    details = (
        analysis.get("analysisDetails")
        or "The vulnerability has been assessed as exploitable."
    )

    entry["notes"].append(
        {
            "category": "details",
            "title": "Exploitability analysis",
            "text": details,
        }
    )

    entry["remediations"] = [
        {
            "category": "mitigation",
            "details": (
                "The vulnerability is known to affect this product. "
                "Appropriate remediation or mitigation should be evaluated."
            ),
            "product_ids": [product_id],
        }
    ]

    if (
        vulnerability.get("cvssV3BaseScore") is not None
        and vulnerability.get("cvssV3Vector")
    ):
        vector = vulnerability["cvssV3Vector"]

        cvss_version = "3.1"
        if vector.startswith("CVSS:3.0/"):
            cvss_version = "3.0"

        entry["scores"] = [
            {
                "cvss_v3": {
                    "baseScore": vulnerability["cvssV3BaseScore"],
                    "baseSeverity": vulnerability["severity"],
                    "vectorString": vector,
                    "version": cvss_version,
                },
                "products": [product_id],
            }
        ]


STATE_HANDLERS = {
    "IN_TRIAGE": apply_in_triage,
    "NOT_AFFECTED": apply_not_affected,
    "EXPLOITABLE": apply_exploitable,
}


def build_vulnerability_entry(finding, analysis):
    component = finding["component"]
    vulnerability = finding["vulnerability"]

    state = analysis.get("analysisState")

    if not state or state == "NOT_SET":
        return None

    if state not in STATE_MAP:
        return None

    product_id = (
        f'{component["projectName"]}-'
        f'{component["projectVersion"]}'
    )

    entry = {
        "cve": vulnerability["vulnId"],
        "notes": [
            {
                "category": "description",
                "title": "Analysis status",
                "text": vulnerability.get(
                    "description",
                    "No description available.",
                ),
            }
        ],
        "product_status": {
            STATE_MAP[state]: [product_id]
        },
        "title": vulnerability["vulnId"],
    }

    handler = STATE_HANDLERS[state]
    handler(
        entry,
        analysis,
        product_id,
        vulnerability,
    )

    cwes = vulnerability.get("cwes", [])
    if cwes:
        entry["cwe"] = {
            "id": f'CWE-{cwes[0]["cweId"]}',
            "name": cwes[0]["name"],
        }

    return entry

def main():

    validate_config()
        
    with INPUT.open() as f:
        findings = json.load(f)

    now = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    valid_findings = []
    vulnerabilities = []

    for finding in findings:
        full_analysis = get_analysis(finding)

        vulnerability_entry = build_vulnerability_entry(
            finding,
            full_analysis,
        )

        if vulnerability_entry:
            vulnerabilities.append(vulnerability_entry)
            valid_findings.append(finding)

    if not vulnerabilities:
        OUTPUT.unlink(missing_ok=True)
        print("No analyzed findings available for CSAF generation.")
        return

    first = valid_findings[0]
    project_name = first["component"]["projectName"]
    project_version = first["component"]["projectVersion"]
    product_id = f"{project_name}-{project_version}"
    document_id = CSAF_DOCUMENT_ID or f"{project_name}-csaf-vex"
    document_content = build_document_content(
        project_name,
        project_version,
        product_id,
        vulnerabilities,
    )

    tracking = build_tracking(
        document_id,
        now,
    )
    document = document_content
    document["document"]["tracking"] = tracking

    with OUTPUT.open("w") as f:
        json.dump(document, f, indent=2)

    print(f"Generated {OUTPUT}")

if __name__ == "__main__":
    main()
