import hashlib
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

SBOM_PATH = Path(
    os.environ.get(
        "SBOM_PATH",
        "docker.cyclonedx.json",
    )
)

STATE_MAP = {
    "IN_TRIAGE": "under_investigation",
    "NOT_AFFECTED": "known_not_affected",
    "EXPLOITABLE": "known_affected",
    "RESOLVED": "fixed",
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
    sbom_path,
    sbom_sha256,
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
                                    "product_identification_helper": {
                                        "hashes": [
                                            {
                                                "filename": sbom_path.name,
                                                "file_hashes": [
                                                    {
                                                        "algorithm": "sha256",
                                                        "value": sbom_sha256,
                                                    }
                                                ],
                                            }
                                        ]
                                    },
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
    sbom_path,
    sbom_sha256,
    vulnerabilities,
):
    references = []

    if CSAF_SELF_URL:
        references.append(
            {
                "category": "self",
                "summary": "Canonical URL for this CSAF advisory",
                "url": CSAF_SELF_URL,
            }
        )

    return {
        "document": {
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
            "references": references,
            "title": f"VEX for {project_name}",
        },
        "product_tree": build_product_tree(
            project_name,
            project_version,
            product_id,
            sbom_path,
            sbom_sha256,
        ),
        "vulnerabilities": vulnerabilities,
    }


def sha256_file(path):
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


    
def load_previous_document():
    if not OUTPUT.exists():
        return {}

    try:
        with OUTPUT.open() as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def build_tracking(previous_document, current_content, document_id, now):
    previous_tracking = (
        previous_document
        .get("document", {})
        .get("tracking", {})
    )

    previous_version = previous_tracking.get("version")

    previous_content = {
        "document": {
            key: value
            for key, value in previous_document.get("document", {}).items()
            if key != "tracking"
        },
        "product_tree": previous_document.get("product_tree"),
        "vulnerabilities": previous_document.get("vulnerabilities"),
    }

    content_changed = current_content != previous_content

    initial_release_date = previous_tracking.get(
        "initial_release_date",
        now,
    )

    if not previous_version:
        revision_number = "1"
        revision_history = [
            {
                "date": now,
                "number": "1",
                "summary": "Initial release",
            }
        ]
        current_release_date = now

    elif content_changed:
        try:
            revision_number = str(int(previous_version) + 1)
        except ValueError:
            revision_number = previous_version

        revision_history = list(
            previous_tracking.get("revision_history", [])
        )

        revision_history.append(
            {
                "date": now,
                "number": revision_number,
                "summary": "Updated vulnerability analysis",
            }
        )

        current_release_date = now

    else:
        revision_number = previous_version
        revision_history = previous_tracking.get(
            "revision_history",
            [],
        )
        current_release_date = previous_tracking.get(
            "current_release_date",
            now,
        )

    return {
        "current_release_date": current_release_date,
        "id": document_id,
        "initial_release_date": initial_release_date,
        "revision_history": revision_history,
        "status": "draft",
        "version": revision_number,
    }


def apply_in_triage(entry, analysis, product_id, _):
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

    entry["remediations"] = [
        {
            "category": "mitigation",
            "details": (
                "The vulnerability is currently under investigation. "
                "No final remediation decision has been made yet."
            ),
            "product_ids": [product_id],
        }
    ]


def apply_not_affected(entry, analysis, product_id, _):
    justification = analysis.get("analysisJustification")
    details = analysis.get("analysisDetails")

    parts = []

    if justification and justification != "NOT_SET":
        parts.append(f"Justification: {justification}.")

    if details:
        parts.append(details)

    if not parts:
        parts.append("No additional analysis details available.")

    entry["threats"] = [
        {
            "category": "impact",
            "details": " ".join(parts),
            "product_ids": [product_id],
        }
    ]


def apply_exploitable(entry, analysis, product_id, vulnerability):
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
            "category": "vendor_fix",
            "details": (
                "The vulnerability is considered exploitable. "
                "A fixed version or other remediation should be applied."
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


def apply_resolved(entry, analysis, product_id, _):
    details = (
        analysis.get("analysisDetails")
        or "The vulnerability has been resolved."
    )

    entry["notes"].append(
        {
            "category": "details",
            "title": "Resolution",
            "text": details,
        }
    )

    entry["remediations"] = [
        {
            "category": "vendor_fix",
            "details": "The vulnerability has been resolved.",
            "product_ids": [product_id],
        }
    ]

STATE_HANDLERS = {
    "IN_TRIAGE": apply_in_triage,
    "NOT_AFFECTED": apply_not_affected,
    "EXPLOITABLE": apply_exploitable,
    "RESOLVED": apply_resolved,
}


def build_vulnerability_entry(finding, analysis):
    component = finding["component"]
    vulnerability = finding["vulnerability"]

    state = analysis.get("analysisState")

    if not state or state == "NOT_SET":
        print(
            f'Skipping {vulnerability["vulnId"]}: '
            "no analysis state has been assigned."
        )
        return None

    if state not in STATE_MAP:
        print(
            f'Skipping {vulnerability["vulnId"]}: '
            f"unsupported analysis state {state}."
        )
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
        raise SystemExit("No analyzed findings found.")

    first = valid_findings[0]
    project_name = first["component"]["projectName"]
    project_version = first["component"]["projectVersion"]
    product_id = f"{project_name}-{project_version}"

    if not SBOM_PATH.exists():
        raise SystemExit(f"SBOM file not found: {SBOM_PATH}")

    sbom_sha256 = sha256_file(SBOM_PATH)
    document_id = CSAF_DOCUMENT_ID or f"{project_name}-csaf-vex"

    previous_document = load_previous_document()

    document_content = build_document_content(
        project_name,
        project_version,
        product_id,
        SBOM_PATH,
        sbom_sha256,
        vulnerabilities,
    )

    tracking = build_tracking(
        previous_document,
        document_content,
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