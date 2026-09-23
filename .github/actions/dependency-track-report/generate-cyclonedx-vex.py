import argparse
import json
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-uuid", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-version", required=True)
    parser.add_argument("--project-type", required=True)

    args = parser.parse_args()

    findings_path = Path(args.findings)
    output_path = Path(args.output)

    with findings_path.open() as f:
        findings = json.load(f)

    components = {}
    vulnerabilities = []

    for finding in findings:
        component = finding["component"]
        vulnerability = finding["vulnerability"]
        analysis = finding.get("analysis", {})

        # Do not overwrite an existing manual or previous analysis state.
        if analysis.get("state") or analysis.get("isSuppressed"):
            continue

        component_uuid = component["uuid"]

        component_data = {
            "type": "library",
            "bom-ref": component_uuid,
            "name": component["name"],
            "version": component["version"],
        }

        if component.get("purl"):
            component_data["purl"] = component["purl"]

        components[component_uuid] = component_data

        vulnerabilities.append({
            "id": vulnerability["vulnId"],
            "source": {
                "name": vulnerability["source"],
            },
            "analysis": {
                "state": "in_triage",
            },
            "affects": [
                {
                    "ref": component_uuid,
                }
            ],
        })

    if not vulnerabilities:
        output_path.unlink(missing_ok=True)
        return

    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": args.project_type,
                "bom-ref": args.project_uuid,
                "name": args.project_name,
                "version": args.project_version,
            }
        },
        "components": list(components.values()),
        "vulnerabilities": vulnerabilities,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w") as f:
        json.dump(vex, f, indent=2)


if __name__ == "__main__":
    main()
