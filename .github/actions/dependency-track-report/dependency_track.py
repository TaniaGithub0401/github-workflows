import json
import os
import urllib.error
import urllib.parse
import urllib.request


DTRACK_URL = os.environ.get(
    "DTRACK_URL",
    "http://localhost:8080",
)

DTRACK_API_KEY = os.environ.get("DTRACK_API_KEY")


def validate_config():
    if not DTRACK_API_KEY:
        raise SystemExit("DTRACK_API_KEY is not set")


def get_analysis(finding):
    component = finding["component"]
    vulnerability = finding["vulnerability"]

    params = urllib.parse.urlencode(
        {
            "project": component["project"],
            "component": component["uuid"],
            "vulnerability": vulnerability["uuid"],
        }
    )

    url = f"{DTRACK_URL}/api/v1/analysis?{params}"

    request = urllib.request.Request(
        url,
        headers={
            "X-Api-Key": DTRACK_API_KEY,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=15,
        ) as response:
            return json.load(response)

    except urllib.error.HTTPError as error:
        print(
            f"Warning: Dependency-Track returned HTTP "
            f"{error.code} for "
            f'{vulnerability.get("vulnId", "unknown")}.'
        )

    except urllib.error.URLError as error:
        print(
            f"Warning: Could not reach Dependency-Track for "
            f'{vulnerability.get("vulnId", "unknown")}: '
            f"{error.reason}"
        )

    return {}