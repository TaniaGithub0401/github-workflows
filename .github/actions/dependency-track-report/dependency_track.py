from datetime import datetime, timezone
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


DTRACK_URL = os.environ.get(
    "DTRACK_URL",
    "http://localhost:8080",
)

DTRACK_API_KEY = os.environ.get("DTRACK_API_KEY")
NOTIFICATION_PROPERTY_GROUP = "mundialis"
NOTIFICATION_PROPERTY_NAME = "last-csaf-notification-time"
DTRACK_FINDINGS_FILE = os.environ.get(
    "DTRACK_FINDINGS_FILE",
    "/tmp/dtrack-findings.json",
)

DTRACK_PROJECT_UUID = os.environ.get("DTRACK_PROJECT_UUID")

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

    max_attempts = 5

    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(
                request,
                timeout=15,
            ) as response:
                return json.load(response)

        except urllib.error.HTTPError as error:
            if error.code == 404 and attempt < max_attempts:
                time.sleep(2)
                continue

            print(
                "Warning: Dependency-Track analysis "
                f"request failed with HTTP {error.code}."
            )
            return {}

        except urllib.error.URLError:
            print(
                "Warning: Could not reach Dependency-Track."
            )
            return {}

    return {}


def get_project_properties(project_uuid):
    url = f"{DTRACK_URL}/api/v1/project/{project_uuid}/property"

    request = urllib.request.Request(
        url,
        headers={
            "X-Api-Key": DTRACK_API_KEY,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        print(
            "Warning: Dependency-Track project properties "
            f"request failed with HTTP {error.code}."
        )
        return []
    except urllib.error.URLError:
        print("Warning: Could not reach Dependency-Track.")
        return []


def get_last_notification_time(project_uuid):
    properties = get_project_properties(project_uuid)

    for prop in properties:
        if (
            prop.get("groupName") == NOTIFICATION_PROPERTY_GROUP
            and prop.get("propertyName") == NOTIFICATION_PROPERTY_NAME
        ):
            value = prop.get("propertyValue")

            if not value:
                return None

            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

    return None


def set_last_notification_time(project_uuid, timestamp_ms):
    properties = get_project_properties(project_uuid)

    property_exists = any(
        prop.get("groupName") == NOTIFICATION_PROPERTY_GROUP
        and prop.get("propertyName") == NOTIFICATION_PROPERTY_NAME
        for prop in properties
    )

    timestamp = datetime.fromtimestamp(
        timestamp_ms / 1000,
        tz=timezone.utc,
    ).isoformat().replace("+00:00", "Z")

    payload = json.dumps(
        {
            "groupName": NOTIFICATION_PROPERTY_GROUP,
            "propertyName": NOTIFICATION_PROPERTY_NAME,
            "propertyValue": timestamp,
            "propertyType": "TIMESTAMP",
        }
    ).encode()

    url = f"{DTRACK_URL}/api/v1/project/{project_uuid}/property"

    request = urllib.request.Request(
        url,
        data=payload,
        method="POST" if property_exists else "PUT",
        headers={
            "X-Api-Key": DTRACK_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=15):
            return True
    except urllib.error.HTTPError as error:
        print(
            "Warning: Dependency-Track notification timestamp "
            f"update failed with HTTP {error.code}."
        )
        return False
    except urllib.error.URLError:
        print("Warning: Could not reach Dependency-Track.")
        return False


def get_notification_events(findings, since_time):
    events = []

    for finding in findings:
        analysis = get_analysis(finding)

        for entry in analysis.get("analysisComments", []):
            timestamp_ms = entry.get("timestamp")
            comment = entry.get("comment", "")

            if not timestamp_ms:
                continue

            if not comment.startswith("Analysis: "):
                continue

            event_time = datetime.fromtimestamp(
                timestamp_ms / 1000,
                tz=timezone.utc,
            )

            if since_time and event_time <= since_time:
                continue

            transition = comment.removeprefix("Analysis: ")

            if " → " not in transition:
                continue

            previous_state, current_state = transition.split(" → ", 1)

            if (
                previous_state == "NOT_SET"
                and current_state == "IN_TRIAGE"
                and entry.get("commenter") == "CycloneDX VEX"
            ):
                event_type = "new"
            else:
                event_type = "state_change"

            events.append(
                {
                    "type": event_type,
                    "timestamp": timestamp_ms,
                    "previous_state": previous_state,
                    "current_state": current_state,
                }
            )

    return events


def initialize_notification_time(project_uuid, findings):
    latest_timestamp = None

    for finding in findings:
        analysis = get_analysis(finding)

        for entry in analysis.get("analysisComments", []):
            timestamp = entry.get("timestamp")

            if not timestamp:
                continue

            if latest_timestamp is None or timestamp > latest_timestamp:
                latest_timestamp = timestamp

    if latest_timestamp is None:
        return False

    return set_last_notification_time(
        project_uuid,
        latest_timestamp,
    )


def get_notification_status(project_uuid, findings):
    last_notification_time = get_last_notification_time(project_uuid)

    if last_notification_time is None:
        initialized = initialize_notification_time(
            project_uuid,
            findings,
        )

        return {
            "send_email": False,
            "baseline_initialized": initialized,
            "new_count": 0,
            "state_change_count": 0,
            "latest_event_timestamp": None,
        }

    events = get_notification_events(
        findings,
        last_notification_time,
    )

    if not events:
        return {
            "send_email": False,
            "baseline_initialized": False,
            "new_count": 0,
            "state_change_count": 0,
            "latest_event_timestamp": None,
        }

    new_count = sum(
        1 for event in events
        if event["type"] == "new"
    )

    state_change_count = sum(
        1 for event in events
        if event["type"] == "state_change"
    )

    latest_event_timestamp = max(
        event["timestamp"]
        for event in events
    )

    return {
        "send_email": True,
        "baseline_initialized": False,
        "new_count": new_count,
        "state_change_count": state_change_count,
        "latest_event_timestamp": latest_event_timestamp,
    }

if __name__ == "__main__":
    validate_config()

    if not DTRACK_PROJECT_UUID:
        raise SystemExit("DTRACK_PROJECT_UUID is not set")

    with open(DTRACK_FINDINGS_FILE) as file:
        findings = json.load(file)

    status = get_notification_status(
        DTRACK_PROJECT_UUID,
        findings,
    )

    print(json.dumps(status))