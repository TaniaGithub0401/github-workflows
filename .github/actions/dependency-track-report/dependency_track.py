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
ANALYSIS_COMMENT_PREFIX = "Analysis: "
ANALYSIS_TRANSITION_SEPARATOR = " → "
INITIAL_ANALYSIS_STATE = "NOT_SET"
TRIAGE_ANALYSIS_STATE = "IN_TRIAGE"
CYCLONEDX_VEX_COMMENTER = "CycloneDX VEX"

DTRACK_FINDINGS_FILE = os.environ.get(
    "DTRACK_FINDINGS_FILE",
    "/tmp/dtrack-findings.json",
)

DTRACK_PROJECT_UUID = os.environ.get("DTRACK_PROJECT_UUID")
NOTIFICATION_ACTION = os.environ.get(
    "NOTIFICATION_ACTION",
    "status",
)

LATEST_EVENT_TIMESTAMP = os.environ.get(
    "LATEST_EVENT_TIMESTAMP"
)

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

            raise SystemExit(
                "Dependency-Track analysis request failed "
                f"with HTTP {error.code}."
            ) from error

        except urllib.error.URLError as error:
            raise SystemExit(
                "Could not reach Dependency-Track."
            ) from error


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
        raise SystemExit(
            "Dependency-Track project properties request failed "
            f"with HTTP {error.code}."
        ) from error

    except urllib.error.URLError as error:
        raise SystemExit(
            "Could not reach Dependency-Track."
        ) from error


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


def set_notification_property(
    project_uuid,
    timestamp,
    property_exists,
):
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
            pass
    except urllib.error.HTTPError as error:
        raise SystemExit(
            "Dependency-Track notification property update failed "
            f"with HTTP {error.code}."
        ) from error
    except urllib.error.URLError as error:
        raise SystemExit(
            "Could not reach Dependency-Track."
        ) from error
    

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

    set_notification_property(
        project_uuid,
        timestamp,
        property_exists,
    )


def initialize_notification_baseline(project_uuid):
    properties = get_project_properties(project_uuid)

    property_exists = any(
        prop.get("groupName") == NOTIFICATION_PROPERTY_GROUP
        and prop.get("propertyName") == NOTIFICATION_PROPERTY_NAME
        for prop in properties
    )

    if property_exists:
        return False

    current_time = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    set_notification_property(
        project_uuid,
        current_time,
        property_exists=False,
    )

    return True


def get_notification_events(findings, since_time):
    events = []

    for finding in findings:
        analysis = get_analysis(finding)

        for entry in analysis.get("analysisComments", []):
            timestamp_ms = entry.get("timestamp")
            comment = entry.get("comment", "")

            if not timestamp_ms:
                continue

            if not comment.startswith(ANALYSIS_COMMENT_PREFIX):
                continue

            event_time = datetime.fromtimestamp(
                timestamp_ms / 1000,
                tz=timezone.utc,
            )

            if since_time and event_time <= since_time:
                continue

            transition = comment.removeprefix(
                ANALYSIS_COMMENT_PREFIX
            )

            if ANALYSIS_TRANSITION_SEPARATOR not in transition:
                continue

            previous_state, current_state = transition.split(
                ANALYSIS_TRANSITION_SEPARATOR,
                1,
            )

            if (
                previous_state == INITIAL_ANALYSIS_STATE
                and current_state == TRIAGE_ANALYSIS_STATE
                and entry.get("commenter") == CYCLONEDX_VEX_COMMENTER
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


def get_notification_status(project_uuid, findings):
    last_notification_time = get_last_notification_time(project_uuid)

    if last_notification_time is None:
        return {
            "send_email": False,
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
        "new_count": new_count,
        "state_change_count": state_change_count,
        "latest_event_timestamp": latest_event_timestamp,
    }

if __name__ == "__main__":
    validate_config()

    if not DTRACK_PROJECT_UUID:
        raise SystemExit("DTRACK_PROJECT_UUID is not set")

    if NOTIFICATION_ACTION == "status":
        with open(DTRACK_FINDINGS_FILE) as file:
            findings = json.load(file)

        status = get_notification_status(
            DTRACK_PROJECT_UUID,
            findings,
        )

        print(json.dumps(status))

    elif NOTIFICATION_ACTION == "update":
        if not LATEST_EVENT_TIMESTAMP:
            raise SystemExit(
                "LATEST_EVENT_TIMESTAMP is not set"
            )

        set_last_notification_time(
            DTRACK_PROJECT_UUID,
            int(LATEST_EVENT_TIMESTAMP),
        )

        print("CSAF notification timestamp updated.")

    elif NOTIFICATION_ACTION == "initialize":
        initialized = initialize_notification_baseline(
            DTRACK_PROJECT_UUID,
        )

        if initialized:
            print("CSAF notification baseline initialized.")
        else:
            print("CSAF notification baseline already exists.")

    else:
        raise SystemExit(
            f"Unknown NOTIFICATION_ACTION: {NOTIFICATION_ACTION}"
        )
