import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path


def get_required_env(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is not set")
    return value


def main():
    smtp_server = get_required_env("SMTP_SERVER")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_username = get_required_env("SMTP_USERNAME")
    smtp_password = get_required_env("SMTP_PASSWORD")
    project_name = os.environ.get("PROJECT_NAME", "Unknown project")
    new_count = int(os.environ.get("NEW_COUNT", "0"))
    state_change_count = int(
        os.environ.get("STATE_CHANGE_COUNT", "0")
    )
    email_from = get_required_env("EMAIL_FROM")
    email_to = get_required_env("EMAIL_TO")

    csaf_file = Path(
        os.environ.get("CSAF_FILE", "/tmp/csaf-vex.json")
    )

    if not csaf_file.is_file():
        raise SystemExit("CSAF report does not exist.")

    message = EmailMessage()
    message["From"] = email_from
    message["To"] = email_to

    if new_count > 0 and state_change_count > 0:
        subject = f"[{project_name}] Vulnerability report updated"
    elif new_count > 0:
        subject = f"[{project_name}] New vulnerabilities detected"
    else:
        subject = f"[{project_name}] Vulnerability status updated"

    message["Subject"] = subject

    body_lines = []

    if new_count > 0:
        body_lines.append(
            f"{new_count} new vulnerabilit"
            f"{'y was' if new_count == 1 else 'ies were'} "
            f"detected for {project_name}."
        )

    if state_change_count > 0:
        body_lines.append(
            f"The analysis {'state' if state_change_count == 1 else 'states'} "
            f"of {state_change_count} "
            f"{'vulnerability was' if state_change_count == 1 else 'vulnerabilities were'} "
            "updated."
        )
    body_lines.append("")
    body_lines.append(
        "The updated CSAF vulnerability report is attached."
    )

    message.set_content("\n".join(body_lines))
    message.add_attachment(
        csaf_file.read_bytes(),
        maintype="application",
        subtype="json",
        filename=csaf_file.name,
    )

    context = ssl.create_default_context()

    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as smtp:
        smtp.starttls(context=context)
        smtp.login(smtp_username, smtp_password)
        smtp.send_message(message)

    print("CSAF email notification sent successfully.")


if __name__ == "__main__":
    main()
