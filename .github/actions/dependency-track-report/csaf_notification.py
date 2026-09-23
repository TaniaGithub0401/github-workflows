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
    message["Subject"] = f"[{project_name}] CSAF vulnerability report"

    message.set_content(
        "A new or updated CSAF vulnerability report was generated.\n\n"
        "The CSAF report is attached to this email."
    )

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
