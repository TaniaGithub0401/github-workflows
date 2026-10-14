
from pathlib import Path
import argparse
import difflib
import re

WORKFLOWS = Path(".github/workflows")


def replace_once(content, old, new, filename):
    if old in content:
        return content.replace(old, new, 1)

    if new in content:
        print(f"  Already updated: {filename}")
        return content

    raise ValueError(f"Unexpected configuration in {filename}")


def update_python_publish(content):
    # Keep id-token: write until OIDC requirements are verified.
    return replace_once(
        content,
        "  contents: read\n  id-token: write",
        "  contents: write\n  id-token: write",
        "python-publish.yml",
    )


def update_sbom_scan(content):
    filename = "sbom-vulnerability-scan.yml"

    content = replace_once(
        content,
        "      contents: read\n      security-events: write",
        "      contents: write\n      security-events: write\n      actions: read",
        filename,
    )

    new_inputs = """      fail-build: false
      dependency-track: true
      dependency-track-url: ${{ vars.DEPENDENCY_TRACK_API_URL }}
      dependency-track-project-name: ${{ github.event.repository.name }}-application
      dependency-track-project-version: ${{ github.ref_name }}
      csaf-publisher-name: ${{ vars.CSAF_PUBLISHER_NAME }}
      csaf-publisher-namespace: ${{ vars.CSAF_PUBLISHER_NAMESPACE }}
      email-notification: true
      email-address: ${{ vars.CYBERSECURITY_EMAIL }}
    secrets:
      dependency-track-api-key: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
      smtp-password: ${{ secrets.CYBERSECURITY_EMAIL_APP_PASSWORD }}
    """

    
    if "dependency-track:" in content:
        print(f"  Dependency-Track already configured: {filename}")
        return content

    lines = content.splitlines()

    for index, line in enumerate(lines):
        if re.fullmatch(
            r"\s{6}pyproject:\s*pyproject\.toml\s*",
            line,
        ):
            lines[index] = line.rstrip()
            new_lines = new_inputs.strip("\n").splitlines()
            lines[index + 1:index + 1] = new_lines
            return "\n".join(line.rstrip() for line in lines).rstrip() + "\n"
        
    raise ValueError(
        f"pyproject configuration not found in {filename}"
    )


def update_third_party_licenses(content):
    filename = "third-party-licenses.yml"

    job = "  generate-third-party-licenses:\n"
    permission_block = (
        "    permissions:\n"
        "      contents: write\n"
    )

    if job + permission_block in content:
        print(f"  Already updated: {filename}")
        return content

    if job not in content:
        raise ValueError(f"Job not found in {filename}")

    if "permissions: { }\n" in content:
        content = content.replace(
            "permissions: { }\n\n", "", 1
        )
    elif "permissions: {}\n" in content:
        content = content.replace(
            "permissions: {}\n\n", "", 1
        )
    else:
        raise ValueError(
            f"Unexpected permissions in {filename}"
        )

    return content.replace(
        job, job + permission_block, 1
    )


UPDATES = {
    "python-publish.yml": update_python_publish,
    "sbom-vulnerability-scan.yml": update_sbom_scan,
    "third-party-licenses.yml": update_third_party_licenses,
}


def main(dry_run):
    for filename, update_function in UPDATES.items():
        path = WORKFLOWS / filename

        if not path.is_file():
            print(f"Skipping {filename}: file not found")
            continue

        original = path.read_text(encoding="utf-8")

        try:
            updated = update_function(original)
        except ValueError as error:
            print(f"ERROR: {error}")
            raise

        if original == updated:
            print(f"No changes: {filename}")
            continue

        if dry_run:
            diff = difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
            )
            print("".join(diff))
        else:
            path.write_text(updated, encoding="utf-8")
            print(f"Updated: {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(args.dry_run)
