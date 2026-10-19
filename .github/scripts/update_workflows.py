import argparse
import difflib
import re
from pathlib import Path

WORKFLOWS_DIR = Path('.github/workflows')
PROJECT_NAME = '${{ github.event.repository.name }}'

SBOM_INPUTS = {
    'dependency-track': 'true',
    'dependency-track-url': '${{ vars.DEPENDENCY_TRACK_API_URL }}',
    'dependency-track-project-name': None,  # Derived from SBOM source.
    'dependency-track-project-version': '${{ github.ref_name }}',
    'csaf-publisher-name': '${{ vars.CSAF_PUBLISHER_NAME }}',
    'csaf-publisher-namespace': '${{ vars.CSAF_PUBLISHER_NAMESPACE }}',
    'email-notification': 'true',
    'email-address': '${{ vars.CYBERSECURITY_EMAIL }}',
}
SBOM_SECRETS = {
    'dependency-track-api-key': '${{ secrets.DEPENDENCY_TRACK_API_KEY }}',
    'smtp-password': '${{ secrets.CYBERSECURITY_EMAIL_APP_PASSWORD }}',
}


def section(lines, name, indent=0, start=0, end=None):
    """Return the bounds of a YAML mapping block."""
    if end is None:
        end = len(lines)
    pattern = re.compile(
        '^' + ' ' * indent + re.escape(name) + r':\s*(?:#.*)?$'
    )
    matches = [i for i in range(start, end) if pattern.fullmatch(lines[i])]
    if len(matches) != 1:
        raise ValueError(
            f'Expected one {name!r} section; found {len(matches)}'
        )
    pos = matches[0]
    boundary = next(
        (j for j in range(pos + 1, end)
         if lines[j].strip() and not lines[j].lstrip().startswith('#')
         and (len(lines[j]) - len(lines[j].lstrip(' '))) <= indent),
        end,
    )
    return pos, boundary


def mapping_values(lines, start, end, indent):
    """Find direct scalar entries in a known mapping; reject duplicate keys."""
    pattern = re.compile(r'^' + ' ' * indent + r'([\w-]+):\s*(.*)$')
    found = {}
    for i in range(start + 1, end):
        match = pattern.match(lines[i])
        if match:
            key, value = match.groups()
            if key in found:
                raise ValueError(f'Duplicate YAML key: {key}')
            found[key] = (i, value.strip())
    return found


def ensure_permissions(lines, scope, desired, indent=0, remove=()):
    """Update permissions while preserving unrelated entries."""
    start, end = scope
    prefix = ' ' * indent
    heading = prefix + 'permissions:'
    entries = [
        i for i in range(start + 1, end)
        if lines[i].startswith(heading)
        and re.fullmatch(
            r'\s*(\{\s*\})?\s*(?:#.*)?', lines[i][len(heading):]
        )
    ]
    if len(entries) > 1:
        raise ValueError('Duplicate permissions blocks')
    if not entries:
        block = [heading] + [
            prefix + '  ' + k + ': ' + v for k, v in desired.items()
        ]
        if indent == 0:
            lines[end:end] = block + ['']
        else:
            lines[start + 1:start + 1] = block
        return
    pos = entries[0]
    if re.fullmatch(r'\s*\{\s*\}\s*(?:#.*)?', lines[pos][len(heading):]):
        lines[pos:pos + 1] = [heading] + [
            prefix + '  ' + k + ': ' + v for k, v in desired.items()
        ]
        return
    next_pos = next(
        (j for j in range(pos + 1, len(lines))
         if lines[j].strip() and not lines[j].lstrip().startswith('#')
         and len(lines[j]) - len(lines[j].lstrip(' ')) <= indent),
        len(lines),
    )
    existing = mapping_values(lines, pos, next_pos, indent + 2)
    for key, value in desired.items():
        if key in existing:
            i, _ = existing[key]
            lines[i] = prefix + '  ' + key + ': ' + value
        else:
            insertion = max(
                (index for index, _ in existing.values()), default=pos
            ) + 1
            lines.insert(insertion, prefix + '  ' + key + ': ' + value)
            existing[key] = (insertion, value)
            for other, (index, old_value) in list(existing.items()):
                if other != key and index >= insertion:
                    existing[other] = (index + 1, old_value)

    if remove:
        next_pos = next(
            (
                j for j in range(pos + 1, len(lines))
                if lines[j].strip()
                and not lines[j].lstrip().startswith('#')
                and len(lines[j]) - len(lines[j].lstrip(' ')) <= indent
            ),
            len(lines),
        )

        permissions = mapping_values(
            lines, pos, next_pos, indent + 2
        )

        indices = [
            permissions[key][0]
            for key in remove
            if key in permissions
        ]

        for index in sorted(indices, reverse=True):
            del lines[index]


def update_python_publish(lines):
    lines[:] = [
        line for line in lines
        if not line.startswith(
            '# the workflow does not require permissions,'
        )
    ]

    jobs_start, _ = section(lines, 'jobs')

    ensure_permissions(
        lines,
        (-1, jobs_start),
        {'contents': 'write'},
        remove=('id-token',),
    )


def update_third_party_licenses(lines):
    jobs_start, jobs_end = section(lines, 'jobs')
    job_start, job_end = section(
        lines, 'generate-third-party-licenses', 2, jobs_start + 1, jobs_end
    )
    ensure_permissions(
        lines, (job_start, job_end), {'contents': 'write'}, indent=4
    )
    jobs_start, _ = section(lines, 'jobs')
    for i in range(jobs_start - 1, -1, -1):
        if re.fullmatch(r'permissions:\s*\{\s*\}\s*', lines[i]):
            del lines[i]
            jobs_index, _ = section(lines, 'jobs')
            while (
                jobs_index >= 2
                and not lines[jobs_index - 1].strip()
                and not lines[jobs_index - 2].strip()
            ):
                del lines[jobs_index - 1]
                jobs_index -= 1
            break


def update_sbom_scan(lines):
    jobs_start, jobs_end = section(lines, 'jobs')
    job_start, job_end = section(
        lines, 'sbom-scan', 2, jobs_start + 1, jobs_end
    )
    with_start, with_end = section(lines, 'with', 4, job_start + 1, job_end)
    inputs = mapping_values(lines, with_start, with_end, 6)
    sources = [
        key for key in ('pyproject', 'dockerfile')
        if key in inputs and inputs[key][1]
    ]
    if len(sources) != 1:
        raise ValueError(
            'SBOM workflow needs exactly one pyproject or dockerfile input'
        )
    kind = 'application' if sources[0] == 'pyproject' else 'container'
    project_name = PROJECT_NAME + '-' + kind

    existing_dtrack = [key for key in SBOM_INPUTS if key in inputs]
    if existing_dtrack:
        missing = [
            key for key in SBOM_INPUTS
            if key not in inputs or not inputs[key][1]
        ]
        if missing:
            raise ValueError(f'Incomplete Dependency-Track inputs: {missing}')
        if inputs['dependency-track'][1] != 'true':
            raise ValueError('Dependency-Track exists but is not enabled')
        print(f'  Dependency-Track already configured ({kind})')
    else:
        if 'fail-build' not in inputs:
            lines.insert(with_end, '      fail-build: false')
            with_end += 1
        for key, value in SBOM_INPUTS.items():
            if key == 'dependency-track-project-name':
                value = project_name
            lines.insert(with_end, f'      {key}: {value}')
            with_end += 1

    jobs_start, jobs_end = section(lines, 'jobs')
    job_start, job_end = section(
        lines, 'sbom-scan', 2, jobs_start + 1, jobs_end
    )
    secrets_headings = [
        i for i in range(job_start + 1, job_end)
        if lines[i].strip() == 'secrets:'
        and lines[i].startswith('    ')
    ]
    if len(secrets_headings) > 1:
        raise ValueError('Duplicate secrets blocks')
    if secrets_headings:
        secret_start = secrets_headings[0]
        secret_end = next(
            (i for i in range(secret_start + 1, job_end)
             if lines[i].strip() and not lines[i].lstrip().startswith('#')
             and len(lines[i]) - len(lines[i].lstrip(' ')) <= 4),
            job_end,
        )
        existing_secrets = mapping_values(lines, secret_start, secret_end, 6)
        missing_secrets = [
            key for key in SBOM_SECRETS
            if key not in existing_secrets or not existing_secrets[key][1]
        ]
        if existing_dtrack and missing_secrets:
            raise ValueError(
                f'Incomplete Dependency-Track secrets: {missing_secrets}'
            )
        for key in missing_secrets:
            lines.insert(secret_end, f'      {key}: {SBOM_SECRETS[key]}')
            secret_end += 1
    elif existing_dtrack:
        raise ValueError('Dependency-Track configured without secrets block')
    else:
        _, end_of_with = section(lines, 'with', 4, job_start + 1, job_end)
        lines[end_of_with:end_of_with] = ['    secrets:'] + [
            f'      {key}: {value}' for key, value in SBOM_SECRETS.items()
        ]

    jobs_start, jobs_end = section(lines, 'jobs')
    job_start, job_end = section(
        lines, 'sbom-scan', 2, jobs_start + 1, jobs_end
    )
    ensure_permissions(
        lines, (job_start, job_end),
        {
            'contents': 'write',
            'security-events': 'write',
            'actions': 'read',
        },
        4,
    )


UPDATES = {
    'python-publish.yml': update_python_publish,
    'sbom-vulnerability-scan.yml': update_sbom_scan,
    'third-party-licenses.yml': update_third_party_licenses,
}


def main(dry_run=False):
    changes = []
    for name, updater in UPDATES.items():
        path = WORKFLOWS_DIR / name
        if not path.is_file():
            print(f'Skipping {name}: not found')
            continue
        original = path.read_text(encoding='utf-8')
        lines = original.splitlines()
        updater(lines)
        updated = '\n'.join(lines).rstrip('\n') + '\n'
        if updated == original:
            print(f'No changes: {name}')
        else:
            changes.append((path, original, updated))

    for path, old, new in changes:
        if dry_run:
            diff = difflib.unified_diff(
                (old.rstrip('\n') + '\n').splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f'a/{path}',
                tofile=f'b/{path}',
            )
            print(''.join(diff), end='')
        else:
            path.write_text(new, encoding='utf-8')
            print(f'Updated: {path.name}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    main(args.dry_run)
