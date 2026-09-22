# workflows

## (Python) Linting

The python3 linting workflow uses `black`, `flake8`, `pylint`, `ruff` and `super-linter` to check the
code quality.

You can use it e.g. like this:

```yaml
name: Linting and code quality check

on:
  push:
    branches:
      - main
      - develop
  pull_request:

jobs:
  lint:
    uses: mundialis/github-workflows/.github/workflows/linting.yml@main
    with:
      pylint-version: '2.17.4'
      VALIDATE_JAVASCRIPT_STANDARD: false
      BASH_SEVERITY: 'warning'
    # the workflow requires permissions that need to be granted by the parent job:
    permissions:
      contents: read
      packages: read
      # To report GitHub Actions status checks
      statuses: write

```

or use e.g. `      pylint-version: ''` to skip checks with pylint. (If one of 
the versions is set to an empty string the code quality check will be skipped.)

Examples how `flake8`, `pylint`, `markdownlint`, `shellcheck` and `ruff` can be 
configured are in the [linting-config-examples](linting-config-examples)
folder. The `pylint` and `ruff` configuration files do not need to be created if
they are not to be customized, since they will be copied by the workflow if they
do not exists, although an additional `ruff.toml` file will be merged.
See [linting-config-examples](linting-config-examples/README.md) for more
details on how to configure the individual linters.

To exclude files (files, folders or patterns) to be linted with super linter completely
(e.g. to exclude specific files from JSON linting via super-linter)
add them to the `linting.yml` in the repo where the workflow is used, e.g.:

```yaml
jobs:
  lint:
    uses: mundialis/github-workflows/.github/workflows/linting.yml@main
    with:
      SUPER_LINTER_FILTER_REGEX_EXCLUDE: ".*processing/templates/template_MAIN_loop.json"
```

Attention: This skips the whole file to be linted with super-linter!
 -> all-or-nothing per file
To exlude python files, use the dedicated exclude configs (e.g. `.flake8`).

Always prefer to exlude more specific rules instead of a whole file
as explained in the [linting-config-example](https://github.com/mundialis/github-workflows/tree/main/linting-config-examples#superlinter)


### (Python) Linting - reviewdog

For `ruff` and `black` linting, another workflow can propose suggestions to a pull request.
For this the additional file `post-pr-reviews.yml` has to be created e.g. like this:

```yaml
name: Post PR code suggestions

on:
  workflow_run:
    workflows: ["Linting and code quality check"]
    types:
      - completed

jobs:
  post-pr-reviews:
    uses: mundialis/github-workflows/.github/workflows/post-pr-reviews.yml@main
    # the workflow requires permissions that need to be granted by the parent job:
    permissions:
      pull-requests: write
```

It needs to be in the `main` branch to become active.
Code suggestions are only made for ruff and black if they are fixable by these tools.
Also suggestions can only be added near to lines changed in the PR.


## GRASS GIS addon tests

The GRASS GIS addon tests can be added to a repo with one GRASS GIS test.

The workflow downloads the NC sample location if the workflow is configured using `with`
`NC_TEST_DATA: 'NC'`.

You can use it e.g. like this:

```yaml
name: Run tests for GRASS GIS addons
on:
  push:
    branches: [ main ]
  pull_request:
    # The branches below must be a subset of the branches above
    branches: [ main ]

# the workflow does not require permissions, but to avoid a code security warning this should be explicitly defined:
permissions: {}

jobs:
  tests:
    uses: mundialis/github-workflows/.github/workflows/grass-tests.yml@main
    # set NC_TEST_DATA to 'NC' for using NC GRASS GIS sample location
    # with:
    #   NC_TEST_DATA: 'NC'
```

## GRASS GIS addon manual

The GRASS GIS addon (and multi addon) manual workflow can be added to a repo
with a GRASS GIS addon inside to create the addon manual and pubish the manual
to GitHub Pages.

You can use it e.g. like this:

```yaml
on:
  push:
    branches: [ main ]

jobs:
  grass-manual:
    uses: mundialis/github-workflows/.github/workflows/grass-manual.yml@main
    # the workflow requires permissions that need to be granted by the parent job:
    permissions:
      contents: read
      pages: write
      id-token: write
```

Attention: you have to activate GitHub Pages for the repository (see
[here](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site#publishing-from-a-branch))

After the GitHub Page is created you can go to the repo and click on the Settings next to "About" and check there "Use your GitHub Pages website". The GitHub Pages will appear under the description of the repo.

## Python Publishing

The python publish workflow creates a wheel and uploads it to release assets.
Also the python package is published on PyPI or test PyPI.

To use this workflow in the repo the **secrets** `TEST_PYPI_API_TOKEN` or
`PYPI_API_TOKEN` have to be set. Additional, you have to check under `Settings > Actions > General > Workflow permissions` the `Read and write permissions`.

For publishing on test PyPI use e.g.:

```yaml
name: Upload Python Package to test PyPI

on:
  release:
    types: [published]

# the workflow does not require permissions, but to avoid a code security warning this should be explicitly defined:
permissions: {}

jobs:
  publish-python:
    uses: mundialis/github-workflows/.github/workflows/python-publish.yml@main
    with:
      test_pypi: true
    secrets:
      PYPI_PASSWORD: ${{ secrets.TEST_PYPI_API_TOKEN }}
```

For publishing on PyPI use e.g.:

```yaml
name: Upload Python Package to PyPI

on:
  release:
    types: [published]

# the workflow does not require permissions, but to avoid a code security warning this should be explicitly defined:
permissions: {}

jobs:
  publish-python:
    uses: mundialis/github-workflows/.github/workflows/python-publish.yml@main
    secrets:
      PYPI_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
```
## CodeQL Code Scan

The CodeQL Code Scan scans the codebase for vulnerabilities. Supported
languages are python, C and github workflow files.
The vulnerability results are uploaded to GitHub Code Scanning at category "/language:${{matrix.language}}".

You can use it e.g. like this:

```yaml
name: CodeQL Code Scan

on:
  push:
    branches: [ "main" ]
  schedule:
    # Check every Monday at 04:36
    - cron: "36 04 * * 1"

jobs:
  codeql:
    uses: mundialis/github-workflows/.github/workflows/codeql.yml@main
    # the workflow requires permissions that need to be granted by the parent job:
    permissions:
      # required for all workflows
      security-events: write

      # required to fetch internal or private CodeQL packs
      packages: read

      # only required for workflows in private repositories
      actions: read
      contents: read

```

## SBOM Vulnerability Scan

The SBOM vulnerability scan workflow generates a CycloneDX SBOM and scans
dependencies for known vulnerabilities with Grype. The workflow can be used
with a Dockerfile, a `requirements.txt` file, or a `pyproject.toml` file.

For Docker-based projects, Grype scans the SBOM generated from the Docker image.
For Python projects, a virtual environment is created from either
`requirements.txt` or `pyproject.toml`. Grype scans the virtual environment
directly because this provides valid SARIF artifact locations for GitHub Code
Scanning.

The vulnerability results are uploaded to GitHub Code Scanning using the
categories `grype-docker` or `grype-python`.

Optionally, the generated SBOM can also be uploaded to Dependency-Track.
When Dependency-Track integration is enabled, new findings without an existing
analysis state are documented as `IN_TRIAGE` using CycloneDX VEX. Existing
manual or previous analysis states are preserved.

Based on the Dependency-Track analysis states, the workflow also generates a
CSAF 2.0 VEX document. The generated CSAF document is validated automatically.
If no findings are reported, or no findings contain an analysis state that can
be included in the CSAF document, CSAF generation and validation are skipped.

You can use it e.g. like this:

```yaml
name: SBOM Vulnerability Scan

on:
  push:
    branches: [ "main" ]
  schedule:
    # Check every Monday at 04:36
    - cron: "36 04 * * 1"
  release:
    types: [published]

jobs:
  sbom-scan:
    permissions:
      contents: read
      security-events: write

    uses: mundialis/github-workflows/.github/workflows/sbom-vulnerability-scan.yml@main
    with:
      dockerfile: docker/actinia-core-alpine/Dockerfile
      # requirements: requirements.txt
      # pyproject: pyproject.toml
      # additional-packages: "libgdal-dev gdal-bin build-essential"


      fail-build: false

      dependency-track: true
      dependency-track-url: https://dependency-track.example.com
      dependency-track-project-name: example-project
      dependency-track-project-version: latest

    secrets:
      dependency-track-api-key: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
```

Provide exactly one of the following inputs:

- `dockerfile`: Path to the Dockerfile.
- `requirements`: Path to the `requirements.txt` file.
- `pyproject`: Path to the `pyproject.toml` file.


The calling job requires the following permissions:

- `contents: read` to check out the repository.
- `security-events: write` to upload the vulnerability results to GitHub Code Scanning.

Optional inputs:
- `fetch_depth`: Number of commits to fetch during checkout. Use `0` to fetch the full history and tags. Default: `1`.
- `fail-build`: Set to `true` if the workflow should fail when vulnerabilities above the severity cutoff are found. Default: `false`.
- `additional-packages`: Space-separated list of additional system packages
  to install before creating a Python environment.
- `dependency-track`: Enable Dependency-Track integration. Default: `false`.
- `dependency-track-url`: Dependency-Track base URL. Required when `dependency-track` is enabled.
- `dependency-track-project-name`: Project name used in Dependency-Track. Required when
  `dependency-track` is enabled.
- `dependency-track-project-version`: Project version used in Dependency-Track. Default: `latest`.

When Dependency-Track integration is enabled, the secret `dependency-track-api-key` must also
be provided by the calling workflow.

The generated Docker or Python SBOM is uploaded as a workflow artifact.

The generated CSAF VEX document is currently generated and validated within the
workflow and is not uploaded as a workflow artifact.

The vulnerability results are available under **Security and quality** → **Code scanning**.

## Generate Third-Party-License list on release

The workflow generates a json file with third-party-licenses as release asset.
The workflow can be used with a `Dockerfile`, a `requirements.txt` file, or a `pyproject.toml` file.

You can use it e.g. like this:
```yaml
name: Generate Third-Party Licenses

on:
  release:
    types: [published]

# the workflow does not require permissions, but to avoid a code security warning this should be explicitly defined:
permissions: {}

jobs:
  generate-third-party-licenses:
    uses: mundialis/github-workflows/.github/workflows/third-party-licenses.yml@main
    with:
      # dockerfile: docker/actinia-core-alpine/Dockerfile
      requirements: requirements.txt
      # pyproject: pyproject.toml
      # additional-packages: "libgdal-dev gdal-bin build-essential"
```

Provide exactly one of the following inputs:

- `dockerfile`: Path to the Dockerfile.
- `requirements`: Path to the requirements.txt file.
- `pyproject`: Path to the pyproject.toml file.

Additional packages can be installed e.g. for gdal see example. In the
requirements.txt the gdal version not not be set to a fixed version, because
the system version of GDAL is used.

The workflow contains two jobs:
1. `generate`: The generation of the THIRD_PARTY_LICENSES.json file
2. `license-scan`: A scan of the file where warnings will be given when a
license contains:
  * "unknown": this should be fixed if possible, you can use following commands
  to update the THIRD_PARTY_LICENSES.json
    ```bash
    # list all releases
    gh release list
    VERSION="0.0.0"
    # view assets from release
    gh release view ${VERSION}
    # download assets
    gh release download ${VERSION}
    # TODO adjust THIRD_PARTY_LICENSES.json
    # delete old THIRD_PARTY_LICENSES.json from release
    gh release delete-asset ${VERSION} THIRD_PARTY_LICENSES.json
    # upload adjusted THIRD_PARTY_LICENSES.json to release
    gh release upload ${VERSION} THIRD_PARTY_LICENSES.json
    ```
  * OR "GLP/AGPL/LPGL": these versions need to be checked for
  compability with the other licenses, see:
    * [Wiki licenses overview](https://en.wikipedia.org/wiki/Comparison_of_free_and_open-source_software_licenses#Approvals)
    * [compatibility-checker](https://joinup.ec.europa.eu/collection/eupl/solution/joinup-licensing-assistant/jla-compatibility-checker)

# pre-commit
## Python Linting

The python3 linting pre-commit hook uses `black`, `flake8`, `pylint`
and `ruff` to check the code quality.

You can use it by adding a `.pre-commit-config.yml` file to the repo containing e.g.:

```yaml
repos:
-   repo: https://github.com/mundialis/github-workflows
    rev: 1.4.0
    hooks:
    -   id: linting
```

**Note**: Might need to adapt/update the release tag of repo within `pre-commit-config.yml`

An extended example can be found at [.pre-commit-example-config.yml](.pre-commit-example-config.yml)

It might take a while initially because the Dockerfile is build, after that cache is used.
To enable pre-commit, run

```
pip install pre-commit
pre-commit install
```

Then the code is linted before every commit.

To test the hooks without commits, you can run

```
pre-commit run -a
```

As configuration is reused from github workflows, a linting workflow using above reusable
workflow must exist at `.github/workflows/linting.yml`. It is configurable:

- Linter versions:
  - Default versions specified in github-workflows/.github/workflows/linting.yml are used.
  - If overwritten in workflow which uses this workflow, only '' is supported for now
    to skip this linter.
  - Overwriting the version is not supported yet, the default version
    will still be used due to permission errors.
- Linter config files:
  - Files in code repository will be used.
  - If no config file in code repository exists, will be downloaded from github-workflows
    from main branch (same behaviour as in workflow)

In general what happens during pre-commit is that the Dockerfile of this repository is build
while having access to all files in this repository - if needed later, they need to be copied.
The linting.sh is then executed with the code repository mounted, so all files of that
repository are accessible only during runtime of the docker container.

When the linting config files do not exist in your repository because no general adjustments
are necessary, the default configs are downloaded. To avoid duplicate downloads and to be
able to lint locally, they are kept and it makes sense to add them to the `.gitignore` file.
So if .pylintrc and .pylintrc_allowed_to_fail already exist, do nothing, else add them to
`.gitignore`. Also add some temporary config files for ruff to `.gitignore` like so:

```
.pylintrc
.pylintrc_allowed_to_fail
ruff-github-workflows.toml
ruff-merged.toml
```

Once in a while you can remove them manually to be in sync with the github-workflows default configs.

It is also recommended to add a `renovate.json` config with pre-commit enabled to your repository:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended"
  ],
  "pre-commit": {
    "enabled": true
  }
}
```

### Development

To develop the pre-commit hook locally, cd into a code repository where you want to use it and run

```bash
pre-commit try-repo ../../github-workflows linting -a --verbose
```

If you want to start a container to debug the executed file, check last build docker image and run

```bash
docker run --rm -it --entrypoint sh -v $PWD:/src:rw,Z pre-commit-33a9cd78e77e8963da808aa71baf0b54
```

## Local linting


For quick local linting with the same flags as the linters use in the workflow and pre-commit,
you can add this snippet to your `~/.bashrc`:

Requirements:
- `pip install toml-union`
- have a local checkout of this repo at `~/repos/github-workflows` (or adjust below)

```bash
flake8() {
    if [ -z "$1" ]
    then
        LINT_TARGET=.
    else
        LINT_TARGET=$1
    fi

    /home/`whoami`/.local/bin/flake8 --count --statistics --show-source --jobs=4 $LINT_TARGET
}

alias black="black --check --diff --line-length 79 ."
alias pylint="pylint ."

ruff () {
    wget --continue https://raw.githubusercontent.com/mundialis/github-workflows/refs/heads/main/linting-config-examples/ruff.toml -O /tmp/ruff.toml -q
    toml-union ruff.toml /tmp/ruff.toml -o ruff-merged.toml
    /home/`whoami`/.local/bin/ruff check --config ruff-merged.toml --output-format=concise . --preview --unsafe-fixes
}

lint() {
    echo "Which Tool?"
    select tool in flake8 pylint black ruff
    do
        echo "Linting with $tool..."
        case $tool in
          flake8)
            flake8
            break
            ;;
          pylint)
            pylint
            break
            ;;
          black)
            black
            break
            ;;
          ruff)
            ruff
            break
            ;;
        esac
    done
}
```

Example usage:
```bash
17:49 $ lint
Which Tool?
1) flake8
2) pylint
3) black
4) ruff
#? 3
Linting with black...
All done! ✨ 🍰 ✨
208 files would be left unchanged.
```
