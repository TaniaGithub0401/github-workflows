#!/usr/bin/env python3

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def find_notebooks(path):
    path = Path(path)

    if not path.exists():
        raise SystemExit(f"Notebook path does not exist: {path}")

    if path.is_file():
        notebooks = [path] if path.suffix == ".ipynb" else []
    else:
        notebooks = [
            notebook
            for notebook in path.rglob("*.ipynb")
            if ".ipynb_checkpoints" not in notebook.parts
        ]

    if not notebooks:
        raise SystemExit(f"No Jupyter notebooks found in: {path}")

    return notebooks


def convert_notebooks(path, output_dir):
    path = Path(path)
    output_dir = Path(output_dir)

    notebooks = find_notebooks(path)

    if path.is_file():
        base_path = path.parent
    else:
        base_path = path

    output_dir.mkdir(parents=True, exist_ok=True)

    for notebook in notebooks:
        relative_path = notebook.relative_to(base_path)
        notebook_output_dir = output_dir / relative_path.parent

        notebook_output_dir.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            [
                "jupyter",
                "nbconvert",
                "--to",
                "python",
                f"--output-dir={notebook_output_dir}",
                str(notebook),
            ],
            check=False,
        )

        if result.returncode != 0:
            raise SystemExit(
                f"Failed to convert notebook: {notebook}"
            )

    print(
        f"Converted {len(notebooks)} Jupyter notebook(s) "
        f"to {output_dir}."
    )


def has_outputs(notebook_path):
    with notebook_path.open(encoding="utf-8") as file:
        notebook = json.load(file)

    for cell in notebook.get("cells", []):
        if cell.get("cell_type") == "code" and cell.get("outputs"):
            return True

    return False


def check_outputs(path):
    notebooks = find_notebooks(path)
    failed = False

    for notebook in notebooks:
        if has_outputs(notebook):
            print(f"Notebook contains saved outputs: {notebook}")
            failed = True

    if failed:
        raise SystemExit(1)

    print(f"Validated outputs for {len(notebooks)} Jupyter notebook(s).")


def check_secrets(path, baseline=None):
    path = Path(path)

    if not path.exists():
        raise SystemExit(f"Scan path does not exist: {path}")

    if baseline:
        baseline = Path(baseline).resolve()

        if not baseline.exists():
            raise SystemExit(
                f"detect-secrets baseline does not exist: {baseline}"
            )

        files = [
            str(file)
            for file in path.rglob("*")
            if file.is_file()
        ]

        if not files:
            raise SystemExit(
                f"No files found to scan in: {path}"
            )

        result = subprocess.run(
            [
                "detect-secrets-hook",
                "--baseline",
                str(baseline),
                *files,
            ],
            check=False,
        )

        if result.returncode != 0:
            print(
                "Potential new secrets were detected "
                "in Jupyter notebook code."
            )
            raise SystemExit(1)

        print(
            "No new secrets detected in Jupyter notebook code."
        )
        return

    with tempfile.NamedTemporaryFile(
        mode="w+",
        suffix=".json",
    ) as result_file:
        result = subprocess.run(
            [
                "detect-secrets",
                "scan",
                "--all-files",
                ".",
            ],
            cwd=path,
            stdout=result_file,
            check=False,
        )

        if result.returncode != 0:
            raise SystemExit("detect-secrets scan failed")

        result_file.seek(0)
        results = json.load(result_file)

    secret_count = sum(
        len(findings)
        for findings in results.get("results", {}).values()
    )

    if secret_count:
        print(
            "Potential secrets were detected "
            "in Jupyter notebook code."
        )
        raise SystemExit(1)

    print(
        "No potential secrets detected "
        "in Jupyter notebook code."
    )


def check_git_history(path):
    path = Path(path)

    if not path.exists():
        raise SystemExit(f"Repository path does not exist: {path}")

    result = subprocess.run(
        [
            "betterleaks",
            "detect",
            "--source",
            str(path),
            "--redact",
        ],
        check=False,
    )

    if result.returncode != 0:
        print(
            "Potential secrets were detected "
            "in Git history."
        )
        raise SystemExit(1)

    print("No potential secrets detected in Git history.")


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit(
            "Usage: check-notebooks.py "
            "<outputs|convert|secrets|history> <path> [argument]"
        )

    mode = sys.argv[1]
    path = sys.argv[2]
    argument = sys.argv[3] if len(sys.argv) == 4 else ""

    if mode == "outputs":
        check_outputs(path)

    elif mode == "convert":
        if not argument:
            raise SystemExit(
                "Output directory is required for convert mode."
            )

        convert_notebooks(path, argument)

    elif mode == "secrets":
        check_secrets(path, argument)

    elif mode == "history":
        check_git_history(path)

    else:
        raise SystemExit(
            f"Unknown mode: {mode}. "
            "Use 'outputs', 'convert','secrets', or 'history'."
        )


if __name__ == "__main__":
    main()
