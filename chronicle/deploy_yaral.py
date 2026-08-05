#!/usr/bin/env python3
"""Deploy YARA-L rules to Google SecOps (Chronicle).

Required environment:
    CHRONICLE_INSTANCE
    GOOGLE_APPLICATION_CREDENTIALS

Example:
    export CHRONICLE_INSTANCE="projects/PROJECT/locations/us/instances/INSTANCE"
    export GOOGLE_APPLICATION_CREDENTIALS="$HOME/chronicle-sa.json"
    python3 chronicle/deploy_yaral.py
"""

import glob
import json
import os
import urllib.error
import urllib.request

INSTANCE = os.environ.get("CHRONICLE_INSTANCE")


def get_token():
    import google.auth
    import google.auth.transport.requests

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

    credentials.refresh(
        google.auth.transport.requests.Request()
    )

    return credentials.token


def deploy(path, token):
    filename = os.path.basename(path)
    display_name = filename.removesuffix(".yaral")

    url = (
        f"https://chronicle.googleapis.com/v1/"
        f"{INSTANCE}/rules?alt=json"
    )

    with open(path, encoding="utf-8") as handle:
        rule_text = handle.read()

    body = json.dumps(
        {
            "text": rule_text,
            "displayName": display_name,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            print(f"DEPLOYED {path}: HTTP {response.status}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        print(f"FAILED {path}: HTTP {error.code} {detail[:500]}")
    except urllib.error.URLError as error:
        print(f"FAILED {path}: {error}")


def main():
    if not INSTANCE:
        raise SystemExit(
            "ERROR: CHRONICLE_INSTANCE environment variable is required."
        )

    files = sorted(glob.glob("chronicle/rules/*.yaral"))

    if not files:
        raise SystemExit("ERROR: No .yaral files found.")

    token = get_token()

    for path in files:
        deploy(path, token)


if __name__ == "__main__":
    main()
