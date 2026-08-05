#!/usr/bin/env python3

"""Deploy YARA-L rules to Google SecOps."""

import glob
import json
import os
import urllib.error
import urllib.request

INSTANCE = os.environ["CHRONICLE_INSTANCE"]


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


def deploy(path):
    with open(path, encoding="utf-8") as rule_file:
        rule_text = rule_file.read()

    url = (
        f"https://chronicle.googleapis.com/v1/"
        f"{INSTANCE}/rules?alt=json"
    )

    body = json.dumps(
        {
            "text": rule_text,
            "displayName": os.path.basename(path).replace(
                ".yaral", ""
            ),
        }
    ).encode()

    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {get_token()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            print(
                f"DEPLOYED {path}: HTTP {response.status}"
            )

    except urllib.error.HTTPError as error:
        print(
            f"FAIL {path}: {error.code} "
            f"{error.read().decode()[:500]}"
        )


if __name__ == "__main__":
    for rule in glob.glob("chronicle/rules/*.yaral"):
        deploy(rule)
