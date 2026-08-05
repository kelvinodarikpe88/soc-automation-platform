#!/usr/bin/env python3
"""Microsoft Graph + Defender response actions for SOAR.

Required environment variables:
    GRAPH_TENANT
    GRAPH_CLIENT_ID
    GRAPH_CLIENT_SECRET
"""

import argparse
import json
import os
import urllib.error
import urllib.request
import urllib.parse

TENANT = os.environ["GRAPH_TENANT"]
CLIENT_ID = os.environ["GRAPH_CLIENT_ID"]
SECRET = os.environ["GRAPH_CLIENT_SECRET"]

TOKEN_URL = (
    f"https://login.microsoftonline.com/{TENANT}"
    "/oauth2/v2.0/token"
)


def get_token():
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
            "scope": "https://graph.microsoft.com/.default",
        }
    ).encode()

    request = urllib.request.Request(
        TOKEN_URL,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())["access_token"]


def graph(method, path, body=None):
    request = urllib.request.Request(
        f"https://graph.microsoft.com/v1.0{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {get_token()}",
            "Content-Type": "application/json",
        },
        method=method,
    )

    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"{}")

    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()[:1000]


def disable_user(user_id):
    return graph(
        "PATCH",
        f"/users/{urllib.parse.quote(user_id)}",
        {"accountEnabled": False},
    )


def enable_user(user_id):
    return graph(
        "PATCH",
        f"/users/{urllib.parse.quote(user_id)}",
        {"accountEnabled": True},
    )


def revoke_sessions(user_id):
    return graph(
        "POST",
        f"/users/{urllib.parse.quote(user_id)}/revokeSignInSessions",
    )


def get_user_risk(user_id):
    safe_user = user_id.replace("'", "''")

    return graph(
        "GET",
        "/identityProtection/riskyUsers"
        f"?$filter=userPrincipalName eq '{safe_user}'",
    )


def list_signins(user_id, hours=24):
    # Microsoft Graph requires an actual ISO-8601 timestamp.
    from datetime import datetime, timedelta, timezone

    since = (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    safe_user = user_id.replace("'", "''")

    path = (
        "/auditLogs/signIns"
        f"?$filter=userPrincipalName eq '{safe_user}'"
        f" and createdDateTime ge {since}"
    )

    return graph("GET", path)


def block_named_location(name, ips):
    return graph(
        "POST",
        "/identity/conditionalAccess/namedLocations",
        {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": name,
            "isTrusted": False,
            "ipRanges": [
                {
                    "@odata.type": "#microsoft.graph.iPv4CidrRange",
                    "cidrAddress": ip,
                }
                for ip in ips
            ],
        },
    )


def _defender_post(path, body):
    request = urllib.request.Request(
        path,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {get_token()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"{}")

    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()[:1000]


def add_defender_ioc(sha256, domains=None):
    path = "https://api.security.microsoft.com/api/tiindicators"

    body = {
        "indicatorValue": sha256,
        "indicatorType": "FileSha256",
        "action": "Block",
        "title": "SOC auto-block",
        "expirationTime": "2099-01-01T00:00:00Z",
        "generateAlert": True,
    }

    return _defender_post(path, body)


def isolate_device(device_id):
    path = (
        "https://api.security.microsoft.com/api/machines/"
        f"{device_id}/isolate"
    )

    return _defender_post(
        path,
        {
            "Comment": "SOC incident response",
            "IsolationType": "Full",
        },
    )


ACTIONS = {
    "disable": disable_user,
    "enable": enable_user,
    "revoke": revoke_sessions,
    "risk": get_user_risk,
    "signins": list_signins,
    "blockip": block_named_location,
    "ioc": add_defender_ioc,
    "isolate": isolate_device,
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("target")

    args = parser.parse_args()

    if args.action == "blockip":
        result = block_named_location(
            args.target,
            [args.target],
        )
    else:
        result = ACTIONS[args.action](args.target)

    print(json.dumps(result, indent=2))
