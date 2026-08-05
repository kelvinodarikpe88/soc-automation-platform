#!/usr/bin/env python3

import json
import os
from openai import AzureOpenAI


client = AzureOpenAI(
    api_key=os.environ["AOAI_KEY"],
    api_version="2024-06-01",
    azure_endpoint=os.environ["AOAI_ENDPOINT"],
)


INCIDENT = {
    "id": "SOC-2026-001",
    "title": "Impossible travel",
    "severity": "High",
    "entities": [
        {
            "type": "account",
            "name": "user@example.com",
        }
    ],
    "evidence": [
        "Successful login from country A",
        "Successful login from country B",
    ],
}


def triage(incident):
    response = client.chat.completions.create(
        model=os.environ["AOAI_DEPLOYMENT"],
        temperature=0.2,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a senior SOC analyst. "
                    "Return JSON only with summary, playbook, "
                    "containment and false_positive_check."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(incident),
            },
        ],
    )

    return response.choices[0].message.content


if __name__ == "__main__":
    print(triage(INCIDENT))
