#!/usr/bin/env python3

import os
from openai import AzureOpenAI


client = AzureOpenAI(
    api_key=os.environ["AOAI_KEY"],
    api_version="2024-06-01",
    azure_endpoint=os.environ["AOAI_ENDPOINT"],
)


def draft(technique, data_source):
    response = client.chat.completions.create(
        model=os.environ["AOAI_DEPLOYMENT"],
        temperature=0.3,
        messages=[
            {
                "role": "system",
                "content": (
                    "Write a production Microsoft Sentinel KQL "
                    "detection rule. Output only KQL with a "
                    "METADATA-START/END header."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Technique: {technique}\n"
                    f"Data source: {data_source}"
                ),
            },
        ],
    )

    return response.choices[0].message.content


if __name__ == "__main__":
    print(
        draft(
            "T1059.001 PowerShell",
            "DeviceProcessEvents",
        )
    )
