"""Runnable example loading a custom plugin file and executing a policy that uses it."""

from __future__ import annotations

import json
from pathlib import Path

from datamasking import MaskingEngine, load_plugin


def main() -> None:
    here = Path(__file__).parent
    load_plugin(str(here / "date_shift.py"))

    engine = MaskingEngine.from_file(here / "policy.yaml")
    payload = {
        "study_arm": "control",
        "encounters": [
            {"encounter_id": "ENC-1", "admitted_on": "2026-03-15", "discharged_on": "2026-03-19"}
        ],
    }
    masked = engine.mask_data(payload)
    print(json.dumps(masked, indent=2))


if __name__ == "__main__":
    main()
