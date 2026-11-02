"""Runnable quickstart example demonstrating policy-driven JSON masking and k-anonymity."""

from __future__ import annotations

import json
from pathlib import Path

from datamasking import MaskingEngine


def main() -> None:
    here = Path(__file__).parent
    engine = MaskingEngine.from_file(here / "policy.yaml", salt="demo-study-hmac-key-2026")
    result = engine.mask_file(here / "patients.json")

    masked = json.loads(result.output_text)
    print(json.dumps(masked, indent=2))
    print("\n--- Audit Summary ---")
    print(f"Format:           {result.format_name}")
    print(f"Conflicts:        {result.conflict_count}")
    print(f"Unmatched leaves: {result.unmatched_paths}")
    print(f"k-Anonymity met:  {result.k_achieved}")
    if result.kanon_report is not None:
        print(f"Final QI levels:  {result.kanon_report.final_qi_levels}")


if __name__ == "__main__":
    main()
