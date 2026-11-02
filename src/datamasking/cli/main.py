"""Command-line interface for ``datamasking-core``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from datamasking.adapters.registry import detect_format_from_filename, list_supported_formats
from datamasking.engine import MaskingEngine
from datamasking.exceptions import DataMaskingError
from datamasking.hierarchies.base import get_hierarchy, list_hierarchies
from datamasking.pipeline.phase3_apply import ExecutionMode
from datamasking.plugins import discover_entrypoint_plugins, load_plugin
from datamasking.policy.loader import export_policy_json_schema, load_policy_from_file
from datamasking.techniques.base import get_technique, list_techniques


def _add_plugin_arg(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="SPEC",
        help="Load a custom plugin (.py file path or importable module name). Repeatable.",
    )


def _load_requested_plugins(specs: list[str]) -> None:
    discover_entrypoint_plugins()
    for spec in specs:
        load_plugin(spec)


def create_parser() -> argparse.ArgumentParser:
    """Build the top-level ``datamasking`` CLI argument parser."""
    from datamasking import __version__

    parser = argparse.ArgumentParser(
        prog="datamasking",
        description="Declarative, zero-disk, policy-driven data masking engine.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"datamasking-core {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: mask
    mask_p = subparsers.add_parser(
        "mask",
        help="Mask a file or stdin stream in memory using a declarative YAML policy.",
    )
    mask_p.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input file path, or '-' to read raw bytes from stdin.",
    )
    mask_p.add_argument(
        "-p",
        "--policy",
        required=True,
        help="Path to the declarative masking policy YAML file.",
    )
    mask_p.add_argument(
        "-o",
        "--output",
        help="Optional output file path. Writes masked bytes to stdout when omitted.",
    )
    mask_p.add_argument(
        "-f",
        "--format",
        help="Explicit format override ('json', 'xml', 'yaml', 'csv').",
    )
    mask_p.add_argument(
        "-r",
        "--role",
        default=None,
        help="Optional caller role evaluated against policy roles and scopes.",
    )
    mask_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview which rules would apply without executing destructive masking.",
    )
    mask_p.add_argument(
        "-s",
        "--salt",
        default=None,
        help="HMAC key for deterministic pseudonymization (or set DATAMASKING_SALT).",
    )
    mask_p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional integer RNG seed for reproducible randomized techniques.",
    )
    mask_p.add_argument(
        "--report",
        default=None,
        help="Optional file path to write JSON execution metadata (conflicts, unmatched paths, k-anonymity).",
    )
    _add_plugin_arg(mask_p)

    # Subcommand: validate
    val_p = subparsers.add_parser(
        "validate",
        help="Strictly validate a masking policy YAML file.",
    )
    val_p.add_argument(
        "-p",
        "--policy",
        required=True,
        help="Path to the masking policy YAML file.",
    )
    _add_plugin_arg(val_p)

    # Subcommand: techniques
    tech_p = subparsers.add_parser(
        "techniques",
        help="List registered masking techniques and their accepted parameters.",
    )
    tech_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output full JSON Schema definitions for all registered techniques.",
    )
    _add_plugin_arg(tech_p)

    # Subcommand: formats
    fmt_p = subparsers.add_parser(
        "formats",
        help="List registered serialization formats and generalization hierarchies.",
    )
    _add_plugin_arg(fmt_p)

    # Subcommand: schema
    schema_p = subparsers.add_parser(
        "schema",
        help="Export Draft 2020-12 JSON Schema for policy YAML validation and IDE autocomplete.",
    )
    schema_p.add_argument(
        "-o",
        "--output",
        help="Optional output path for the JSON Schema file (defaults to stdout).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point returning an OS exit status code (``0`` on success, ``1`` on error)."""
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        plugin_specs: list[str] = getattr(args, "plugin", [])
        _load_requested_plugins(plugin_specs)

        if args.command == "mask":
            engine = MaskingEngine.from_file(args.policy, salt=args.salt)
            mode: ExecutionMode = "dry_run" if args.dry_run else "mask"

            if args.input == "-":
                raw_bytes = sys.stdin.buffer.read()
                fmt = args.format
            else:
                in_path = Path(args.input)
                if not in_path.is_file():
                    print(f"[ERROR] Input file not found: '{args.input}'", file=sys.stderr)
                    return 1
                raw_bytes = in_path.read_bytes()
                fmt = (
                    args.format or engine.policy.format or detect_format_from_filename(str(in_path))
                )

            result = engine.mask(
                raw_bytes,
                format=fmt,
                role=args.role,
                mode=mode,
                salt=args.salt,
                seed=args.seed,
            )

            if args.report:
                report_payload: dict[str, Any] = {
                    "request_id": result.request_id,
                    "format": result.format_name,
                    "mode": result.mode,
                    "role": result.role,
                    "conflict_count": result.conflict_count,
                    "conflicts": result.conflict_log,
                    "uncovered_count": result.uncovered_count,
                    "unmatched_paths": result.unmatched_paths,
                    "warnings": result.warnings,
                    "k_achieved": result.k_achieved,
                    "kanon_report": (
                        result.kanon_report.to_dict() if result.kanon_report else None
                    ),
                }
                report_path = Path(args.report)
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps(report_payload, indent=2) + "\n",
                    encoding="utf-8",
                )

            if args.output:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(result.output_bytes)
                print(
                    f"[OK] Wrote {len(result.output_bytes)} bytes to '{args.output}' "
                    f"(format={result.format_name}, mode={result.mode}).",
                    file=sys.stderr,
                )
            else:
                sys.stdout.buffer.write(result.output_bytes)
                if not result.output_bytes.endswith(b"\n"):
                    sys.stdout.buffer.write(b"\n")
                sys.stdout.buffer.flush()
            return 0

        if args.command == "validate":
            policy = load_policy_from_file(args.policy)
            print(f"[OK] Policy '{args.policy}' is valid.")
            print(f"  Version:          {policy.version}")
            print(f"  Format:           {policy.format or '(auto-detect)'}")
            print(f"  Unmatched fields: {policy.unmatched_fields}")
            print(f"  On error:         {policy.on_error}")
            print(f"  Global rules:     {len(policy.rules)}")
            print(f"  Profiles:         {sorted(policy.profiles.keys())}")
            print(f"  Scopes:           {len(policy.scopes)}")
            print(
                f"  k-Anonymity:      "
                f"{f'k={policy.k_anonymity.k} ({policy.k_anonymity.strategy})' if policy.k_anonymity else 'disabled'}"
            )
            return 0

        if args.command == "techniques":
            tech_names = list_techniques()
            if args.as_json:
                schemas = {
                    name: get_technique(name).params_model.model_json_schema()
                    for name in tech_names
                }
                print(json.dumps(schemas, indent=2))
                return 0

            print(f"Registered Masking Techniques ({len(tech_names)}):")
            for name in tech_names:
                instance = get_technique(name)
                schema = instance.params_model.model_json_schema()
                props = list(schema.get("properties", {}).keys())
                suffix = f" (params: {', '.join(props)})" if props else " (no params)"
                print(f"  - {name}{suffix}")
            return 0

        if args.command == "formats":
            fmts = list_supported_formats()
            hierarchies = list_hierarchies()
            print(f"Supported Formats ({len(fmts)}): {', '.join(fmts)}")
            h_desc = [f"{h} (0..{get_hierarchy(h).max_level})" for h in hierarchies]
            print(f"Generalization Hierarchies ({len(hierarchies)}): {', '.join(h_desc)}")
            return 0

        if args.command == "schema":
            schema_dict = export_policy_json_schema()
            rendered = json.dumps(schema_dict, indent=2) + "\n"
            if args.output:
                schema_out = Path(args.output)
                schema_out.parent.mkdir(parents=True, exist_ok=True)
                schema_out.write_text(rendered, encoding="utf-8")
                print(f"[OK] Wrote Policy JSON Schema to '{args.output}'.", file=sys.stderr)
            else:
                sys.stdout.write(rendered)
            return 0

        return 0
    except DataMaskingError as exc:
        print(f"[ERROR] {exc.message}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERROR] Unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
