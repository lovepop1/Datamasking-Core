"""Tabular CSV format adapter with header-isolated row AST."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.json_adapter import JSONAdapter
from datamasking.adapters.node_wrapper import NodeWrapper, unwrap_tree, wrap_tree
from datamasking.exceptions import FormatParseError


@dataclass
class CSVDocument:
    """In-memory CSV document holding header column names separately from row nodes.

    Separating ``fieldnames`` from the mutable row AST ensures wildcard selectors
    (such as ``$..*``) only target data cells (`$[row].column`) and never corrupt
    column header names.
    """

    fieldnames: list[str]
    root: NodeWrapper


class CSVAdapter(FormatAdapter):
    """AST adapter for UTF-8 CSV tables with a header row.

    Rows are represented as a top-level JSONPath array ``$[*]`` of column-keyed
    objects, so both ``$[*].ssn`` and ``$..ssn`` address the ``ssn`` column across
    every row, and ``record_root: "$[*]"`` addresses rows for k-anonymity.
    """

    def __init__(self) -> None:
        self._json_adapter = JSONAdapter()

    @property
    def format_name(self) -> str:
        return "csv"

    def parse(self, raw_bytes: bytes) -> CSVDocument:
        try:
            text = raw_bytes.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            fieldnames = [str(f) for f in (reader.fieldnames or [])]
            rows: list[dict[str, Any]] = [dict(row) for row in reader]
        except Exception as exc:
            raise FormatParseError(
                f"Failed to parse CSV payload: {exc}",
                detail={"format": "csv", "error": str(exc)},
            ) from exc
        return CSVDocument(fieldnames=fieldnames, root=wrap_tree(rows))

    def serialize(self, tree: CSVDocument) -> bytes:
        plain_rows = unwrap_tree(tree.root)
        rows: list[dict[str, Any]] = (
            [r for r in plain_rows if isinstance(r, dict)] if isinstance(plain_rows, list) else []
        )

        if rows:
            active_fields = [col for col in tree.fieldnames if any(col in r for r in rows)]
            for r in rows:
                for k in r:
                    if k not in active_fields:
                        active_fields.append(k)
        else:
            active_fields = list(tree.fieldnames)

        output = io.StringIO()
        if active_fields:
            writer = csv.DictWriter(
                output,
                fieldnames=active_fields,
                lineterminator="\n",
                extrasaction="ignore",
            )
            writer.writeheader()
            for row in rows:
                writer.writerow({k: ("" if v is None else v) for k, v in row.items()})

        return output.getvalue().encode("utf-8")

    def validate_selector(self, selector: str) -> None:
        self._json_adapter.validate_selector(selector)

    def select(self, tree: Any, selector: str) -> list[NodeWrapper]:
        target = tree.root if isinstance(tree, CSVDocument) else tree
        return self._json_adapter.select(target, selector)

    def get_identity(self, node: NodeWrapper) -> int:
        return self._json_adapter.get_identity(node)

    def get_value(self, node: NodeWrapper) -> Any:
        return self._json_adapter.get_value(node)

    def set_value(self, node: NodeWrapper, value: Any) -> None:
        self._json_adapter.set_value(node, value)

    def remove_node(self, node: NodeWrapper) -> None:
        self._json_adapter.remove_node(node)

    def is_attached(self, node: NodeWrapper) -> bool:
        return self._json_adapter.is_attached(node)

    def get_path(self, node: NodeWrapper) -> str:
        return self._json_adapter.get_path(node)

    def is_leaf_node(self, node: NodeWrapper) -> bool:
        return self._json_adapter.is_leaf_node(node)

    def iter_nodes(self, tree: Any) -> Iterable[NodeWrapper]:
        target = tree.root if isinstance(tree, CSVDocument) else tree
        return self._json_adapter.iter_nodes(target)

    def iter_subtree(self, subtree_root: NodeWrapper) -> Iterator[NodeWrapper]:
        return self._json_adapter.iter_subtree(subtree_root)
