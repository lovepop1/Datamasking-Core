"""Safe YAML format adapter backed by ``yaml.safe_load`` and ``jsonpath-ng``."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import yaml

from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.json_adapter import JSONAdapter
from datamasking.adapters.node_wrapper import NodeWrapper, unwrap_tree, wrap_tree
from datamasking.exceptions import FormatParseError


class YAMLAdapter(FormatAdapter):
    """AST adapter for YAML 1.1/1.2 documents using ``yaml.safe_load`` / ``yaml.safe_dump``."""

    def __init__(self) -> None:
        self._json_adapter = JSONAdapter()

    @property
    def format_name(self) -> str:
        return "yaml"

    def parse(self, raw_bytes: bytes) -> NodeWrapper:
        try:
            data = yaml.safe_load(raw_bytes.decode("utf-8"))
            if data is None:
                data = {}
        except Exception as exc:
            raise FormatParseError(
                f"Failed to parse YAML payload: {exc}",
                detail={"format": "yaml", "error": str(exc)},
            ) from exc
        return wrap_tree(data)

    def serialize(self, tree: NodeWrapper) -> bytes:
        plain = unwrap_tree(tree)
        dumped: str = yaml.safe_dump(
            plain,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
        return dumped.encode("utf-8")

    def validate_selector(self, selector: str) -> None:
        self._json_adapter.validate_selector(selector)

    def select(self, tree: Any, selector: str) -> list[NodeWrapper]:
        return self._json_adapter.select(tree, selector)

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

    def iter_nodes(self, tree: NodeWrapper) -> Iterable[NodeWrapper]:
        return self._json_adapter.iter_nodes(tree)

    def iter_subtree(self, subtree_root: NodeWrapper) -> Iterator[NodeWrapper]:
        return self._json_adapter.iter_subtree(subtree_root)
