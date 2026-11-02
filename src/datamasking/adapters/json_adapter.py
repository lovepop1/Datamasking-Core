"""JSON format adapter backed by ``json`` and ``jsonpath-ng`` (extended grammar)."""

from __future__ import annotations

import contextlib
import functools
import json
from collections.abc import Iterable, Iterator
from typing import Any

from jsonpath_ng import Fields, Index, Root
from jsonpath_ng.ext import parse as jp_parse  # type: ignore[attr-defined]

from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.node_wrapper import (
    NodeWrapper,
    is_node_attached,
    iter_wrapped,
    sever_subtree,
    unwrap_tree,
    wrap_tree,
)
from datamasking.exceptions import FormatParseError, SelectorEvaluationError


@functools.lru_cache(maxsize=512)
def _compile_jsonpath(selector: str) -> Any:
    """Compile and cache an extended JSONPath expression (supports filter predicates)."""
    try:
        return jp_parse(selector)
    except Exception as exc:
        raise SelectorEvaluationError(
            f"Invalid JSONPath selector {selector!r}: {exc}",
            detail={"selector": selector, "format": "json", "error": str(exc)},
        ) from exc


def _resolve_match(start: NodeWrapper, match: Any) -> NodeWrapper | None:
    """Walk the ``DatumInContext`` chain from *start* to locate the exact :class:`NodeWrapper`."""
    steps: list[str | int] = []
    cur: Any = match
    while cur is not None:
        path_obj = getattr(cur, "path", None)
        if isinstance(path_obj, Root):
            break
        if isinstance(path_obj, Fields):
            fields = getattr(path_obj, "fields", ())
            if not fields:
                return None
            steps.append(str(fields[0]))
        elif isinstance(path_obj, Index):
            indices = getattr(path_obj, "indices", None)
            if indices:
                steps.append(int(indices[0]))
            elif hasattr(path_obj, "index"):
                steps.append(int(path_obj.index))
            else:
                return None
        cur = getattr(cur, "context", None)

    steps.reverse()
    node: NodeWrapper | None = start
    for step in steps:
        if node is None:
            return None
        val = node.value
        if isinstance(step, int):
            if isinstance(val, list) and 0 <= step < len(val):
                child = val[step]
                node = child if isinstance(child, NodeWrapper) else None
            else:
                return None
        else:
            if isinstance(val, dict) and step in val:
                child = val[step]
                node = child if isinstance(child, NodeWrapper) else None
            else:
                return None
    return node


class JSONAdapter(FormatAdapter):
    """AST adapter for UTF-8 JSON documents."""

    @property
    def format_name(self) -> str:
        return "json"

    def parse(self, raw_bytes: bytes) -> NodeWrapper:
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise FormatParseError(
                f"Failed to parse JSON payload: {exc}",
                detail={"format": "json", "error": str(exc)},
            ) from exc
        return wrap_tree(data)

    def serialize(self, tree: NodeWrapper) -> bytes:
        plain = unwrap_tree(tree)
        return json.dumps(plain, indent=2, ensure_ascii=False).encode("utf-8")

    def validate_selector(self, selector: str) -> None:
        super().validate_selector(selector)
        stripped = selector.strip()
        if stripped.startswith("/"):
            raise SelectorEvaluationError(
                f"Selector {selector!r} looks like an XPath expression, expected JSONPath for format 'json'.",
                detail={"selector": selector, "format": "json"},
            )
        _compile_jsonpath(stripped)

    def select(self, tree: Any, selector: str) -> list[NodeWrapper]:
        stripped = selector.strip()
        if not stripped:
            raise SelectorEvaluationError("Selector must be a non-empty string.")

        # Multi-format policies may carry XPath rules alongside JSONPath rules.
        if stripped.startswith("/"):
            return []

        root = tree if isinstance(tree, NodeWrapper) else wrap_tree(tree)
        expr = _compile_jsonpath(stripped)
        plain = unwrap_tree(root)

        try:
            matches = expr.find(plain)
        except Exception as exc:
            raise SelectorEvaluationError(
                f"Failed to evaluate JSONPath selector {selector!r}: {exc}",
                detail={"selector": selector, "format": "json", "error": str(exc)},
            ) from exc

        results: list[NodeWrapper] = []
        seen_ids: set[int] = set()
        for match in matches:
            wrapper = _resolve_match(root, match)
            if wrapper is not None and self.is_attached(wrapper):
                wid = id(wrapper)
                if wid not in seen_ids:
                    seen_ids.add(wid)
                    results.append(wrapper)
        return results

    def get_identity(self, node: NodeWrapper) -> int:
        return id(node)

    def get_value(self, node: NodeWrapper) -> Any:
        return node.value

    def set_value(self, node: NodeWrapper, value: Any) -> None:
        node.value = value

    def remove_node(self, node: NodeWrapper) -> None:
        if node.parent is None:
            return
        pval = node.parent.value
        if isinstance(pval, dict) and isinstance(node.key, str):
            pval.pop(node.key, None)
            sever_subtree(node)
        elif isinstance(pval, list) and isinstance(node.key, int):
            with contextlib.suppress(ValueError):
                pval.remove(node)
            for idx, sibling in enumerate(pval):
                if isinstance(sibling, NodeWrapper):
                    sibling.key = idx
            sever_subtree(node)

    def is_attached(self, node: NodeWrapper) -> bool:
        return is_node_attached(node)

    def get_path(self, node: NodeWrapper) -> str:
        return node.path

    def is_leaf_node(self, node: NodeWrapper) -> bool:
        return not isinstance(node.value, (dict, list))

    def iter_nodes(self, tree: NodeWrapper) -> Iterable[NodeWrapper]:
        yield from iter_wrapped(tree)

    def iter_subtree(self, subtree_root: NodeWrapper) -> Iterator[NodeWrapper]:
        yield from iter_wrapped(subtree_root)
