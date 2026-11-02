"""Parent-tracking AST node wrapper for JSON, YAML, and CSV structures.

Plain Python ``dict`` and ``list`` containers do not retain parent pointers,
keys, or canonical paths. Wrapping parsed structures in :class:`NodeWrapper`
enables O(1) in-place value updates, safe node removal from dicts and lists,
attachment checks, and accurate path reporting.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _format_child_path(parent_path: str, key: str) -> str:
    if _IDENT_RE.match(key):
        return f"{parent_path}.{key}"
    escaped = key.replace("\\", "\\\\").replace("'", "\\'")
    return f"{parent_path}['{escaped}']"


@dataclass(eq=False)
class NodeWrapper:
    """Mutable AST node wrapping a scalar, ``dict[str, NodeWrapper]``, or ``list[NodeWrapper]``."""

    value: Any
    parent: NodeWrapper | None = field(default=None, repr=False)
    key: str | int | None = field(default=None)
    path: str = field(default="$")
    _is_root: bool = field(default=False, repr=False)


def wrap_tree(raw: Any) -> NodeWrapper:
    """Recursively wrap a plain Python ``dict``/``list``/scalar structure."""
    root = NodeWrapper(value=None, parent=None, key=None, path="$", _is_root=True)
    _fill(root, raw, path="$")
    return root


def _fill(wrapper: NodeWrapper, raw: Any, path: str) -> None:
    if isinstance(raw, dict):
        wrapped_dict: dict[str, NodeWrapper] = {}
        for k, v in raw.items():
            key_str = str(k)
            child_path = _format_child_path(path, key_str)
            child = NodeWrapper(value=None, parent=wrapper, key=key_str, path=child_path)
            _fill(child, v, child_path)
            wrapped_dict[key_str] = child
        wrapper.value = wrapped_dict
    elif isinstance(raw, list):
        wrapped_list: list[NodeWrapper] = []
        for i, v in enumerate(raw):
            child_path = f"{path}[{i}]"
            child = NodeWrapper(value=None, parent=wrapper, key=i, path=child_path)
            _fill(child, v, child_path)
            wrapped_list.append(child)
        wrapper.value = wrapped_list
    else:
        wrapper.value = raw


def iter_wrapped(root: NodeWrapper) -> Iterator[NodeWrapper]:
    """Yield *root* and all descendants in depth-first document order."""
    yield root
    if isinstance(root.value, dict):
        for child in list(root.value.values()):
            yield from iter_wrapped(child)
    elif isinstance(root.value, list):
        for child in list(root.value):
            yield from iter_wrapped(child)


def unwrap_tree(wrapper: NodeWrapper) -> Any:
    """Reconstruct plain Python ``dict``/``list``/scalar objects from *wrapper*."""
    if isinstance(wrapper.value, dict):
        return {k: unwrap_tree(child) for k, child in wrapper.value.items()}
    if isinstance(wrapper.value, list):
        return [unwrap_tree(child) for child in wrapper.value]
    return wrapper.value


def sever_subtree(node: NodeWrapper) -> None:
    """Detach *node* and all descendants from their parents."""
    node.parent = None
    node._is_root = False
    if isinstance(node.value, dict):
        for child in node.value.values():
            sever_subtree(child)
    elif isinstance(node.value, list):
        for child in node.value:
            sever_subtree(child)


def is_node_attached(node: NodeWrapper) -> bool:
    """Return ``True`` if *node* traces an unbroken parent chain to the document root."""
    current: NodeWrapper | None = node
    while current is not None:
        if current._is_root:
            return True
        current = current.parent
    return False
