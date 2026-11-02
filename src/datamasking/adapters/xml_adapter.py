"""XXE-hardened XML format adapter using ``lxml.etree``."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from lxml import etree

from datamasking.adapters.base import FormatAdapter
from datamasking.exceptions import FormatParseError, SelectorEvaluationError


@dataclass(frozen=True)
class XMLAttributeNode:
    """First-class AST node representing an attribute on an XML element."""

    element: etree._Element
    attr_name: str


class XMLTreeWrapper:
    """Holds the root XML element and retains element proxies so ``id(elem)`` stays stable."""

    def __init__(self, root: etree._Element) -> None:
        self.root: etree._Element = root
        self.keep_alive: list[etree._Element] = list(root.iter())


def _rewrite_default_ns_xpath(selector: str) -> str:
    """Rewrite unprefixed element names in *selector* to ``*[local-name()='...']``."""
    return re.sub(
        r"(?<![:@\w])([A-Za-z_][\w\-]*)(?!\s*\()",
        lambda m: (
            f"*[local-name()='{m.group(1)}']"
            if m.group(1) not in ("and", "or", "not", "div", "mod", "true", "false")
            else m.group(1)
        ),
        selector,
    )


class XMLAdapter(FormatAdapter):
    """Hardened :class:`FormatAdapter` for XML documents (elements and attributes).

    Security:
        Configured with ``resolve_entities=False``, ``load_dtd=False``,
        ``no_network=True``, and ``huge_tree=False`` to block XML External Entity
        (XXE), SSRF, and Billion-Laughs entity-expansion attacks.
    """

    _PARSER = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
    )

    @property
    def format_name(self) -> str:
        return "xml"

    def parse(self, raw_bytes: bytes) -> XMLTreeWrapper:
        try:
            root = etree.fromstring(raw_bytes, parser=self._PARSER)
            return XMLTreeWrapper(root)
        except Exception as exc:
            raise FormatParseError(
                f"Failed to parse XML payload: {exc}",
                detail={"format": "xml", "error": str(exc)},
            ) from exc

    def serialize(self, tree: XMLTreeWrapper) -> bytes:
        out: bytes = etree.tostring(
            tree.root,
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8",
        )
        return out

    def validate_selector(self, selector: str) -> None:
        super().validate_selector(selector)
        stripped = selector.strip()
        if stripped.startswith("$"):
            raise SelectorEvaluationError(
                f"Selector {selector!r} looks like a JSONPath expression, expected XPath for format 'xml'.",
                detail={"selector": selector, "format": "xml"},
            )
        try:
            etree.XPath(stripped)
        except Exception as exc:
            raise SelectorEvaluationError(
                f"Invalid XPath selector {selector!r}: {exc}",
                detail={"selector": selector, "format": "xml", "error": str(exc)},
            ) from exc

    def select(self, tree: Any, selector: str) -> list[Any]:
        stripped = selector.strip()
        if not stripped:
            raise SelectorEvaluationError("Selector must be a non-empty string.")

        # Multi-format policies may include JSONPath rules alongside XPath rules.
        if stripped.startswith("$"):
            return []

        root_elem: etree._Element = tree.root if isinstance(tree, XMLTreeWrapper) else tree
        try:
            raw_results: Any = root_elem.xpath(stripped)
        except Exception as exc:
            raise SelectorEvaluationError(
                f"Invalid XPath selector {selector!r}: {exc}",
                detail={"selector": selector, "format": "xml", "error": str(exc)},
            ) from exc

        if not isinstance(raw_results, list):
            return []

        if not raw_results and None in root_elem.nsmap:
            try:
                ns_results = root_elem.xpath(_rewrite_default_ns_xpath(stripped))
                if isinstance(ns_results, list):
                    raw_results = ns_results
            except Exception:
                pass

        nodes: list[Any] = []
        for item in raw_results:
            if isinstance(item, etree._Element):
                nodes.append(item)
            elif getattr(item, "is_attribute", False):
                parent = item.getparent()
                attr_name = getattr(item, "attrname", None)
                if parent is not None and isinstance(attr_name, str):
                    nodes.append(XMLAttributeNode(parent, attr_name))
        return nodes

    def get_identity(self, node: Any) -> int:
        if isinstance(node, XMLAttributeNode):
            return hash((id(node.element), node.attr_name))
        return id(node)

    def get_value(self, node: Any) -> Any:
        if isinstance(node, XMLAttributeNode):
            return node.element.get(node.attr_name)
        elem: etree._Element = node
        return elem.text

    def set_value(self, node: Any, value: Any) -> None:
        if isinstance(node, XMLAttributeNode):
            if value is None:
                node.element.attrib.pop(node.attr_name, "")
            else:
                node.element.set(node.attr_name, str(value))
            return
        elem: etree._Element = node
        elem.text = str(value) if value is not None else ""

    def remove_node(self, node: Any) -> None:
        if isinstance(node, XMLAttributeNode):
            node.element.attrib.pop(node.attr_name, "")
            return
        elem: etree._Element = node
        parent = elem.getparent()
        if parent is not None:
            parent.remove(elem)

    def is_attached(self, node: Any) -> bool:
        if isinstance(node, XMLAttributeNode):
            if node.attr_name not in node.element.attrib:
                return False
            return self.is_attached(node.element)

        current: etree._Element = node
        while True:
            parent = current.getparent()
            if parent is None:
                try:
                    return current.getroottree().getroot() is current
                except Exception:
                    return False
            if current not in parent:
                return False
            current = parent

    def get_path(self, node: Any) -> str:
        if isinstance(node, XMLAttributeNode):
            return f"{self.get_path(node.element)}/@{node.attr_name}"

        parts: list[str] = []
        current: etree._Element | None = node
        while current is not None:
            tag = current.tag if isinstance(current.tag, str) else str(current.tag)
            if "}" in tag:
                tag = tag.split("}", 1)[1]
            parts.append(tag)
            current = current.getparent()
        return "/" + "/".join(reversed(parts))

    def is_leaf_node(self, node: Any) -> bool:
        if isinstance(node, XMLAttributeNode):
            return True
        elem: etree._Element = node
        if len(elem) > 0:
            return False
        # An empty root element with no text is a container, not a scalar leaf.
        return not (elem.getparent() is None and elem.text is None)

    def iter_nodes(self, tree: Any) -> Iterable[Any]:
        root: etree._Element = tree.root if isinstance(tree, XMLTreeWrapper) else tree
        for elem in root.iter():
            if not isinstance(elem.tag, str):
                continue
            yield elem
            for attr_name in list(elem.attrib.keys()):
                yield XMLAttributeNode(elem, str(attr_name))

    def iter_subtree(self, subtree_root: Any) -> Iterator[Any]:
        if isinstance(subtree_root, XMLAttributeNode):
            yield subtree_root
            return
        elem_root: etree._Element = subtree_root
        for elem in elem_root.iter():
            if not isinstance(elem.tag, str):
                continue
            yield elem
            for attr_name in list(elem.attrib.keys()):
                yield XMLAttributeNode(elem, str(attr_name))
