"""Abstract base class for AST format adapters.

A :class:`FormatAdapter` abstracts a concrete serialization format (JSON, XML,
YAML, CSV, or any custom user-registered format) behind a uniform mutable tree
interface so the masking pipeline operates identically across formats.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import Any


class FormatAdapter(ABC):
    """Contract implemented by all AST format adapters."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Canonical lowercase format identifier (e.g. ``'json'``, ``'xml'``)."""

    @abstractmethod
    def parse(self, raw_bytes: bytes) -> Any:
        """Parse *raw_bytes* into an in-memory mutable AST representation.

        Raises:
            FormatParseError: If *raw_bytes* is malformed for this format.
        """

    @abstractmethod
    def serialize(self, tree: Any) -> bytes:
        """Serialize the mutated AST *tree* back into UTF-8 encoded bytes."""

    @abstractmethod
    def select(self, tree: Any, selector: str) -> list[Any]:
        """Evaluate *selector* against *tree* and return matching AST nodes.

        Raises:
            SelectorEvaluationError: If *selector* has invalid syntax for this format.
        """

    def validate_selector(self, selector: str) -> None:
        """Validate *selector* syntax without requiring a document instance.

        Subclasses should override this to provide load-time selector checking
        when a policy explicitly sets ``format``.
        """
        if not selector or not selector.strip():
            from datamasking.exceptions import SelectorEvaluationError

            raise SelectorEvaluationError("Selector must be a non-empty string.")

    @abstractmethod
    def get_identity(self, node: Any) -> int:
        """Return an integer uniquely identifying *node* during a single pipeline run."""

    @abstractmethod
    def get_value(self, node: Any) -> Any:
        """Return the scalar value stored at *node*."""

    @abstractmethod
    def set_value(self, node: Any, value: Any) -> None:
        """Replace the scalar value stored at *node* in-place."""

    @abstractmethod
    def remove_node(self, node: Any) -> None:
        """Detach and remove *node* from its parent container in the AST."""

    @abstractmethod
    def is_attached(self, node: Any) -> bool:
        """Return ``True`` if *node* is still connected to the document root."""

    @abstractmethod
    def get_path(self, node: Any) -> str:
        """Return a canonical human-readable path string for *node*."""

    @abstractmethod
    def is_leaf_node(self, node: Any) -> bool:
        """Return ``True`` if *node* holds a scalar value rather than child containers."""

    @abstractmethod
    def iter_nodes(self, tree: Any) -> Iterable[Any]:
        """Yield every node in *tree* in depth-first document order."""

    @abstractmethod
    def iter_subtree(self, subtree_root: Any) -> Iterator[Any]:
        """Yield *subtree_root* and all of its descendants in depth-first order."""
