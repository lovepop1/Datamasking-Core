"""Plugin discovery and dynamic plugin loading for ``datamasking-core``.

Supports three ways for users and contributors to extend the library without
modifying core code:

1. **In-process Python decorators**: ``@register_technique``, ``@register_adapter``,
   ``@register_hierarchy``.
2. **Installed Python distribution entry points** (auto-discovered):
   - ``datamasking.techniques``
   - ``datamasking.adapters``
   - ``datamasking.hierarchies``
3. **File paths or dotted module names** (used by the CLI ``--plugin`` flag and
   :func:`load_plugin`): ``load_plugin("./my_plugin.py")`` or
   ``load_plugin("my_company.masking_plugins")``.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import sys
from pathlib import Path
from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.registry import register_adapter
from datamasking.exceptions import PluginLoadError
from datamasking.hierarchies.base import Hierarchy, register_hierarchy
from datamasking.techniques.base import (
    BaseTechnique,
    register_technique_instance,
)

ENTRYPOINT_GROUPS: tuple[str, str, str] = (
    "datamasking.techniques",
    "datamasking.adapters",
    "datamasking.hierarchies",
)

_ENTRYPOINTS_LOADED = False


def _register_loaded_object(group: str, ep_name: str, obj: Any) -> None:
    """Register an entry-point target if its module import did not already self-register."""
    if group == "datamasking.techniques":
        if isinstance(obj, type) and issubclass(obj, BaseTechnique):
            register_technique_instance(ep_name, obj())
        elif isinstance(obj, BaseTechnique):
            register_technique_instance(ep_name, obj)
        elif callable(obj):
            obj()
    elif group == "datamasking.adapters":
        if isinstance(obj, type) and issubclass(obj, FormatAdapter):
            register_adapter(ep_name, obj())
        elif isinstance(obj, FormatAdapter):
            register_adapter(ep_name, obj)
        elif callable(obj):
            obj()
    elif group == "datamasking.hierarchies":
        if isinstance(obj, type) and issubclass(obj, Hierarchy):
            register_hierarchy(ep_name, obj())
        elif isinstance(obj, Hierarchy):
            register_hierarchy(ep_name, obj)
        elif callable(obj):
            obj()


def discover_entrypoint_plugins(*, force: bool = False) -> list[str]:
    """Discover and load plugins advertised via ``importlib.metadata.entry_points``.

    Returns:
        Sorted list of loaded ``"<group>:<name>"`` identifiers.
    """
    global _ENTRYPOINTS_LOADED
    if _ENTRYPOINTS_LOADED and not force:
        return []

    loaded: list[str] = []
    eps = importlib.metadata.entry_points()
    for group in ENTRYPOINT_GROUPS:
        group_eps = eps.select(group=group)
        for ep in group_eps:
            try:
                target = ep.load()
                _register_loaded_object(group, ep.name, target)
                loaded.append(f"{group}:{ep.name}")
            except Exception as exc:
                raise PluginLoadError(
                    f"Failed to load entry-point plugin '{ep.name}' in group '{group}': {exc}",
                    detail={"group": group, "name": ep.name, "error": str(exc)},
                ) from exc

    _ENTRYPOINTS_LOADED = True
    return sorted(loaded)


def load_plugin(spec: str) -> str:
    """Load a plugin from either a Python file path or a dotted module path.

    Args:
        spec: Either a path to a ``.py`` file (e.g. ``"./custom_tech.py"``) or
            an importable module name (e.g. ``"acme_privacy.techniques"``).

    Returns:
        The loaded module's ``__name__``.

    Raises:
        PluginLoadError: If the file does not exist or importing raises an error.
    """
    candidate_path = Path(spec)
    if spec.endswith(".py") or candidate_path.is_file():
        resolved = candidate_path.resolve()
        if not resolved.is_file():
            raise PluginLoadError(
                f"Plugin file not found: '{spec}'",
                detail={"plugin": spec},
            )
        module_name = f"_datamasking_user_plugin_{resolved.stem}_{abs(hash(str(resolved)))}"
        try:
            mod_spec = importlib.util.spec_from_file_location(module_name, resolved)
            if mod_spec is None or mod_spec.loader is None:
                raise PluginLoadError(
                    f"Could not create module spec from '{resolved}'.",
                    detail={"plugin": spec},
                )
            module = importlib.util.module_from_spec(mod_spec)
            sys.modules[module_name] = module
            mod_spec.loader.exec_module(module)
            return module_name
        except PluginLoadError:
            raise
        except Exception as exc:
            raise PluginLoadError(
                f"Failed to execute plugin file '{spec}': {exc}",
                detail={"plugin": spec, "error": str(exc)},
            ) from exc

    try:
        mod = importlib.import_module(spec)
        return mod.__name__
    except Exception as exc:
        raise PluginLoadError(
            f"Failed to import plugin module '{spec}': {exc}",
            detail={"plugin": spec, "error": str(exc)},
        ) from exc
