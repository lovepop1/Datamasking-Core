"""Format adapters package for ``datamasking-core``.

Registers built-in ``json``, ``xml``, ``yaml`` (alias ``yml``), and ``csv``
adapters and their file extensions upon import.
"""

from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.csv_adapter import CSVAdapter, CSVDocument
from datamasking.adapters.json_adapter import JSONAdapter
from datamasking.adapters.node_wrapper import NodeWrapper
from datamasking.adapters.registry import (
    detect_format_from_content,
    detect_format_from_filename,
    get_adapter,
    list_supported_formats,
    register_adapter,
)
from datamasking.adapters.xml_adapter import XMLAdapter, XMLAttributeNode, XMLTreeWrapper
from datamasking.adapters.yaml_adapter import YAMLAdapter

register_adapter("json", JSONAdapter(), extensions=[".json"])
register_adapter("xml", XMLAdapter(), extensions=[".xml"])
register_adapter("yaml", YAMLAdapter(), extensions=[".yaml", ".yml"])
register_adapter("yml", YAMLAdapter())
register_adapter("csv", CSVAdapter(), extensions=[".csv"])

__all__ = [
    "CSVAdapter",
    "CSVDocument",
    "FormatAdapter",
    "JSONAdapter",
    "NodeWrapper",
    "XMLAdapter",
    "XMLAttributeNode",
    "XMLTreeWrapper",
    "YAMLAdapter",
    "detect_format_from_content",
    "detect_format_from_filename",
    "get_adapter",
    "list_supported_formats",
    "register_adapter",
]
