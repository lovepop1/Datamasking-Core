"""Built-in masking technique implementations."""

from __future__ import annotations

from datamasking.techniques.builtins.deep_redact import DeepRedactParams, DeepRedactTechnique
from datamasking.techniques.builtins.format_preserve import (
    FormatPreserveParams,
    FormatPreserveTechnique,
)
from datamasking.techniques.builtins.generalize import GeneralizeParams, GeneralizeTechnique
from datamasking.techniques.builtins.mask_pattern import MaskPatternParams, MaskPatternTechnique
from datamasking.techniques.builtins.noise import NoiseParams, NoiseTechnique
from datamasking.techniques.builtins.nullify import NullifyParams, NullifyTechnique
from datamasking.techniques.builtins.pseudonymize import (
    PseudonymizeParams,
    PseudonymizeTechnique,
)
from datamasking.techniques.builtins.redact import RedactParams, RedactTechnique
from datamasking.techniques.builtins.suppress import SuppressParams, SuppressTechnique
from datamasking.techniques.builtins.synthesize import (
    SynthesizeParams,
    SynthesizeTechnique,
    SyntheticCategory,
)

__all__ = [
    "DeepRedactParams",
    "DeepRedactTechnique",
    "FormatPreserveParams",
    "FormatPreserveTechnique",
    "GeneralizeParams",
    "GeneralizeTechnique",
    "MaskPatternParams",
    "MaskPatternTechnique",
    "NoiseParams",
    "NoiseTechnique",
    "NullifyParams",
    "NullifyTechnique",
    "PseudonymizeParams",
    "PseudonymizeTechnique",
    "RedactParams",
    "RedactTechnique",
    "SuppressParams",
    "SuppressTechnique",
    "SynthesizeParams",
    "SynthesizeTechnique",
    "SyntheticCategory",
]
