"""Phase-aware schema capability registry for Assurance Bundle interoperability."""

from __future__ import annotations

import inspect
from types import ModuleType
from typing import cast

from pydantic import BaseModel

from omiv.assurance.models import EvidencePhase
from omiv.attestations import models as attestation_models
from omiv.continuous_trust.schema import SCHEMA_MODELS as CONTINUOUS_TRUST_SCHEMAS
from omiv.custody import models as custody_models
from omiv.governance import models as governance_models
from omiv.passport import models as passport_models
from omiv.payload_integrity.schema import SCHEMA_MODELS as PAYLOAD_SCHEMAS
from omiv.quantization.schema import SCHEMA_MODELS as QUANTIZATION_SCHEMAS
from omiv.reconciliation.schema import SCHEMA_MODELS as RECONCILIATION_SCHEMAS
from omiv.runtime.schema import RUNTIME_SCHEMA_MODELS
from omiv.runtime_resolution.schema import SCHEMA_MODELS as RUNTIME_RESOLUTION_SCHEMAS
from omiv.security.schema import SECURITY_SCHEMA_MODELS
from omiv.tokenizer_parity.schema import SCHEMA_MODELS as TOKENIZER_SCHEMAS
from omiv.trust import models as trust_models


def _models_from_module(module: ModuleType) -> dict[str, type[BaseModel]]:
    discovered: dict[str, type[BaseModel]] = {}
    for _name, candidate in inspect.getmembers(module, inspect.isclass):
        if not issubclass(candidate, BaseModel):
            continue
        field = candidate.model_fields.get("schema_id")
        if field is None or field.alias != "schema" or not isinstance(field.default, str):
            continue
        existing = discovered.get(field.default)
        if existing is not None and existing is not candidate:
            raise RuntimeError(f"duplicate schema model registration: {field.default}")
        discovered[field.default] = candidate
    return discovered


def _merge(*registries: dict[str, type[BaseModel]]) -> dict[str, type[BaseModel]]:
    result: dict[str, type[BaseModel]] = {}
    for registry in registries:
        for schema, model in registry.items():
            existing = result.get(schema)
            if existing is not None and existing is not model:
                raise RuntimeError(f"conflicting schema model registration: {schema}")
            result[schema] = model
    return result


PHASE_5_SCHEMAS = _merge(
    _models_from_module(passport_models),
    _models_from_module(custody_models),
    _models_from_module(attestation_models),
    _models_from_module(trust_models),
    _models_from_module(governance_models),
    SECURITY_SCHEMA_MODELS,
    cast(dict[str, type[BaseModel]], RUNTIME_SCHEMA_MODELS),
    CONTINUOUS_TRUST_SCHEMAS,
)

PHASE_SCHEMAS: dict[EvidencePhase, dict[str, type[BaseModel]]] = {
    EvidencePhase.PHASE_5: PHASE_5_SCHEMAS,
    EvidencePhase.PHASE_6A: PAYLOAD_SCHEMAS,
    EvidencePhase.PHASE_6B: RECONCILIATION_SCHEMAS,
    EvidencePhase.PHASE_6C: QUANTIZATION_SCHEMAS,
    EvidencePhase.PHASE_6D: TOKENIZER_SCHEMAS,
    EvidencePhase.PHASE_6E: RUNTIME_RESOLUTION_SCHEMAS,
}


def supported_schemas(phase: EvidencePhase | None = None) -> tuple[str, ...]:
    if phase is not None:
        return tuple(sorted(PHASE_SCHEMAS.get(phase, {})))
    return tuple(sorted({schema for registry in PHASE_SCHEMAS.values() for schema in registry}))


def schema_model(phase: EvidencePhase, schema: str) -> type[BaseModel] | None:
    return PHASE_SCHEMAS.get(phase, {}).get(schema)
