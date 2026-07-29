"""Static registry of explicitly imported built-in model packs."""

from __future__ import annotations

from collections.abc import Iterable

from omiv.errors import OmivInputError
from omiv.model_packs.base import (
    ModelPack,
    ModelPackCapability,
    ModelPackMetadata,
)


class ModelPackRegistry:
    def __init__(self, packs: Iterable[ModelPack] = ()) -> None:
        self._packs: dict[str, ModelPack] = {}
        for pack in packs:
            self.register(pack)

    def register(self, pack: ModelPack) -> None:
        existing = self._packs.get(pack.pack_id)
        if existing is not None:
            if existing.pack_version == pack.pack_version:
                detail = "duplicate pack ID and version"
            else:
                detail = "duplicate pack ID"
            raise RuntimeError(f"{detail}: {pack.pack_id!r}")
        self._packs[pack.pack_id] = pack

    def get(self, pack_id: str) -> ModelPack:
        try:
            return self._packs[pack_id]
        except KeyError as exc:
            raise OmivInputError(f"unsupported model pack: {pack_id!r}") from exc

    def list(self, *, include_test_packs: bool = False) -> list[ModelPackMetadata]:
        return [
            pack.metadata
            for pack in sorted(self._packs.values(), key=lambda item: item.pack_id)
            if include_test_packs or not pack.test_only
        ]

    def detect(
        self,
        *,
        model_family: str,
        capability: ModelPackCapability | None = None,
    ) -> ModelPack:
        matches = [
            pack
            for pack in self._packs.values()
            if pack.model_family == model_family
            and (capability is None or capability in pack.capabilities)
            and not pack.test_only
        ]
        if not matches:
            raise OmivInputError(
                f"no supported model pack identifies model family {model_family!r}"
            )
        if len(matches) > 1:
            ids = ", ".join(sorted(pack.pack_id for pack in matches))
            raise OmivInputError(f"ambiguous model-pack detection for {model_family!r}: {ids}")
        return matches[0]


def _built_in_registry() -> ModelPackRegistry:
    # These are the only trusted imports used for built-in discovery.
    from omiv.model_packs.kimi_k3 import KimiK3ModelPack
    from omiv.model_packs.qwen2 import Qwen2ModelPack
    from omiv.model_packs.synthetic_dense import SyntheticDenseModelPack

    return ModelPackRegistry((Qwen2ModelPack(), KimiK3ModelPack(), SyntheticDenseModelPack()))


BUILT_IN_MODEL_PACKS = _built_in_registry()


def get_model_pack(pack_id: str) -> ModelPack:
    return BUILT_IN_MODEL_PACKS.get(pack_id)


def list_model_packs(*, include_test_packs: bool = False) -> list[ModelPackMetadata]:
    return BUILT_IN_MODEL_PACKS.list(include_test_packs=include_test_packs)


def detect_model_pack(
    *,
    model_family: str,
    capability: ModelPackCapability | None = None,
) -> ModelPack:
    return BUILT_IN_MODEL_PACKS.detect(model_family=model_family, capability=capability)
