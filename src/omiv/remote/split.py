"""Generic filename-only candidate split-set detection."""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from omiv.remote.models import SplitCandidate

_SHARD = re.compile(
    r"^(?P<stem>.+)-(?P<ordinal>[0-9]{5})-of-(?P<count>[0-9]{5})\.gguf$",
    re.IGNORECASE,
)


def detect_split_candidates(paths: list[str]) -> tuple[list[SplitCandidate], list[str]]:
    grouped: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
    extras: list[str] = []
    for path in sorted(item for item in paths if item.lower().endswith(".gguf")):
        name = path.rsplit("/", 1)[-1]
        match = _SHARD.fullmatch(name)
        if match is None:
            extras.append(path)
            continue
        directory = path.rpartition("/")[0]
        stem_name = match.group("stem")
        stem = f"{directory}/{stem_name}" if directory else stem_name
        grouped[stem].append(
            (path, int(match.group("ordinal")), int(match.group("count")))
        )

    candidates: list[SplitCandidate] = []
    for stem in sorted(grouped):
        entries = grouped[stem]
        counts = sorted({item[2] for item in entries})
        declared = max(counts)
        ordinal_counts = Counter(item[1] for item in entries)
        observed = sorted(ordinal_counts)
        duplicates = sorted(key for key, count in ordinal_counts.items() if count > 1)
        missing = sorted(set(range(1, declared + 1)) - set(observed))
        inconsistent = counts if len(counts) > 1 else []
        contiguous = observed == list(range(1, declared + 1))
        candidates.append(
            SplitCandidate(
                stem=stem,
                declared_shard_count=declared,
                observed_ordinals=observed,
                duplicate_ordinals=duplicates,
                missing_ordinals=missing,
                inconsistent_declared_counts=inconsistent,
                non_contiguous=not contiguous,
                files=sorted(item[0] for item in entries),
                complete=not duplicates and not missing and not inconsistent and contiguous,
            )
        )
    return candidates, extras
