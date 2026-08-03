"""Bounded Hugging Face metadata adapter layered on the provider-neutral core."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote

from omiv.errors import OmivInputError
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.reconciliation.building import (
    build_digest_descriptor,
    build_execution_record,
    build_member,
    build_snapshot,
)
from omiv.reconciliation.collection import (
    BoundedMetadataClient,
    HttpMetadataResponse,
)
from omiv.reconciliation.models import (
    CollectionMode,
    DigestKind,
    ListingCompleteness,
    NetworkUse,
    ObservationLevel,
    ProvenanceStrength,
    RemoteArtifactLocator,
    RemoteCollectionExecutionRecord,
    RemoteMemberRole,
    RemoteSnapshotManifest,
    RemoteSnapshotPlan,
    ResolvedRevisionKind,
    StorageRepresentation,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class UrllibMetadataTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(self, url: str, *, timeout_seconds: float) -> HttpMetadataResponse:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "omiv-phase6b-metadata/1"},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                body = response.read(16 * 1024 * 1024 + 1)
                return HttpMetadataResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(16 * 1024 * 1024 + 1)
            return HttpMetadataResponse(
                status=exc.code,
                headers=dict(exc.headers.items()),
                body=body,
            )
        except TimeoutError:
            raise
        except OSError as exc:
            raise OmivInputError(f"metadata transport failed: {exc}") from exc


def collect_huggingface_metadata(
    locator: RemoteArtifactLocator,
    plan: RemoteSnapshotPlan,
    *,
    observed_at: str,
    transport: Any | None = None,
    raw_response_sink: Callable[[str, bytes], None] | None = None,
) -> tuple[RemoteCollectionExecutionRecord, RemoteSnapshotManifest]:
    if locator.provider_kind.value != "HUGGING_FACE":
        raise OmivInputError("Hugging Face adapter requires a HUGGING_FACE locator")
    if plan.collection_mode != CollectionMode.BOUNDED_PUBLIC_METADATA_COLLECTION:
        raise OmivInputError("live metadata adapter requires bounded public metadata mode")
    if plan.payload_download_policy.value != "FORBIDDEN" or plan.limits.maximum_payload_bytes != 0:
        raise OmivInputError("payload download must remain forbidden")
    client = BoundedMetadataClient(
        transport or UrllibMetadataTransport(),
        allowed_hosts=plan.allowed_hosts,
        limits=plan.limits,
    )
    repo = quote(f"{locator.namespace}/{locator.artifact_name}", safe="/")
    revision = quote(locator.requested_revision, safe="")
    url = f"https://huggingface.co/api/models/{repo}/revision/{revision}?blobs=true"
    raw = client.get_json_metadata(url)
    if raw_response_sink is not None:
        raw_response_sink("model", raw)
    value = parse_bounded_json_bytes(
        raw,
        source_name="huggingface-model-metadata",
        max_bytes=plan.limits.maximum_response_bytes,
    )
    resolved = value.get("sha")
    if not isinstance(resolved, str):
        raise OmivInputError("provider metadata lacks resolved revision or member listing")
    tree_url = (
        f"https://huggingface.co/api/models/{repo}/tree/{quote(resolved, safe='')}?recursive=true"
    )
    tree_entries: list[Any] = []
    page = 0
    while tree_url:
        response = client.get_json_response(tree_url)
        if raw_response_sink is not None:
            raw_response_sink(f"tree-{page:04}", response.body)
        tree_value = parse_bounded_json_bytes(
            response.body,
            source_name=f"huggingface-repository-tree-page-{page}",
            max_bytes=plan.limits.maximum_response_bytes,
            require_object=False,
        )
        if not isinstance(tree_value, list):
            raise OmivInputError("provider tree response must be a JSON list")
        tree_entries.extend(tree_value)
        if len(tree_entries) > plan.limits.maximum_members:
            raise OmivInputError("LIMIT_EXCEEDED:REMOTE_MEMBERS")
        tree_url = _next_link(response.headers)
        page += 1
    siblings = [
        item for item in tree_entries if isinstance(item, dict) and item.get("type") != "directory"
    ]
    members = []
    for raw_member in siblings:
        path_value = raw_member.get("path") if isinstance(raw_member, dict) else None
        if not isinstance(path_value, str):
            raise OmivInputError("provider returned an invalid member record")
        path = path_value
        size = raw_member.get("size")
        size = size if isinstance(size, int) and size >= 0 else None
        digests = []
        storage = StorageRepresentation.DIRECT_FILE
        lfs = raw_member.get("lfs")
        xet = raw_member.get("xetHash") or raw_member.get("xet_hash")
        blob_id = raw_member.get("oid") or raw_member.get("blobId")
        lfs_sha256 = None
        if isinstance(lfs, dict):
            lfs_sha256 = lfs.get("sha256") or lfs.get("oid")
        if isinstance(lfs_sha256, str):
            storage = StorageRepresentation.GIT_LFS_POINTER
            digests.append(
                build_digest_descriptor(
                    DigestKind.LFS_OID_SHA256,
                    lfs_sha256,
                    evidence_source="source.huggingface-api",
                    provenance_strength=ProvenanceStrength.PROVIDER_OBSERVED,
                    limitations=(
                        "Provider metadata did not independently observe and validate LFS "
                        "pointer semantics.",
                    ),
                )
            )
        if isinstance(xet, str):
            storage = StorageRepresentation.XET_BACKED_OBJECT
            digests.append(
                build_digest_descriptor(
                    DigestKind.XET_OBJECT_ID,
                    xet,
                    evidence_source="source.huggingface-api",
                    provenance_strength=ProvenanceStrength.PROVIDER_OBSERVED,
                    limitations=("Xet object identity is not a payload digest.",),
                )
            )
        if isinstance(blob_id, str):
            digests.append(
                build_digest_descriptor(
                    DigestKind.PROVIDER_OPAQUE_ID,
                    blob_id,
                    evidence_source="source.huggingface-api",
                    provenance_strength=ProvenanceStrength.PROVIDER_OBSERVED,
                    limitations=("Git or provider object identity is not payload SHA-256.",),
                )
            )
        if not digests:
            digests.append(
                build_digest_descriptor(
                    DigestKind.UNAVAILABLE,
                    evidence_source="source.huggingface-api",
                    provenance_strength=ProvenanceStrength.PROVIDER_OBSERVED,
                )
            )
        members.append(
            build_member(
                path,
                role=RemoteMemberRole.UNKNOWN,
                logical_size=size,
                digests=digests,
                storage_representation=storage,
                observation_level=ObservationLevel.METADATA_ONLY,
                provenance_strength=ProvenanceStrength.PROVIDER_OBSERVED,
                member_provenance="source.huggingface-api",
                available_at=observed_at,
                limitations=("Member role was not inferred from its filename.",),
            )
        )
    accounting = client.accounting
    execution = build_execution_record(
        plan,
        locator,
        network_use=NetworkUse.PUBLIC_METADATA_ONLY,
        contacted_hosts=accounting.contacted_hosts,
        requested_urls=accounting.requested_urls,
        request_count=accounting.request_count,
        response_count=accounting.response_count,
        response_bytes=accounting.response_bytes,
        redirect_hosts=accounting.redirect_hosts,
        available_at=observed_at,
        observed_at=observed_at,
    )
    snapshot = build_snapshot(
        locator,
        plan,
        execution,
        members,
        resolved_revision=resolved,
        resolved_revision_kind=ResolvedRevisionKind.IMMUTABLE_COMMIT,
        listing_completeness=ListingCompleteness.COMPLETE_FOR_DECLARED_RESPONSE_SCOPE,
        available_at=observed_at,
        observed_at=observed_at,
        provenance_strength=ProvenanceStrength.PROVIDER_OBSERVED,
        limitations=(
            "Public API metadata was observed without downloading any model payload bytes.",
            "Completeness is for this bounded API response at the supplied observation time only.",
        ),
    )
    return execution, snapshot


def _next_link(headers: Mapping[str, str]) -> str:
    link = headers.get("link") or headers.get("Link")
    if not isinstance(link, str):
        return ""
    for item in link.split(","):
        pieces = item.strip().split(";")
        if len(pieces) < 2 or not any(piece.strip() == 'rel="next"' for piece in pieces[1:]):
            continue
        target = pieces[0].strip()
        if target.startswith("<") and target.endswith(">"):
            return target[1:-1]
    return ""
