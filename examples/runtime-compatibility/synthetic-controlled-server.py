#!/usr/bin/env python3
"""Hermetic standard-library loopback fixture; never use with real model payloads."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "llama.cpp synthetic-controlled-server b10353 f8def7fe168bab245fbf15d3f18b26dbb1ef73c8"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--model", required=True)
    parser.add_argument("--mmproj")
    parser.add_argument("--gpu-layers", required=True)
    parser.add_argument("--device")
    parser.add_argument("--no-mmproj-offload", action="store_true")
    parser.add_argument("--spec-type")
    parser.add_argument("--spec-draft-model")
    parser.add_argument("--spec-draft-ngl")
    parser.add_argument("--spec-draft-device")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ctx-size", required=True, type=int)
    parser.add_argument("--parallel", required=True, type=int)
    parser.add_argument("--seed", required=True, type=int)
    return parser.parse_args()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send(self, value: object, status: int = 200) -> None:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("request must be an object")
        return value

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._send({"error": "not found"}, 404)
            return
        self._send({"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            value = self._body()
        except (ValueError, json.JSONDecodeError):
            self._send({"error": "invalid request"}, 400)
            return
        if self.path == "/tokenize":
            prompt = value.get("content")
            if not isinstance(prompt, str):
                self._send({"error": "content required"}, 400)
                return
            self._send({"tokens": list(range(1, len(prompt.split()) + 1))})
            return
        if self.path != "/completion":
            self._send({"error": "not found"}, 404)
            return
        prompt = value.get("prompt")
        image_data = value.get("image_data")
        image = None
        if isinstance(image_data, list) and len(image_data) == 1:
            item = image_data[0]
            if isinstance(item, dict) and item.get("id") == 0 and isinstance(item.get("data"), str):
                try:
                    image = base64.b64decode(item["data"], validate=True)
                except ValueError:
                    image = None
        image_prompt = isinstance(prompt, str) and prompt.startswith("[img-0]\n")
        if image_prompt != (image is not None):
            self._send({"error": "image_data required for image prompt"}, 400)
            return
        draft = self.server.active_dflash  # type: ignore[attr-defined]
        outputs = {
            "Return exactly alpha.": "alpha",
            "Describe the fixed image using one word.": "red-square",
            "Return exactly PASS.": "PASS",
        }
        plain_prompt = prompt.split("\n", 1)[-1] if image_prompt else prompt
        content = outputs.get(plain_prompt, "synthetic")
        if image is not None and hashlib.sha256(image).hexdigest() != (
            "53bf31df09c932233812a2c7b61c89a0ecbbaee90ab63f36058099e5d008e852"
        ):
            content = "wrong-image"
        prompt_tokens = len(prompt.split()) if isinstance(prompt, str) else 0
        self._send(
            {
                "backend": {
                    "backend": "SYNTHETIC",
                    "device_count": 1,
                    "device_index": 0,
                    "device_name": "OMIV synthetic controlled device",
                    "main_model_gpu_layers": "NONE",
                    "projector_offloaded": False,
                },
                "content": content,
                "dflash": {
                    "accepted_tokens": 1 if draft else 0,
                    "active": draft,
                    "draft_artifact_sha256": self.server.draft_sha256,  # type: ignore[attr-defined]
                    "draft_tokens": 2 if draft else 0,
                    "gpu_layers": "NONE",
                    "implementation": "draft-dflash" if draft else "NONE",
                },
                "finish_reason": "stop",
                "predicted_ms": 2,
                "predicted_tokens": 1,
                "prompt_ms": 1,
                "prompt_tokens": prompt_tokens,
            }
        )


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print(VERSION)
        return 0
    arguments = _arguments()
    if arguments.host != "127.0.0.1" or arguments.parallel != 1 or arguments.seed != 0:
        return 64
    if arguments.gpu_layers != "0" or arguments.device is not None:
        return 65
    active_dflash = arguments.spec_type == "draft-dflash"
    if active_dflash != (arguments.spec_draft_model is not None):
        return 66
    server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)
    server.active_dflash = active_dflash  # type: ignore[attr-defined]
    server.draft_sha256 = (  # type: ignore[attr-defined]
        hashlib.sha256(Path(arguments.spec_draft_model).read_bytes()).hexdigest()
        if active_dflash
        else None
    )

    def stop(_signum: int, _frame: object) -> None:
        server.server_close()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    server.serve_forever(poll_interval=0.02)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
