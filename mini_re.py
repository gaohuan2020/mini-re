#!/usr/bin/env python3
"""Minimal, compile-gated source reconstruction for one native object file."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence


class MiniREError(RuntimeError):
    """An expected, user-facing mini-re failure."""


@dataclass(frozen=True)
class Evidence:
    metadata: str
    symbols: str
    disassembly: str
    language: str

    def render(self) -> str:
        return (
            "## File metadata\n"
            + self.metadata
            + "\n\n## Symbols and relocations\n"
            + self.symbols
            + "\n\n## Disassembly\n"
            + self.disassembly
        )


@dataclass(frozen=True)
class CompileResult:
    ok: bool
    output: str


def _run(command: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise MiniREError(f"required tool not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise MiniREError(f"command timed out after {timeout}s: {command[0]}") from exc


def _successful_output(commands: Sequence[Sequence[str]], label: str) -> str:
    errors = []
    for command in commands:
        if not shutil.which(command[0]):
            continue
        proc = _run(command)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
        errors.append(f"{' '.join(command)} -> exit {proc.returncode}")
    detail = "; ".join(errors) or "no supported tool was found"
    raise MiniREError(f"could not extract {label}: {detail}")


def collect_evidence(object_file: Path, max_chars: int = 120_000) -> Evidence:
    """Collect portable, read-only evidence from exactly one .o file."""
    if not object_file.is_file():
        raise MiniREError(f"object file does not exist: {object_file}")
    if object_file.suffix.lower() not in {".o", ".obj"}:
        raise MiniREError("input must be a single .o or .obj file")

    metadata = _successful_output(
        [["file", str(object_file)]], "file metadata"
    )
    symbols = _successful_output(
        [
            ["nm", "-a", str(object_file)],
            ["llvm-nm", "-a", str(object_file)],
        ],
        "symbols",
    )

    disassembly = _successful_output(
        [
            ["objdump", "-dr", str(object_file)],
            ["llvm-objdump", "-dr", str(object_file)],
            ["otool", "-tvV", str(object_file)],
        ],
        "disassembly",
    )

    # Mach-O's objdump may omit relocation records. Add them when available.
    if "Mach-O" in metadata and shutil.which("otool"):
        reloc = _run(["otool", "-rv", str(object_file)])
        if reloc.returncode == 0 and reloc.stdout.strip():
            disassembly += "\n\nRelocations:\n" + reloc.stdout.strip()

    if len(symbols) + len(disassembly) > max_chars:
        room = max(1, max_chars - len(symbols))
        disassembly = disassembly[:room] + "\n[disassembly truncated by --max-evidence-chars]"

    language = (
        "c++"
        if re.search(r"(?:^|\s)(?:__?Z[N0-9]|\?[A-Za-z_])", symbols, re.MULTILINE)
        else "c"
    )
    return Evidence(metadata, symbols, disassembly, language)


def extract_code(response: str) -> str:
    """Extract one C/C++ translation unit from an LLM response."""
    blocks = re.findall(r"```(?:c\+\+|cpp|c|cc)?\s*\n(.*?)```", response, re.DOTALL | re.IGNORECASE)
    code = max(blocks, key=len).strip() if blocks else response.strip()
    if not code:
        raise MiniREError("the model returned no source code")
    return code + "\n"


def defined_global_symbols(nm_output: str) -> set[str]:
    """Parse defined global symbols from traditional nm output."""
    symbols = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        kind = fields[-2]
        name = fields[-1]
        if len(kind) == 1 and kind.isupper() and kind != "U":
            symbols.add(name)
    return symbols


def object_global_symbols(object_file: Path) -> set[str]:
    output = _successful_output(
        [
            ["nm", "-a", str(object_file)],
            ["llvm-nm", "-a", str(object_file)],
        ],
        "candidate symbols",
    )
    return defined_global_symbols(output)


def build_prompt(evidence: Evidence, previous: Optional[str] = None, diagnostic: Optional[str] = None) -> str:
    language_name = "C++" if evidence.language == "c++" else "C"
    prompt = f"""You are reconstructing one small native object file as portable {language_name} source.

Return exactly one complete translation unit in a single fenced code block. It must compile with no headers or files from the original project. Declare unresolved external functions or globals instead of defining fake behavior. Preserve exported symbol names, integer widths, signedness, branches, calls, constants, and side effects whenever the evidence supports them. Do not include prose outside the code block. Compilation is a required gate, but compilation alone is not proof of semantic equivalence.

{evidence.render()}
"""
    if previous is not None and diagnostic is not None:
        prompt += f"""

## Previous candidate
```{evidence.language}
{previous.rstrip()}
```

## Compiler diagnostic
```
{diagnostic[-12_000:]}
```

Repair the candidate. Return the full translation unit, not a patch.
"""
    return prompt


def codex_provider(model: Optional[str], timeout: int, codex_bin: str = "codex") -> Callable[[str], str]:
    binary = shutil.which(codex_bin)
    if binary is None:
        raise MiniREError(f"Codex CLI not found: {codex_bin}")

    def send(prompt: str) -> str:
        fd, output_name = tempfile.mkstemp(prefix="mini-re-codex-", suffix=".txt")
        os.close(fd)
        output_path = Path(output_name)
        try:
            command = [
                binary,
                "exec",
                "-s",
                "read-only",
                "--color",
                "never",
                "--skip-git-repo-check",
                "--output-last-message",
                str(output_path),
            ]
            if model:
                command.extend(["-m", model])
            command.append(prompt)
            proc = _run(command, timeout=timeout)
            if proc.returncode != 0:
                raise MiniREError(f"codex exec failed (exit {proc.returncode}):\n{proc.stdout[-4000:]}")
            return output_path.read_text(encoding="utf-8")
        finally:
            output_path.unlink(missing_ok=True)

    return send


def openai_compat_provider(
    model: str,
    timeout: int,
    base_url: str,
    api_key: Optional[str],
    api_mode: str = "responses",
) -> Callable[[str], str]:
    if api_mode not in {"responses", "chat-completions"}:
        raise MiniREError(f"unsupported OpenAI API mode: {api_mode}")
    suffix = "/responses" if api_mode == "responses" else "/chat/completions"
    normalized_base = base_url.rstrip("/")
    endpoint = normalized_base if normalized_base.endswith(suffix) else normalized_base + suffix

    def send(prompt: str) -> str:
        if api_mode == "responses":
            request_payload = {
                "model": model,
                "input": prompt,
                # Binary/source evidence can be sensitive. Do not persist it by default.
                "store": False,
            }
        else:
            request_payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "store": False,
            }
        body = json.dumps(request_payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise MiniREError(f"LLM HTTP {exc.code}: {detail[-4000:]}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise MiniREError(f"LLM request failed: {exc}") from exc
        return extract_openai_text(payload, api_mode)

    return send


def extract_openai_text(payload: object, api_mode: str = "responses") -> str:
    """Extract text from raw Responses or Chat Completions JSON."""
    if not isinstance(payload, dict):
        raise MiniREError("OpenAI response was not a JSON object")
    error = payload.get("error")
    if error:
        if isinstance(error, dict):
            detail = str(error.get("message") or error)
        else:
            detail = str(error)
        raise MiniREError(f"OpenAI API error: {detail}")

    if api_mode == "chat-completions":
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise MiniREError(
                "Chat Completions response did not contain choices[0].message.content"
            ) from exc
        if not isinstance(content, str) or not content:
            raise MiniREError("Chat Completions response contained no text")
        return content

    helper_text = payload.get("output_text")
    if isinstance(helper_text, str) and helper_text:
        return helper_text

    texts = []
    refusals = []
    output = payload.get("output", [])
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content_items = item.get("content", [])
            if not isinstance(content_items, list):
                continue
            for content in content_items:
                if not isinstance(content, dict):
                    continue
                value = content.get("text")
                if content.get("type") == "output_text" and isinstance(value, str):
                    texts.append(value)
                elif content.get("type") == "refusal" and isinstance(
                    content.get("refusal"), str
                ):
                    refusals.append(content["refusal"])
    if texts:
        return "\n".join(texts)
    if refusals:
        raise MiniREError("OpenAI model refused the request: " + "\n".join(refusals))
    raise MiniREError("Responses API result contained no output_text content")


def compile_source(
    source: Path,
    output_object: Path,
    language: str,
    compiler: Optional[str] = None,
    timeout: int = 60,
) -> CompileResult:
    compiler_name = compiler or ("c++" if language == "c++" else "cc")
    binary = shutil.which(compiler_name)
    if binary is None:
        raise MiniREError(f"compiler not found: {compiler_name}")
    standard = "-std=c++17" if language == "c++" else "-std=c11"
    output_object.unlink(missing_ok=True)
    proc = _run(
        [
            binary,
            standard,
            "-Wall",
            "-Wextra",
            "-x",
            language,
            "-c",
            str(source),
            "-o",
            str(output_object),
        ],
        timeout=timeout,
    )
    return CompileResult(proc.returncode == 0, proc.stdout.strip())


def reverse_object(
    object_file: Path,
    source_output: Path,
    object_output: Path,
    provider: Callable[[str], str],
    attempts: int = 3,
    language: str = "auto",
    compiler: Optional[str] = None,
    timeout: int = 60,
    max_evidence_chars: int = 120_000,
) -> int:
    evidence = collect_evidence(object_file, max_evidence_chars)
    if language != "auto":
        evidence = Evidence(evidence.metadata, evidence.symbols, evidence.disassembly, language)

    source_output.parent.mkdir(parents=True, exist_ok=True)
    object_output.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    diagnostic = None
    required_symbols = defined_global_symbols(evidence.symbols)

    for attempt in range(1, attempts + 1):
        response = provider(build_prompt(evidence, previous, diagnostic))
        candidate = extract_code(response)
        source_output.write_text(candidate, encoding="utf-8")
        result = compile_source(source_output, object_output, evidence.language, compiler, timeout)
        if result.ok:
            actual_symbols = object_global_symbols(object_output)
            missing_symbols = sorted(required_symbols - actual_symbols)
            if not missing_symbols:
                print(f"PASS: candidate compiled and preserved global symbols on attempt {attempt}")
                print(f"source: {source_output}")
                print(f"object: {object_output}")
                return attempt
            result = CompileResult(
                False,
                "Candidate compiled, but its object file is missing required global symbols: "
                + ", ".join(missing_symbols),
            )
        previous = candidate
        diagnostic = result.output or "compiler failed without diagnostic output"
        print(f"attempt {attempt}/{attempts} failed validation", file=sys.stderr)

    object_output.unlink(missing_ok=True)
    raise MiniREError(f"candidate did not compile after {attempts} attempts:\n{diagnostic}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mini-re",
        description=(
            "Run the mandatory Ghidra -> graph -> dual review -> deterministic "
            "verification -> parity -> overlay build/test/runtime pipeline."
        ),
    )
    parser.add_argument("object_file", type=Path, help="input .o or .obj file")
    parser.add_argument("-o", "--source-output", type=Path, help="generated .c/.cpp path")
    parser.add_argument("--provider", choices=("codex", "openai"), default="codex")
    parser.add_argument("--model", default=None, help="provider model name")
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY"))
    parser.add_argument(
        "--openai-api",
        choices=("responses", "chat-completions"),
        default=os.getenv("OPENAI_API_MODE", "responses"),
        help="OpenAI wire protocol (default: Responses API)",
    )
    parser.add_argument("--language", choices=("auto", "c", "c++"), default="auto")
    parser.add_argument("--timeout", type=int, default=300, help="per LLM/compiler command timeout")
    parser.add_argument("--max-evidence-chars", type=int, default=120_000)
    parser.add_argument("--dump-evidence", action="store_true", help="print evidence and exit without an LLM call")
    parser.add_argument("--checker-provider", choices=("codex", "openai"))
    parser.add_argument("--checker-model", help="independent checker model name")
    parser.add_argument("--checker-base-url", help="checker OpenAI-compatible base URL")
    parser.add_argument(
        "--checker-openai-api",
        choices=("responses", "chat-completions"),
        default=os.getenv("MINI_RE_CHECKER_OPENAI_API"),
    )
    parser.add_argument(
        "--checker-api-key",
        default=os.getenv("MINI_RE_CHECKER_API_KEY"),
        help="checker API key (prefer MINI_RE_CHECKER_API_KEY)",
    )
    parser.add_argument("--review-rounds", type=int, default=3)
    parser.add_argument("--ghidra-cli", help="ghidra-ai-bridge compatible CLI executable")
    parser.add_argument("--ghidra-timeout", type=int, default=45)
    parser.add_argument("--address", help="target function address passed to Ghidra")
    parser.add_argument("--project-root", type=Path, help="project copied into an isolated overlay")
    parser.add_argument("--source-file", type=Path, help="target source file, relative to project root")
    parser.add_argument("--function", dest="function_name", help="unique function name to replace")
    parser.add_argument(
        "--function-signature",
        help="complete source signature used to disambiguate overloads",
    )
    parser.add_argument(
        "--address-map",
        type=Path,
        help="JSON map from function address to source_file/function/signature",
    )
    parser.add_argument(
        "--build-command",
        action="append",
        default=[],
        help="project-owned overlay build gate; may be repeated",
    )
    parser.add_argument(
        "--test-command",
        action="append",
        default=[],
        help="project-owned overlay test gate; may be repeated",
    )
    parser.add_argument(
        "--runtime-command",
        action="append",
        default=[],
        help="project-owned overlay runtime gate; may be repeated",
    )
    parser.add_argument("--require-tests", action="store_true")
    parser.add_argument("--require-runtime", action="store_true")
    parser.add_argument(
        "--parity-fail-on-yellow",
        action="store_true",
        help="make YELLOW parity findings block acceptance (RED always blocks)",
    )
    parser.add_argument("--reports-dir", type=Path, default=Path("reports/mini-re"))
    parser.add_argument("--keep-overlay", action="store_true")
    return parser


def _provider_from_args(
    provider_name: str,
    model: Optional[str],
    timeout: int,
    base_url: str,
    api_key: Optional[str],
    openai_api: str,
) -> Callable[[str], str]:
    if provider_name == "codex":
        return codex_provider(model, timeout)
    if not api_key and base_url.rstrip("/").startswith("https://api.openai.com/v1"):
        raise MiniREError("an API key is required for the OpenAI API")
    return openai_compat_provider(
        model or "gpt-4o", timeout, base_url, api_key, api_mode=openai_api
    )


def _validate_full_pipeline_args(args: argparse.Namespace) -> None:
    required = {
        "--model": args.model,
        "--checker-model": args.checker_model,
        "--ghidra-cli": args.ghidra_cli,
        "--address": args.address,
        "--project-root": args.project_root,
        "--build-command": args.build_command,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise MiniREError(
            "the mandatory full pipeline is missing: " + ", ".join(missing)
        )
    if not args.address_map and (not args.source_file or not args.function_name):
        raise MiniREError(
            "the mandatory full pipeline requires --source-file and --function, "
            "or an --address-map entry"
        )
    if args.require_tests and not args.test_command:
        raise MiniREError("--require-tests requires at least one --test-command")
    if args.require_runtime and not args.runtime_command:
        raise MiniREError("--require-runtime requires at least one --runtime-command")
    if args.review_rounds < 2:
        raise MiniREError("--review-rounds must be at least 2 for bounded repair")
    checker_provider = args.checker_provider or args.provider
    if checker_provider == args.provider and args.checker_model == args.model:
        raise MiniREError(
            "reverser and checker must use different models when they share a provider"
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = collect_evidence(args.object_file, args.max_evidence_chars)
        if args.dump_evidence:
            print(evidence.render())
            return 0

        _validate_full_pipeline_args(args)

        language = evidence.language if args.language == "auto" else args.language
        suffix = ".cpp" if language == "c++" else ".c"
        source_output = args.source_output or Path("out") / (args.object_file.stem + ".recovered" + suffix)
        object_output = Path("out") / (args.object_file.stem + ".recovered.o")

        provider = _provider_from_args(
            args.provider,
            args.model,
            args.timeout,
            args.base_url,
            args.api_key,
            args.openai_api,
        )

        from advanced import GhidraBridge, run_review_pipeline

        checker_provider_name = args.checker_provider or args.provider
        checker_base_url = args.checker_base_url or args.base_url
        checker_api_key = args.checker_api_key or args.api_key
        checker = _provider_from_args(
            checker_provider_name,
            args.checker_model,
            args.timeout,
            checker_base_url,
            checker_api_key,
            args.checker_openai_api or args.openai_api,
        )
        bridge = GhidraBridge(
            args.ghidra_cli,
            args.project_root.resolve(),
            args.ghidra_timeout,
            strict=True,
        )
        run_review_pipeline(
            args.object_file,
            source_output,
            object_output,
            provider,
            checker,
            args.reports_dir,
            review_rounds=args.review_rounds,
            language=args.language,
            timeout=args.timeout,
            max_evidence_chars=args.max_evidence_chars,
            ghidra_bridge=bridge,
            address=args.address,
            project_root=args.project_root,
            source_file=args.source_file,
            function_name=args.function_name,
            function_signature=args.function_signature,
            address_map=args.address_map,
            build_commands=args.build_command,
            test_commands=args.test_command,
            runtime_commands=args.runtime_command,
            require_tests=args.require_tests,
            require_runtime=args.require_runtime,
            parity_fail_on_yellow=args.parity_fail_on_yellow,
            keep_overlay=args.keep_overlay,
        )
        return 0
    except MiniREError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
