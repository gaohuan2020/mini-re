"""Advanced mini-re pipeline: Ghidra, knowledge graph, dual review, and overlays."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from mini_re import (
    Evidence,
    MiniREError,
    collect_evidence,
    compile_source,
    defined_global_symbols,
    extract_code,
    object_global_symbols,
)
from verifiers import ObjectiveVerdict, ParityReport, run_parity_engine, verify_objective


@dataclass(frozen=True)
class GhidraEvidence:
    address: str
    artifacts: dict[str, str]

    def render(self, max_chars: int = 80_000) -> str:
        parts = []
        for name, content in self.artifacts.items():
            parts.append(f"## Ghidra {name}\n{content}")
        return "\n\n".join(parts)[:max_chars]


@dataclass(frozen=True)
class ReviewVerdict:
    verdict: str
    summary: str
    issues: list[str]
    fix_instructions: list[str]


@dataclass(frozen=True)
class GateResult:
    kind: str
    command: str
    status: str
    exit_code: Optional[int]
    output: str
    elapsed_seconds: float


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    summary: str
    output: str = ""
    overlay_root: Optional[Path] = None
    gates: tuple[GateResult, ...] = ()


@dataclass(frozen=True)
class FunctionLocation:
    path: Path
    body_start: int
    body_end: int
    line: int
    context: str
    signature: str
    qualified_name: str


@dataclass(frozen=True)
class TargetSourceSpec:
    source_file: Path
    function_name: str
    signature: Optional[str]
    address_map: Optional[Path] = None


class GhidraBridge:
    """Small capability-tolerant adapter for the ghidra-ai-bridge CLI."""

    OPTIONAL_COMMANDS = (
        ("assembly", "asm"),
        ("context", "context"),
        ("pcode", "pcode"),
        ("cfg", "cfg"),
        ("xrefs_from", "xrefs-from"),
        ("xrefs_to", "xrefs-to"),
    )

    def __init__(
        self,
        cli_path: str,
        cwd: Path,
        timeout: int = 45,
        strict: bool = False,
    ) -> None:
        self.cli_path = cli_path
        self.cwd = cwd
        self.timeout = timeout
        self.strict = strict
        self._cache: dict[tuple[str, str], Optional[str]] = {}

    def _run(self, command: str, target: str, required: bool) -> Optional[str]:
        key = (command, target)
        if key in self._cache:
            return self._cache[key]
        binary = (
            shutil.which(self.cli_path)
            if os.sep not in self.cli_path
            else str(Path(self.cli_path).resolve())
        )
        if not binary or not Path(binary).exists():
            raise MiniREError(f"Ghidra bridge CLI not found: {self.cli_path}")
        try:
            proc = subprocess.run(
                [binary, command, target],
                cwd=str(self.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            if required:
                raise MiniREError(f"Ghidra command timed out: {command}") from exc
            self._cache[key] = None
            return None
        if proc.returncode != 0:
            if required:
                raise MiniREError(
                    f"Ghidra command failed: {command} {target}\n{proc.stdout[-4000:]}"
                )
            self._cache[key] = None
            return None
        value = proc.stdout.strip()
        self._cache[key] = value or None
        return self._cache[key]

    def collect(self, address: str) -> GhidraEvidence:
        artifacts: dict[str, str] = {}
        decompile = self._run("decompile", address, required=True)
        if not decompile:
            raise MiniREError("Ghidra decompile returned no evidence")
        artifacts["decompile"] = decompile
        for label, command in self.OPTIONAL_COMMANDS:
            content = self._run(command, address, required=self.strict)
            if content:
                artifacts[label] = content
            elif self.strict:
                raise MiniREError(f"Ghidra required command returned no evidence: {command}")
        return GhidraEvidence(address, artifacts)


class KnowledgeGraph:
    """Atomic JSON graph of functions, symbols, calls, globals, and strings."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: list[dict[str, str]] = []
        if path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    self.nodes = dict(payload.get("nodes", {}))
                    self.edges = list(payload.get("edges", []))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass

    @staticmethod
    def _normal_address(value: str) -> str:
        value = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]+", value):
            return "0x" + value.lstrip("0") if int(value, 16) else "0x0"
        if re.fullmatch(r"0x[0-9a-f]+", value):
            return hex(int(value, 16))
        return value

    def _put(self, node_kind: str, node_identity: str, **data: object) -> str:
        node_id = f"{node_kind}:{node_identity}"
        current = self.nodes.get(node_id, {})
        self.nodes[node_id] = {
            **current,
            **data,
            "kind": node_kind,
            "identity": node_identity,
        }
        return node_id

    def _edge(self, source: str, target: str, relation: str) -> None:
        edge = {"source": source, "target": target, "relation": relation}
        if edge not in self.edges:
            self.edges.append(edge)

    def ingest_object(self, object_file: Path, evidence: Evidence) -> None:
        object_node = self._put("object", str(object_file.resolve()), metadata=evidence.metadata)
        for symbol in sorted(defined_global_symbols(evidence.symbols)):
            self._edge(object_node, self._put("symbol", symbol, name=symbol), "defines")
        self.save()

    def ingest_ghidra(self, evidence: GhidraEvidence) -> None:
        address = self._normal_address(evidence.address)
        function_node = self._put("function", address, address=address)
        context = evidence.artifacts.get("context")
        if context:
            try:
                payload = json.loads(context)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                function = payload.get("function")
                if isinstance(function, dict):
                    function_node = self._put("function", address, **function)
                    for callee in function.get("callees", []):
                        if isinstance(callee, dict):
                            raw = str(callee.get("addr") or callee.get("address") or "")
                            if raw:
                                target = self._put("function", self._normal_address(raw), **callee)
                                self._edge(function_node, target, "calls")
                for key, kind, relation in (
                    ("globals", "global", "accesses"),
                    ("strings", "string", "references"),
                ):
                    values = payload.get(key, [])
                    if isinstance(values, list):
                        for item in values:
                            if isinstance(item, dict):
                                identity = str(item.get("address") or item.get("name") or item.get("value") or "")
                                if identity:
                                    self._edge(function_node, self._put(kind, identity, **item), relation)
        for direction, relation in (("xrefs_from", "calls"), ("xrefs_to", "called_by")):
            for raw_address, name in _parse_xrefs(evidence.artifacts.get(direction, "")):
                other = self._put("function", self._normal_address(raw_address), name=name)
                if relation == "calls":
                    self._edge(function_node, other, relation)
                else:
                    self._edge(function_node, other, relation)
        for name, content in evidence.artifacts.items():
            if name not in {"context", "xrefs_from", "xrefs_to"}:
                self._put("artifact", f"{address}:{name}", artifact_type=name, preview=content[:4000])
                self._edge(function_node, f"artifact:{address}:{name}", "has_evidence")
        self.save()

    def neighborhood(self, address: str, max_chars: int = 8000) -> str:
        root = f"function:{self._normal_address(address)}"
        edges = [edge for edge in self.edges if edge.get("source") == root or edge.get("target") == root]
        node_ids = {root}
        for edge in edges:
            node_ids.update((edge["source"], edge["target"]))
        payload = {
            "nodes": {key: self.nodes[key] for key in node_ids if key in self.nodes},
            "edges": edges,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)[:max_chars]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=str(self.path.parent))
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(
                    {"schema_version": 1, "nodes": self.nodes, "edges": self.edges},
                    stream,
                    ensure_ascii=False,
                    indent=2,
                )
                stream.write("\n")
            os.replace(temporary, self.path)
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise


def _parse_xrefs(content: str) -> list[tuple[str, str]]:
    values = []
    for line in content.splitlines():
        match = re.match(r"\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]{4,})\s+(.+?)\s*$", line)
        if match:
            values.append((match.group(1), match.group(2)))
    return values


def _matching_delimiter(text: str, start: int, opening: str, closing: str) -> Optional[int]:
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = start
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char in ("'", '"'):
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def canonical_signature(value: str) -> str:
    """Normalize insignificant whitespace while preserving a full declarator."""
    value = re.sub(r"/\*.*?\*/|//[^\n]*", " ", value, flags=re.DOTALL)
    value = re.sub(r"\s+", " ", value.strip())
    value = re.sub(r"\s*([(),*&<>])\s*", r"\1", value)
    return re.sub(r"\s*::\s*", "::", value)


def _definition_brace(text: str, start: int) -> Optional[int]:
    """Find a definition brace after a parameter list, rejecting call expressions."""
    paren_depth = 0
    bracket_depth = 0
    index = start
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if char == "/" and following == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char == "/" and following == "*":
            closing = text.find("*/", index + 2)
            index = len(text) if closing < 0 else closing + 2
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            if paren_depth == 0:
                return None
            paren_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        elif paren_depth == 0 and bracket_depth == 0:
            if char == "{":
                return index
            if char in ";,=":
                return None
        index += 1
    return None


def _signature_start(text: str, name_start: int) -> int:
    boundary = max(
        text.rfind(";", 0, name_start),
        text.rfind("{", 0, name_start),
        text.rfind("}", 0, name_start),
    )
    start = boundary + 1
    prefix = text[start:name_start]
    access = list(re.finditer(r"(?:public|private|protected)\s*:\s*", prefix))
    if access:
        start += access[-1].end()
    return start


def _qualified_name(signature: str, fallback: str) -> str:
    values = re.findall(
        r"([~A-Za-z_][A-Za-z0-9_]*(?:::[~A-Za-z_][A-Za-z0-9_]*)*)\s*\(", signature
    )
    return values[-1] if values else fallback


def find_function(
    source_file: Path,
    function_name: str,
    signature: Optional[str] = None,
) -> FunctionLocation:
    """Locate exactly one definition, using a complete signature when supplied."""
    text = source_file.read_text(encoding="utf-8", errors="replace")
    token = re.escape(function_name.strip())
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){token}\s*\(")
    matches: list[FunctionLocation] = []
    requested_signature = canonical_signature(signature) if signature else None
    for match in pattern.finditer(text):
        paren = text.find("(", match.start())
        paren_end = _matching_delimiter(text, paren, "(", ")")
        if paren_end is None:
            continue
        body_start = _definition_brace(text, paren_end + 1)
        if body_start is None:
            continue
        closing = _matching_delimiter(text, body_start, "{", "}")
        if closing is None:
            continue
        signature_start = _signature_start(text, match.start())
        raw_signature = text[signature_start:body_start].strip()
        normalized = canonical_signature(raw_signature)
        if requested_signature and not (
            normalized == requested_signature or normalized.endswith(requested_signature)
        ):
            continue
        body_end = closing + 1
        context_start = max(0, text.rfind("\n", 0, max(0, body_start - 5000)))
        context_end = min(len(text), text.find("\n", min(len(text), body_end + 5000)))
        if context_end < 0:
            context_end = len(text)
        matches.append(
            FunctionLocation(
                source_file,
                body_start,
                body_end,
                text.count("\n", 0, body_start) + 1,
                text[context_start:context_end],
                raw_signature,
                _qualified_name(raw_signature, function_name),
            )
        )
    target_label = signature or function_name
    if not matches:
        raise MiniREError(f"function definition not found: {target_label} in {source_file}")
    if len(matches) > 1:
        signatures = "; ".join(item.signature for item in matches)
        raise MiniREError(
            f"ambiguous/overloaded function definition: {target_label} in {source_file}; "
            f"matches: {signatures}; provide --function-signature or --address-map"
        )
    return matches[0]


def _normal_address(value: str) -> str:
    try:
        return hex(int(value.strip(), 16))
    except ValueError:
        return value.strip().lower()


def resolve_target_source(
    project_root: Path,
    address: str,
    source_file: Optional[Path],
    function_name: Optional[str],
    function_signature: Optional[str],
    address_map: Optional[Path],
) -> TargetSourceSpec:
    """Resolve a target from explicit arguments and an optional JSON address map."""
    map_source: Optional[Path] = None
    map_name: Optional[str] = None
    map_signature: Optional[str] = None
    if address_map is not None:
        map_path = address_map if address_map.is_absolute() else project_root / address_map
        try:
            payload = json.loads(map_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MiniREError(f"could not read address map {map_path}: {exc}") from exc
        functions = payload.get("functions", payload) if isinstance(payload, dict) else payload
        entry: Optional[dict[str, object]] = None
        normalized_address = _normal_address(address)
        if isinstance(functions, dict):
            for raw_address, value in functions.items():
                if _normal_address(str(raw_address)) == normalized_address and isinstance(value, dict):
                    entry = value
                    break
        elif isinstance(functions, list):
            for value in functions:
                if (
                    isinstance(value, dict)
                    and _normal_address(str(value.get("address", ""))) == normalized_address
                ):
                    entry = value
                    break
        if entry is None:
            raise MiniREError(f"address {address} not found in address map {map_path}")
        raw_path = entry.get("source_file", entry.get("path"))
        raw_name = entry.get("function", entry.get("name", entry.get("qualified_name")))
        raw_signature = entry.get("signature")
        map_source = Path(str(raw_path)) if raw_path else None
        map_name = str(raw_name) if raw_name else None
        map_signature = str(raw_signature) if raw_signature else None
        address_map = map_path

    if source_file is not None and map_source is not None:
        explicit_path = source_file if source_file.is_absolute() else project_root / source_file
        mapped_path = map_source if map_source.is_absolute() else project_root / map_source
        if explicit_path.resolve() != mapped_path.resolve():
            raise MiniREError(f"--source-file conflicts with address map: {source_file} != {map_source}")
    if function_name and map_name and function_name != map_name:
        raise MiniREError(f"--function conflicts with address map: {function_name} != {map_name}")
    if (
        function_signature
        and map_signature
        and canonical_signature(function_signature) != canonical_signature(map_signature)
    ):
        raise MiniREError("--function-signature conflicts with address map")

    resolved_source = source_file or map_source
    resolved_name = function_name or map_name
    resolved_signature = function_signature or map_signature
    if resolved_source is None or resolved_name is None:
        raise MiniREError(
            "target source requires --source-file and --function, or an --address-map entry containing both"
        )
    resolved_source = resolved_source if resolved_source.is_absolute() else project_root / resolved_source
    try:
        resolved_source.resolve().relative_to(project_root.resolve())
    except ValueError as exc:
        raise MiniREError(f"mapped source file is outside project root: {resolved_source}") from exc
    return TargetSourceSpec(resolved_source, resolved_name, resolved_signature, address_map)


def extract_function_body(candidate: str) -> str:
    opening = candidate.find("{")
    if opening < 0:
        raise MiniREError("candidate does not contain a function body")
    closing = _matching_delimiter(candidate, opening, "{", "}")
    if closing is None:
        raise MiniREError("candidate function body has unbalanced braces")
    return candidate[opening : closing + 1]


def create_project_overlay(
    project_root: Path,
    source_file: Path,
    location: FunctionLocation,
    candidate: str,
    reports_dir: Path,
) -> tuple[Path, Path]:
    """Copy the full project and replace only the selected function body."""
    project_root = project_root.resolve()
    source_file = source_file.resolve()
    try:
        relative_source = source_file.relative_to(project_root)
    except ValueError as exc:
        raise MiniREError(f"source file is outside project root: {source_file}") from exc
    overlay_parent = reports_dir / "overlays"
    overlay_parent.mkdir(parents=True, exist_ok=True)
    overlay_root = Path(tempfile.mkdtemp(prefix="overlay-", dir=str(overlay_parent)))
    try:
        shutil.copytree(
            project_root,
            overlay_root,
            dirs_exist_ok=True,
            symlinks=True,
            ignore=shutil.ignore_patterns(
                ".git", ".venv", "build", "reports", "outputs", "work", "__pycache__", "*.pyc"
            ),
        )
        (overlay_root / ".mini-re-overlay").write_text("schema_version=1\n", encoding="utf-8")
        overlay_source = overlay_root / relative_source
        text = overlay_source.read_text(encoding="utf-8", errors="replace")
        body = extract_function_body(candidate)
        patched = text[: location.body_start] + body + text[location.body_end :]
        overlay_source.write_text(patched, encoding="utf-8")
        return overlay_root, overlay_source
    except Exception:
        shutil.rmtree(overlay_root, ignore_errors=True)
        raise


def validate_project_overlay(
    project_root: Path,
    source_file: Path,
    location: FunctionLocation,
    candidate: str,
    reports_dir: Path,
    build_commands: Sequence[str],
    timeout: int,
    keep_overlay: bool,
    test_commands: Sequence[str] = (),
    runtime_commands: Sequence[str] = (),
    require_build: bool = True,
    require_tests: bool = False,
    require_runtime: bool = False,
) -> ValidationResult:
    missing = []
    if require_build and not build_commands:
        missing.append("build")
    if require_tests and not test_commands:
        missing.append("test")
    if require_runtime and not runtime_commands:
        missing.append("runtime")
    if missing:
        return ValidationResult(
            False,
            "required project overlay gates are not configured: " + ", ".join(missing),
        )
    commands = [*(('build', value) for value in build_commands)]
    commands.extend(('test', value) for value in test_commands)
    commands.extend(('runtime', value) for value in runtime_commands)
    if not commands:
        return ValidationResult(False, "project overlay requires at least one validation command")
    overlay_root, overlay_source = create_project_overlay(
        project_root, source_file, location, candidate, reports_dir
    )
    env = os.environ.copy()
    env.update(
        {
            "MINI_RE_OVERLAY_ROOT": str(overlay_root),
            "MINI_RE_CANDIDATE_FILE": str(overlay_source),
            "MINI_RE_SOURCE_FILE": str(source_file),
        }
    )
    findings: list[str] = []
    gates: list[GateResult] = []
    ok = True
    try:
        for command_index, (kind, command) in enumerate(commands):
            expanded = command.replace("{overlay_root}", str(overlay_root)).replace(
                "{candidate_file}", str(overlay_source)
            )
            started = time.monotonic()
            try:
                proc = subprocess.run(
                    ["/bin/sh", "-lc", expanded],
                    cwd=str(overlay_root),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                message = f"[{kind}] timed out: {command}"
                findings.append(message)
                gates.append(GateResult(kind, command, "FAIL", None, message, elapsed))
                ok = False
                for skipped_kind, skipped_command in commands[command_index + 1 :]:
                    gates.append(
                        GateResult(
                            skipped_kind,
                            skipped_command,
                            "SKIP",
                            None,
                            "skipped because an earlier gate failed",
                            0.0,
                        )
                    )
                break
            elapsed = time.monotonic() - started
            tail = proc.stdout[-8000:]
            status = "PASS" if proc.returncode == 0 else "FAIL"
            gates.append(GateResult(kind, command, status, proc.returncode, tail, elapsed))
            findings.append(f"[{kind}] $ {command}\n{tail}".rstrip())
            if proc.returncode != 0:
                findings.append(f"[{kind}] exit code: {proc.returncode}")
                ok = False
                for skipped_kind, skipped_command in commands[command_index + 1 :]:
                    gates.append(
                        GateResult(
                            skipped_kind,
                            skipped_command,
                            "SKIP",
                            None,
                            "skipped because an earlier gate failed",
                            0.0,
                        )
                    )
                break
        summary = (
            "all configured project overlay build/test/runtime gates passed"
            if ok
            else "project overlay build/test/runtime gate failed"
        )
        visible_root = overlay_root if keep_overlay else None
        return ValidationResult(ok, summary, "\n\n".join(findings), visible_root, tuple(gates))
    finally:
        if not keep_overlay:
            shutil.rmtree(overlay_root, ignore_errors=True)


def parse_checker_verdict(response: str) -> ReviewVerdict:
    text = response.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ReviewVerdict("UNKNOWN", "checker did not return valid JSON", [], [])
    if not isinstance(payload, dict):
        return ReviewVerdict("UNKNOWN", "checker returned a non-object JSON value", [], [])
    verdict = str(payload.get("verdict", "UNKNOWN")).upper()
    if verdict not in {"PASS", "FAIL"}:
        verdict = "UNKNOWN"
    issues = payload.get("issues", [])
    fixes = payload.get("fix_instructions", [])
    return ReviewVerdict(
        verdict,
        str(payload.get("summary", "")),
        [str(value) for value in issues] if isinstance(issues, list) else [],
        [str(value) for value in fixes] if isinstance(fixes, list) else [],
    )


def _reverser_prompt(
    evidence: Evidence,
    ghidra: Optional[GhidraEvidence],
    graph_context: str,
    function_name: Optional[str],
    function_signature: Optional[str],
    source_context: str,
    previous_candidate: str,
    feedback: str,
    project_mode: bool,
) -> str:
    output_requirement = (
        "Return exactly one complete definition of the target function in a single fenced code block."
        if project_mode
        else "Return exactly one complete translation unit in a single fenced code block."
    )
    prompt = f"""You are the reverser model in a bounded native-code reconstruction workflow.

{output_requirement} Preserve observable behavior supported by the evidence: symbol/signature, integer widths, signedness, branches, calls, constants, memory offsets, floating-point expression order, and side effects. Do not invent confident types or names when evidence is absent. The result must compile. Do not include prose outside the code block.

Target function: {function_name or '(whole object translation unit)'}
Target source signature: {function_signature or '(not supplied)'}

## Object evidence
{evidence.render()}
"""
    if ghidra:
        prompt += "\n\n" + ghidra.render()
    if graph_context:
        prompt += "\n\n## Persistent knowledge graph neighborhood\n" + graph_context
    if source_context:
        prompt += "\n\n## Nearby original project source\n```\n" + source_context + "\n```"
    if previous_candidate:
        prompt += "\n\n## Previous candidate to repair\n```\n" + previous_candidate.rstrip() + "\n```"
    if feedback:
        prompt += "\n\n## Required repairs from the previous round\n" + feedback
    return prompt


def _checker_prompt(
    candidate: str,
    evidence: Evidence,
    ghidra: Optional[GhidraEvidence],
    function_name: Optional[str],
    function_signature: Optional[str],
) -> str:
    ground_truth = "## Object evidence\n" + evidence.render()
    if ghidra:
        ground_truth += "\n\n" + ghidra.render()
    return f"""You are the independent checker model. Verify the candidate against the supplied binary evidence. Check every supported branch, call, constant, memory offset, signedness choice, expression order, exported symbol/signature, and edge case. Be conservative: missing evidence is not proof of correctness.

Target: {function_name or '(whole object translation unit)'}
Target source signature: {function_signature or '(not supplied)'}

## Candidate
```\n{candidate.rstrip()}\n```

## Ground-truth evidence
{ground_truth}

Return one JSON object and nothing else:
{{"verdict":"PASS or FAIL","summary":"one line","issues":["specific issue"],"fix_instructions":["concrete action"]}}
"""


def _write_round_log(
    reports_dir: Path,
    round_number: int,
    reverser_prompt: str,
    reverser_response: str,
    checker_prompt: str,
    checker_response: str,
    verdict: ReviewVerdict,
    objective: ObjectiveVerdict,
    parity: ParityReport,
    validation: Optional[ValidationResult],
) -> None:
    logs = reports_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    payload = {
        "round": round_number,
        "reverser": {"prompt": reverser_prompt, "response": reverser_response},
        "checker": {
            "prompt": checker_prompt,
            "response": checker_response,
            "verdict": verdict.verdict,
            "summary": verdict.summary,
            "issues": verdict.issues,
            "fix_instructions": verdict.fix_instructions,
        },
        "objective": {
            "verdict": objective.verdict,
            "summary": objective.summary,
            "findings": list(objective.findings),
            "checks": list(objective.checks),
        },
        "parity": {
            "status": parity.status,
            "findings": list(parity.findings),
            "signals": [
                {
                    "signal": item.signal,
                    "level": item.level,
                    "triggered": item.triggered,
                    "detail": item.detail,
                }
                for item in parity.signals
            ],
        },
        "validation": None
        if validation is None
        else {
            "ok": validation.ok,
            "summary": validation.summary,
            "output": validation.output,
            "overlay_root": str(validation.overlay_root) if validation.overlay_root else None,
            "gates": [
                {
                    "kind": gate.kind,
                    "command": gate.command,
                    "status": gate.status,
                    "exit_code": gate.exit_code,
                    "output": gate.output,
                    "elapsed_seconds": round(gate.elapsed_seconds, 6),
                }
                for gate in validation.gates
            ],
        },
    }
    path = logs / f"round-{round_number:02d}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_review_pipeline(
    object_file: Path,
    source_output: Path,
    object_output: Path,
    reverser: Callable[[str], str],
    checker: Callable[[str], str],
    reports_dir: Path,
    review_rounds: int = 3,
    language: str = "auto",
    compiler: Optional[str] = None,
    timeout: int = 300,
    max_evidence_chars: int = 120_000,
    ghidra_bridge: Optional[GhidraBridge] = None,
    address: Optional[str] = None,
    project_root: Optional[Path] = None,
    source_file: Optional[Path] = None,
    function_name: Optional[str] = None,
    function_signature: Optional[str] = None,
    address_map: Optional[Path] = None,
    build_commands: Sequence[str] = (),
    test_commands: Sequence[str] = (),
    runtime_commands: Sequence[str] = (),
    require_tests: bool = False,
    require_runtime: bool = False,
    parity_fail_on_yellow: bool = False,
    keep_overlay: bool = False,
) -> int:
    """Run the bounded dual-model loop with deterministic checks and all gates."""
    if review_rounds < 1:
        raise MiniREError("--review-rounds must be at least 1")
    project_mode = any(
        value is not None
        for value in (project_root, source_file, function_name, function_signature, address_map)
    )
    if project_mode and project_root is None:
        raise MiniREError("project overlay requires --project-root")
    if ghidra_bridge and not address:
        raise MiniREError("--ghidra-cli requires --address")

    evidence = collect_evidence(object_file, max_evidence_chars)
    if language != "auto":
        evidence = Evidence(evidence.metadata, evidence.symbols, evidence.disassembly, language)
    ghidra = ghidra_bridge.collect(address) if ghidra_bridge and address else None
    reports_dir.mkdir(parents=True, exist_ok=True)
    graph = KnowledgeGraph(reports_dir / "knowledge-graph.json")
    graph.ingest_object(object_file, evidence)
    if ghidra:
        graph.ingest_ghidra(ghidra)

    location: Optional[FunctionLocation] = None
    source_context = ""
    if project_mode:
        assert project_root is not None and address is not None
        project_root = project_root.resolve()
        spec = resolve_target_source(
            project_root,
            address,
            source_file,
            function_name,
            function_signature,
            address_map,
        )
        source_file = spec.source_file
        function_name = spec.function_name
        function_signature = spec.signature
        address_map = spec.address_map
        location = find_function(source_file, function_name, function_signature)
        function_signature = location.signature
        source_context = location.context

    graph_context = graph.neighborhood(address) if address else ""
    feedback = ""
    previous_candidate = ""
    final_validation: Optional[ValidationResult] = None
    final_objective: Optional[ObjectiveVerdict] = None
    final_parity: Optional[ParityReport] = None
    source_output.parent.mkdir(parents=True, exist_ok=True)
    object_output.parent.mkdir(parents=True, exist_ok=True)

    for round_number in range(1, review_rounds + 1):
        reverse_prompt = _reverser_prompt(
            evidence,
            ghidra,
            graph_context,
            function_name,
            function_signature,
            source_context,
            previous_candidate,
            feedback,
            project_mode,
        )
        reverse_response = reverser(reverse_prompt)
        candidate = extract_code(reverse_response)
        source_output.write_text(candidate, encoding="utf-8")

        check_prompt = _checker_prompt(
            candidate, evidence, ghidra, function_name, function_signature
        )
        check_response = checker(check_prompt)
        verdict = parse_checker_verdict(check_response)
        objective = verify_objective(candidate, ghidra.artifacts if ghidra else {})
        parity = run_parity_engine(candidate, ghidra.artifacts if ghidra else {})
        final_objective = objective
        final_parity = parity
        if project_mode:
            try:
                assert project_root is not None and source_file is not None and location is not None
                validation = validate_project_overlay(
                    project_root,
                    source_file,
                    location,
                    candidate,
                    reports_dir,
                    build_commands,
                    timeout,
                    keep_overlay,
                    test_commands=test_commands,
                    runtime_commands=runtime_commands,
                    require_tests=require_tests,
                    require_runtime=require_runtime,
                )
            except MiniREError as exc:
                validation = ValidationResult(
                    False, "project overlay validation setup failed", str(exc)
                )
        else:
            compiled = compile_source(
                source_output, object_output, evidence.language, compiler=compiler, timeout=timeout
            )
            if compiled.ok:
                missing = sorted(
                    defined_global_symbols(evidence.symbols) - object_global_symbols(object_output)
                )
            else:
                missing = []
            ok = compiled.ok and not missing
            output = compiled.output
            if missing:
                output += "\nmissing global symbols: " + ", ".join(missing)
            validation = ValidationResult(
                ok,
                "standalone compile gate passed" if ok else "standalone compile gate failed",
                output,
                gates=(
                    GateResult(
                        "build",
                        "standalone compiler",
                        "PASS" if ok else "FAIL",
                        0 if ok else 1,
                        output,
                        0.0,
                    ),
                ),
            )
        final_validation = validation

        _write_round_log(
            reports_dir,
            round_number,
            reverse_prompt,
            reverse_response,
            check_prompt,
            check_response,
            verdict,
            objective,
            parity,
            validation,
        )

        parity_accepted = parity.status != "RED" and not (
            parity_fail_on_yellow and parity.status == "YELLOW"
        )
        if (
            verdict.verdict == "PASS"
            and objective.verdict == "PASS"
            and parity_accepted
            and validation
            and validation.ok
        ):
            result = {
                "success": True,
                "rounds": round_number,
                "checker": verdict.verdict,
                "objective": objective.verdict,
                "parity": parity.status,
                "validation": validation.summary,
                "source": str(source_output),
                "target_source": str(source_file) if source_file else None,
                "target_function": function_name,
                "target_signature": function_signature,
                "address_map": str(address_map) if address_map else None,
                "object": None if project_mode else str(object_output),
                "overlay_root": str(validation.overlay_root) if validation.overlay_root else None,
                "knowledge_graph": str(graph.path),
            }
            (reports_dir / "result.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            print(
                "PASS: checker, objective verifier, parity policy, and validation "
                f"passed on round {round_number}"
            )
            print(f"source: {source_output}")
            print(f"report: {reports_dir / 'result.json'}")
            if validation.overlay_root:
                print(f"overlay: {validation.overlay_root}")
            elif project_mode:
                print("overlay: removed after successful isolated validation")
            else:
                print(f"object: {object_output}")
            return round_number

        feedback_parts = [
            f"Checker verdict: {verdict.verdict}",
            f"Checker summary: {verdict.summary}",
        ]
        feedback_parts.extend(f"Issue: {value}" for value in verdict.issues)
        feedback_parts.extend(f"Fix: {value}" for value in verdict.fix_instructions)
        feedback_parts.append(
            f"Objective verifier: {objective.verdict} — {objective.summary}"
        )
        feedback_parts.extend(f"Objective finding: {value}" for value in objective.findings)
        feedback_parts.append(
            f"Parity: {parity.status} — "
            + ("; ".join(parity.findings) if parity.findings else "no triggered signals")
        )
        feedback_parts.append(
            "Validation: "
            + ("PASS" if validation.ok else "FAIL")
            + f" — {validation.summary}\n{validation.output[-8000:]}"
        )
        feedback = "\n".join(feedback_parts)
        previous_candidate = candidate
        print(f"round {round_number}/{review_rounds} failed review or validation")

    object_output.unlink(missing_ok=True)
    result = {
        "success": False,
        "rounds": review_rounds,
        "objective": final_objective.verdict if final_objective else None,
        "parity": final_parity.status if final_parity else None,
        "validation": final_validation.summary if final_validation else None,
        "source": str(source_output),
        "knowledge_graph": str(graph.path),
    }
    (reports_dir / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    raise MiniREError(f"dual-model review pipeline failed after {review_rounds} rounds")
