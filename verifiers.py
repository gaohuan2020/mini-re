"""Deterministic structural and parity verification for reconstructed functions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ObjectiveVerdict:
    verdict: str
    summary: str
    findings: tuple[str, ...]
    checks: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class ParitySignalResult:
    signal: str
    level: str
    triggered: bool
    detail: str


@dataclass(frozen=True)
class ParityReport:
    status: str
    signals: tuple[ParitySignalResult, ...]

    @property
    def findings(self) -> tuple[str, ...]:
        return tuple(
            f"{item.level}: {item.signal}: {item.detail}"
            for item in self.signals
            if item.triggered
        )


_CONTROL_RE = re.compile(r"\b(if|for|while|switch|case|catch)\b|\?")
_LOOP_RE = re.compile(r"\b(for|while|do)\b")
_CALL_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_:]*)\s*\(")
_CALL_EXCLUDES = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "alignof",
    "decltype",
    "static_cast",
    "reinterpret_cast",
    "const_cast",
    "dynamic_cast",
}
_STUB_RE = re.compile(
    r"\b(TODO|FIXME|unimplemented|not implemented|stub|abort\s*\(|__builtin_trap\s*\()",
    re.IGNORECASE,
)
_FP_SOURCE_RE = re.compile(
    r"\b(float|double|isnan|isfinite|isinf|sqrt|sin|cos|tan|pow|fabs|fma)\b|"
    r"\d+\.\d+(?:[eE][+-]?\d+)?[fFlL]?"
)
_FP_ASM_RE = re.compile(
    r"\b(?:fadd|fsub|fmul|fdiv|fcmp|ucomis[sd]|comis[sd]|add[sp]d|mul[sp]d|div[sp]d|sqrt[sp]d)\b",
    re.IGNORECASE,
)
_NAN_RE = re.compile(r"\b(?:isnan|nan|ucomis[sd]|fcmp)\b", re.IGNORECASE)


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def _body(text: str) -> str:
    opening = text.find("{")
    closing = text.rfind("}")
    if opening >= 0 and closing > opening:
        return text[opening + 1 : closing]
    return text


def _calls(text: str) -> list[str]:
    return [name for name in _CALL_RE.findall(text) if name not in _CALL_EXCLUDES]


def _statement_count(text: str) -> int:
    return text.count(";") + len(re.findall(r"\b(case|default)\b", text))


def _asm_call_count(assembly: str) -> int:
    count = 0
    for line in assembly.splitlines():
        instruction = re.sub(r"^\s*(?:0x)?[0-9a-fA-F]+:?\s*", "", line).strip()
        if re.search(r"^(?:callq?|bl|blr)\b", instruction, re.IGNORECASE):
            count += 1
    return count


def _asm_conditional_count(assembly: str) -> int:
    count = 0
    for line in assembly.splitlines():
        instruction = re.sub(r"^\s*(?:0x)?[0-9a-fA-F]+:?\s*", "", line).strip()
        if re.search(
            r"^(?:j(?!mp)[a-z]+|b\.(?!al\b)[a-z]+|cbz|cbnz|tbz|tbnz)\b",
            instruction,
            re.IGNORECASE,
        ):
            count += 1
    return count


def _cfg_metrics(raw: str) -> tuple[int, int, bool]:
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return 0, 0, False
    if isinstance(payload, dict):
        blocks = payload.get("blocks", [])
        edges = payload.get("edges", [])
    elif isinstance(payload, list):
        blocks = payload
        edges = []
    else:
        return 0, 0, False
    block_count = len(blocks) if isinstance(blocks, list) else 0
    edge_count = len(edges) if isinstance(edges, list) else 0
    has_cycle = False
    if isinstance(edges, list):
        for edge in edges:
            if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                left, right = edge[0], edge[1]
                if isinstance(left, int) and isinstance(right, int) and right <= left:
                    has_cycle = True
            elif isinstance(edge, dict):
                left = edge.get("source", edge.get("from"))
                right = edge.get("target", edge.get("to"))
                if isinstance(left, int) and isinstance(right, int) and right <= left:
                    has_cycle = True
    return block_count, edge_count, has_cycle


def verify_objective(
    candidate: str,
    artifacts: Mapping[str, str],
    *,
    call_tolerance: int = 2,
    control_flow_tolerance: int = 1,
    block_tolerance: int = 3,
) -> ObjectiveVerdict:
    """Compare candidate structure with decompile/ASM/P-code/CFG evidence.

    The verifier deliberately emits FAIL only for strong, directional omissions.
    It never claims binary or semantic equivalence.
    """
    if not candidate.strip():
        return ObjectiveVerdict("FAIL", "candidate is empty", ("no candidate code",), ())

    source = _strip_comments(_body(candidate))
    decompile = _strip_comments(artifacts.get("decompile", ""))
    assembly = artifacts.get("assembly", "")
    pcode = artifacts.get("pcode", "")
    cfg = artifacts.get("cfg", "")

    source_calls = len(_calls(source))
    source_flow = len(_CONTROL_RE.findall(source))
    source_loops = len(_LOOP_RE.findall(source))
    source_returns = len(re.findall(r"\breturn\b", source))
    source_switches = len(re.findall(r"\bswitch\b", source))

    decompile_calls = len(_calls(_body(decompile)))
    decompile_flow = len(_CONTROL_RE.findall(decompile))
    evidence_loops = len(_LOOP_RE.findall(decompile))
    evidence_switches = len(re.findall(r"\bswitch\b", decompile))
    asm_calls = _asm_call_count(assembly)
    asm_flow = _asm_conditional_count(assembly)
    pcode_calls = len(re.findall(r"\bCALL(?:IND)?\b", pcode, re.IGNORECASE))
    pcode_branches = len(re.findall(r"\bCBRANCH\b", pcode, re.IGNORECASE))
    pcode_returns = len(re.findall(r"\bRETURN\b", pcode, re.IGNORECASE))
    if re.search(r"\b(?:BRANCHIND|switch)\b", pcode, re.IGNORECASE):
        evidence_switches = max(evidence_switches, 1)
    cfg_blocks, cfg_edges, cfg_cycle = _cfg_metrics(cfg)
    if re.search(r"\bswitch\b", cfg, re.IGNORECASE):
        evidence_switches = max(evidence_switches, 1)
    if cfg_cycle:
        evidence_loops = max(evidence_loops, 1)

    checks: list[dict[str, object]] = []
    findings: list[str] = []

    def compare(name: str, candidate_value: int, evidence_value: int, tolerance: int, detail: str) -> None:
        failed = evidence_value - candidate_value >= tolerance
        checks.append(
            {
                "name": name,
                "candidate": candidate_value,
                "evidence": evidence_value,
                "tolerance": tolerance,
                "status": "FAIL" if failed else "PASS",
            }
        )
        if failed:
            findings.append(detail.format(candidate=candidate_value, evidence=evidence_value))

    compare(
        "call_count",
        source_calls,
        max(decompile_calls, asm_calls, pcode_calls),
        call_tolerance,
        "candidate has {candidate} calls but binary evidence has at least {evidence}",
    )
    compare(
        "control_flow",
        source_flow,
        max(decompile_flow, asm_flow, pcode_branches),
        control_flow_tolerance,
        "candidate has {candidate} control-flow constructs but evidence has at least {evidence}",
    )
    if cfg_blocks:
        candidate_blocks = source_flow + 1
        compare(
            "cfg_blocks",
            candidate_blocks,
            cfg_blocks,
            block_tolerance,
            "candidate implies about {candidate} blocks but Ghidra CFG has {evidence}",
        )

    loop_failed = evidence_loops > 0 and source_loops == 0
    checks.append(
        {
            "name": "loop_presence",
            "candidate": source_loops,
            "evidence": evidence_loops,
            "status": "FAIL" if loop_failed else "PASS",
        }
    )
    if loop_failed:
        findings.append("binary evidence contains a loop but the candidate contains none")

    switch_failed = evidence_switches > 0 and source_switches == 0
    checks.append(
        {
            "name": "switch_presence",
            "candidate": source_switches,
            "evidence": evidence_switches,
            "status": "FAIL" if switch_failed else "PASS",
        }
    )
    if switch_failed:
        findings.append("binary evidence contains switch/indirect-branch logic but the candidate contains no switch")

    return_failed = pcode_returns >= 2 and source_returns == 0
    checks.append(
        {
            "name": "return_presence",
            "candidate": source_returns,
            "evidence": pcode_returns,
            "status": "FAIL" if return_failed else "PASS",
        }
    )
    if return_failed:
        findings.append("P-code contains multiple returns but the candidate has no explicit return")

    checks.append(
        {
            "name": "cfg_edges",
            "candidate": None,
            "evidence": cfg_edges,
            "status": "OBSERVED" if cfg_edges else "UNAVAILABLE",
        }
    )

    if findings:
        return ObjectiveVerdict(
            "FAIL",
            "deterministic objective verifier found structural omissions",
            tuple(findings),
            tuple(checks),
        )
    return ObjectiveVerdict(
        "PASS",
        "deterministic objective verifier found no strong structural mismatch",
        (),
        tuple(checks),
    )


def run_parity_engine(
    candidate: str,
    artifacts: Mapping[str, str],
    *,
    large_asm_threshold: int = 30,
    short_body_lines: int = 6,
    call_tolerance: int = 3,
) -> ParityReport:
    """Run the fixed set of eleven conservative parity signals."""
    source = _strip_comments(_body(candidate))
    decompile = _strip_comments(artifacts.get("decompile", ""))
    assembly = artifacts.get("assembly", "")
    lines = [line.strip() for line in source.splitlines() if line.strip()]
    calls = _calls(source)
    decompile_calls = _calls(_body(decompile))
    asm_calls = _asm_call_count(assembly)
    control_count = len(_CONTROL_RE.findall(source))
    statement_count = _statement_count(source)
    asm_lines = [line for line in assembly.splitlines() if line.strip()]

    def signal(name: str, level: str, triggered: bool, detail: str) -> ParitySignalResult:
        return ParitySignalResult(name, level, bool(triggered), detail)

    missing_source = not source.strip()
    stub_markers = bool(_STUB_RE.search(source))
    trivial_stub = bool(
        source.strip()
        and control_count == 0
        and not calls
        and statement_count <= 2
        and re.fullmatch(
            r"\s*(?:(?:\([^;]+\)\s*)?;\s*)?(?:return\s+(?:0|nullptr|NULL|false|true|-?1)\s*;)?\s*",
            source,
            flags=re.DOTALL,
        )
    )
    large_asm_tiny = len(asm_lines) >= large_asm_threshold and statement_count <= 3
    plugin_calls = [name for name in calls if re.search(r"(?:plugin|hook|dispatch|invoke)", name, re.I)]
    plugin_heavy = len(plugin_calls) >= 2 and len(plugin_calls) * 2 >= max(1, len(calls))
    short_body = 0 < len(lines) < short_body_lines
    expected_calls = max(len(decompile_calls), asm_calls)
    low_call_count = expected_calls >= call_tolerance and len(calls) == 0
    fp_sensitive = bool(_FP_ASM_RE.search(assembly)) and not bool(_FP_SOURCE_RE.search(source))
    call_mismatch = expected_calls - len(calls) >= call_tolerance
    nan_missing = bool(_NAN_RE.search(decompile + "\n" + assembly)) and not bool(
        re.search(r"\b(?:isnan|nan)\b", source, re.I)
    )
    inline_wrapper = bool(
        len(calls) == 1
        and control_count == 0
        and statement_count <= 2
        and re.search(r"\breturn\b", source)
    )

    results = (
        signal("missing_source", "RED", missing_source, "candidate source body is empty"),
        signal("stub_markers", "RED", stub_markers, "candidate contains a stub/TODO/trap marker"),
        signal("trivial_stub", "RED", trivial_stub, "candidate is a trivial constant/empty stub"),
        signal(
            "large_asm_tiny_source",
            "RED",
            large_asm_tiny,
            f"assembly has {len(asm_lines)} lines while candidate has {statement_count} statements",
        ),
        signal(
            "plugin_call_heavy",
            "YELLOW",
            plugin_heavy,
            f"{len(plugin_calls)} of {len(calls)} calls look like plugin/hook dispatch",
        ),
        signal(
            "short_body",
            "YELLOW",
            short_body,
            f"candidate body has {len(lines)} non-empty lines (threshold {short_body_lines})",
        ),
        signal(
            "low_call_count",
            "YELLOW",
            low_call_count,
            f"evidence has at least {expected_calls} calls while candidate has none",
        ),
        signal(
            "fp_sensitivity",
            "YELLOW",
            fp_sensitive,
            "assembly contains floating-point-sensitive operations absent from candidate",
        ),
        signal(
            "call_count_mismatch",
            "YELLOW",
            call_mismatch,
            f"evidence has at least {expected_calls} calls while candidate has {len(calls)}",
        ),
        signal(
            "nan_logic",
            "YELLOW",
            nan_missing,
            "binary evidence appears NaN-sensitive but candidate has no NaN handling",
        ),
        signal(
            "inline_wrapper",
            "INFO",
            inline_wrapper,
            "candidate is a one-call forwarding wrapper",
        ),
    )
    if any(item.triggered and item.level == "RED" for item in results):
        status = "RED"
    elif any(item.triggered and item.level == "YELLOW" for item in results):
        status = "YELLOW"
    else:
        status = "GREEN"
    return ParityReport(status, results)
