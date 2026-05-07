#!/usr/bin/env python3
"""
Recover and solve SBHA-style Boolean password checks from a compiled PE EXE.

This is intentionally narrow: it targets the code shape produced by the sample
program where runprogram1(bool input[], bool output[]) is compiled as a stack
based chain of calls to tiny Boolean gate helpers.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pefile

And = Bool = Not = Or = Solver = Xor = is_true = sat = None


IMAGE_BASE_DEFAULT = 0x140000000
MIN_INPUT_BITS = 8


ASCII_BANNER = r"""
                         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%
                         @                              @@@@@
                         @                                   @@@
                         @                                      @@
    @ @*                 @                                       @@@
   @@@@@-  *@@@@@@@@@@@@@@                                         @@
   @   @.                @                                          @@
   @   @*                @                                           @+
                         @                                           @@                     :
                         @                                            @                @@  @@
                         @                                            @@@@@@@@@@@@@@@    @@
                         @                                            @                  .@
                         @                                           @@                  -@
   @@@@                  @                                           @@
   @   @@                @                                          @@
   @@@@@   *@@@@@@@@@@@@@@                                         @@
   @   @@                @                                        @@
   @@@@                  @                                      @@
                         @                                   @@@
                         @                               @@@@@
                         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"""


LIGHT_COLORS = {
    "mint": "\033[38;2;165;230;199m",
    "mint_strong": "\033[38;2;0;255;132m",
    "blue": "\033[38;2;112;214;255m",
    "yellow": "\033[38;2;238;218;159m",
    "purple": "\033[38;2;214;178;255m",
    "green": "\033[38;2;144;238;184m",
    "red": "\033[38;2;255;145;164m",
}


def color_text(value, group: str) -> str:
    if not sys.stdout.isatty():
        return str(value)
    color = LIGHT_COLORS.get(group, "")
    if not color:
        return str(value)
    return f"{color}{value}\033[0m"


def status_marker(kind: str) -> str:
    markers = {
        "ok": ("[+]", "green"),
        "work": ("[*]", "blue"),
        "warn": ("[!]", "yellow"),
        "err": ("[-]", "red"),
    }
    marker, color = markers.get(kind, ("[*]", "blue"))
    return color_text(marker, color)


def log_status(progress, enabled: bool, kind: str, message: str) -> None:
    if not enabled:
        return
    if progress is not None:
        progress.newline()
    print(f"{status_marker(kind)} {message}")


def print_banner(enabled: bool, solver: str | None = None, target: Path | None = None) -> None:
    if enabled:
        print(color_text(ASCII_BANNER, "mint"))
        print(f"{color_text('SBHA Solver Framework', 'mint_strong')} {color_text('v0.4', 'yellow')}")
        if solver is not None:
            print(f"mode: {color_text(solver, 'blue')}")
        if target is not None:
            print(f"target: {color_text(target.name, 'purple')}")
        print()


class TextProgress:
    def __init__(self, enabled: bool = True, width: int = 32):
        self.enabled = enabled
        self.width = width
        self.color_enabled = enabled and sys.stdout.isatty()
        self.frames = "/-\\|"
        self.index = 0
        self.frame = self.frames[0]
        self.last_spin = 0.0
        self.spin_interval = 0.25
        self.last_len = 0

    def color_for_percent(self, percent: float) -> str:
        if not self.color_enabled:
            return ""
        if percent >= 100.0:
            r, g, b = 0, 255, 132
        elif percent >= 75.0:
            r, g, b = 49, 236, 153
        elif percent >= 50.0:
            r, g, b = 91, 225, 166
        elif percent >= 25.0:
            r, g, b = 128, 217, 178
        else:
            r, g, b = 165, 230, 199
        return f"\033[38;2;{r};{g};{b}m"

    def update(self, percent: float, label: str) -> None:
        if not self.enabled:
            return
        percent = max(0.0, min(100.0, percent))
        filled = int(self.width * percent / 100.0)
        now = time.perf_counter()
        if now - self.last_spin >= self.spin_interval:
            self.frame = self.frames[self.index % len(self.frames)]
            self.index += 1
            self.last_spin = now
        spinner = self.frame
        if filled >= self.width:
            bar = "#" * self.width
        else:
            bar = "#" * filled + spinner + "." * max(0, self.width - filled - 1)
        color = self.color_for_percent(percent)
        reset = "\033[0m" if color else ""
        visible_text = f"[{bar}] {percent:6.2f}% {label}"
        text = f"\r{color}{visible_text}{reset}"
        padding = " " * max(0, self.last_len - len(visible_text))
        print(text + padding, end="", flush=True)
        self.last_len = len(visible_text)

    def finish(self, label: str = "done") -> None:
        self.update(100.0, label)
        if self.enabled:
            print()
            self.last_len = 0

    def newline(self) -> None:
        if self.enabled and self.last_len:
            print()
            self.last_len = 0


def run_with_spinner(progress: TextProgress, percent: float, label: str, func):
    result = {}

    def target():
        try:
            result["value"] = func()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    while thread.is_alive():
        progress.update(percent, label)
        time.sleep(0.1)
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


@dataclass(frozen=True)
class Candidate:
    va: int
    code: bytes
    input_loads: dict[int, int]

    @property
    def input_bit_count(self) -> int:
        return max(self.input_loads.values()) + 1


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def s32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def gate_expr(name: str, args):
    if name == "and":
        return And(args[0], args[1])
    if name == "or":
        return Or(args[0], args[1])
    if name == "xor":
        return Xor(args[0], args[1])
    if name == "nand":
        return Not(And(args[0], args[1]))
    if name == "nor":
        return Not(Or(args[0], args[1]))
    if name == "nxor":
        return Not(Xor(args[0], args[1]))
    if name == "not":
        return Not(args[0])
    if name == "buff":
        return args[0]
    raise ValueError(f"unsupported gate: {name}")


class PEView:
    def __init__(self, path: Path):
        self.path = path
        self.pe = pefile.PE(str(path))
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = path.read_bytes()
        self.text = next(
            section
            for section in self.pe.sections
            if section.Name.rstrip(b"\0") == b".text"
        )
        self.text_va = self.image_base + self.text.VirtualAddress
        self.text_data = self.text.get_data()
        self.symbols_by_name, self.symbols_by_va = self._read_coff_symbols()

    def va_to_offset(self, va: int) -> int:
        return self.pe.get_offset_from_rva(va - self.image_base)

    def read_va(self, va: int, size: int) -> bytes:
        offset = self.va_to_offset(va)
        return self.data[offset : offset + size]

    def follow_jmp_thunk(self, va: int) -> int:
        code = self.read_va(va, 5)
        if len(code) == 5 and code[0] == 0xE9:
            return va + 5 + s32(code, 1)
        return va

    def _read_coff_symbols(self) -> tuple[dict[str, int], dict[int, str]]:
        pointer = self.pe.FILE_HEADER.PointerToSymbolTable
        count = self.pe.FILE_HEADER.NumberOfSymbols
        if not pointer or not count:
            return {}, {}

        string_table = pointer + count * 18
        symbols_by_name: dict[str, int] = {}
        symbols_by_va: dict[int, str] = {}
        index = 0
        while index < count:
            offset = pointer + index * 18
            raw_name = self.data[offset : offset + 8]
            value = u32(self.data, offset + 8)
            section_number = struct.unpack_from("<h", self.data, offset + 12)[0]
            aux_count = self.data[offset + 17]

            if raw_name[:4] == b"\0\0\0\0":
                name_offset = u32(raw_name, 4)
                start = string_table + name_offset
                end = self.data.find(b"\0", start)
                raw = self.data[start:end]
            else:
                raw = raw_name.rstrip(b"\0")

            try:
                name = raw.decode("ascii")
            except UnicodeDecodeError:
                name = ""

            if name and 1 <= section_number <= len(self.pe.sections):
                section = self.pe.sections[section_number - 1]
                va = self.image_base + section.VirtualAddress + value
                symbols_by_name[name] = va
                if not name.startswith(".") or va not in symbols_by_va:
                    symbols_by_va[va] = name

            index += 1 + aux_count

        return symbols_by_name, symbols_by_va


def parse_stack_store_al(code: bytes, i: int):
    if code[i : i + 3] == b"\x88\x44\x24":
        return code[i + 3], i + 4
    if code[i : i + 3] == b"\x88\x84\x24":
        return u32(code, i + 3), i + 7
    return None


def parse_rbp_store_al(code: bytes, i: int):
    if i + 3 <= len(code) and code[i : i + 2] == b"\x88\x45":
        return struct.unpack_from("b", code, i + 2)[0], i + 3
    if i + 6 <= len(code) and code[i : i + 2] == b"\x88\x85":
        return s32(code, i + 2), i + 6
    return None


def parse_stack_store_input(code: bytes, i: int):
    return parse_stack_store_al(code, i) or parse_rbp_store_al(code, i)


def parse_movzx_stack(code: bytes, i: int):
    short_regs = {0x4C: "ecx", 0x54: "edx"}
    long_regs = {0x8C: "ecx", 0x94: "edx"}

    if i + 5 <= len(code) and code[i : i + 2] == b"\x0f\xb6" and code[i + 2] in short_regs and code[i + 3] == 0x24:
        return short_regs[code[i + 2]], code[i + 4], i + 5

    if i + 8 <= len(code) and code[i : i + 2] == b"\x0f\xb6" and code[i + 2] in long_regs and code[i + 3] == 0x24:
        return long_regs[code[i + 2]], u32(code, i + 4), i + 8

    return None


def parse_movzx_rbp(code: bytes, i: int):
    # movzx eax/edx/ecx, BYTE PTR [rbp+disp]
    short_regs = {0x45: "eax", 0x55: "edx", 0x4D: "ecx"}
    long_regs = {0x85: "eax", 0x95: "edx", 0x8D: "ecx"}

    if i + 4 <= len(code) and code[i : i + 2] == b"\x0f\xb6" and code[i + 2] in short_regs:
        return short_regs[code[i + 2]], struct.unpack_from("b", code, i + 3)[0], i + 4

    if i + 7 <= len(code) and code[i : i + 2] == b"\x0f\xb6" and code[i + 2] in long_regs:
        return long_regs[code[i + 2]], s32(code, i + 3), i + 7

    return None


def parse_movzx_temp(code: bytes, i: int):
    return parse_movzx_stack(code, i) or parse_movzx_rbp(code, i)


def parse_call(code: bytes, i: int, current_va: int):
    if i + 5 <= len(code) and code[i] == 0xE8:
        return current_va + i + 5 + s32(code, i + 1), i + 5
    return None


def parse_imul_rax_rax_immediate(code: bytes, i: int):
    if i + 4 <= len(code) and code[i : i + 3] == b"\x48\x6b\xc0":
        return code[i + 3], i + 4
    if i + 7 <= len(code) and code[i : i + 3] == b"\x48\x69\xc0":
        return u32(code, i + 3), i + 7
    return None


def function_bytes_from_start(view: PEView, start_va: int, max_size: int = 0x800000) -> bytes:
    offset = start_va - view.text_va
    code = view.text_data[offset : offset + max_size]
    epilogue = code.find(b"\x48\x81\xc4")
    while epilogue != -1:
        if epilogue + 8 <= len(code) and code[epilogue + 7] == 0xC3:
            return code[: epilogue + 8]
        if epilogue + 9 <= len(code) and code[epilogue + 7 : epilogue + 9] == b"\x5d\xc3":
            return code[: epilogue + 9]
        epilogue = code.find(b"\x48\x81\xc4", epilogue + 1)
    return code


def extract_input_loads(code: bytes) -> dict[int, int]:
    loads: dict[int, int] = {}
    i = 0
    while i + 25 < len(code):
        if (
            code[i : i + 5] == b"\xb8\x01\x00\x00\x00"
        ):
            imul = parse_imul_rax_rax_immediate(code, i + 5)
            if not imul:
                i += 1
                continue
            input_index, after_imul = imul
            if (
                code[after_imul : after_imul + 8] != b"\x48\x8b\x8c\x24\x80\x01\x00\x00"
                or code[after_imul + 8 : after_imul + 12] != b"\x0f\xb6\x04\x01"
            ):
                i += 1
                continue
            parsed = parse_stack_store_input(code, after_imul + 12)
            if parsed:
                stack_offset, end = parsed
                loads[stack_offset] = input_index
                i = end
                continue
        gcc = parse_gcc_input_load(code, i)
        if gcc:
            input_index, stack_offset, end = gcc
            loads[stack_offset] = input_index
            i = end
            continue
        i += 1
    return loads


def parse_gcc_input_load(code: bytes, i: int):
    # mov rax, QWORD PTR [rbp+input_ptr_slot]
    if i + 10 > len(code) or code[i : i + 3] != b"\x48\x8b\x85":
        return None

    j = i + 7
    if code[j : j + 3] == b"\x0f\xb6\x00":
        input_index = 0
        j += 3
    elif j + 4 <= len(code) and code[j : j + 3] == b"\x0f\xb6\x40":
        input_index = code[j + 3]
        j += 4
    elif j + 7 <= len(code) and code[j : j + 3] == b"\x0f\xb6\x80":
        input_index = u32(code, j + 3)
        j += 7
    else:
        return None

    store = parse_rbp_store_al(code, j)
    if not store:
        return None
    stack_offset, end = store
    return input_index, stack_offset, end


def find_checker_candidates(view: PEView) -> list[Candidate]:
    prologue = b"\x48\x89\x54\x24\x10\x48\x89\x4c\x24\x08\x48\x81\xec"
    candidates: list[Candidate] = []
    seen: set[int] = set()

    symbol_va = view.symbols_by_name.get("_Z11runprogram1PbS_")
    if symbol_va is not None:
        code = function_bytes_from_start(view, symbol_va)
        input_loads = extract_input_loads(code)
        if _is_checker_input_set(input_loads):
            candidates.append(Candidate(symbol_va, code, input_loads))
            seen.add(symbol_va)

    pos = view.text_data.find(prologue)
    while pos != -1:
        va = view.text_va + pos
        if va not in seen:
            code = function_bytes_from_start(view, va)
            input_loads = extract_input_loads(code)
            if _is_checker_input_set(input_loads):
                candidates.append(Candidate(va, code, input_loads))
                seen.add(va)
        pos = view.text_data.find(prologue, pos + 1)

    gcc_prologue = b"\x55\x48\x81\xec"
    pos = view.text_data.find(gcc_prologue)
    while pos != -1:
        va = view.text_va + pos
        if va not in seen:
            code = function_bytes_from_start(view, va)
            input_loads = extract_input_loads(code)
            if _is_checker_input_set(input_loads):
                candidates.append(Candidate(va, code, input_loads))
                seen.add(va)
        pos = view.text_data.find(gcc_prologue, pos + 1)

    return sorted(candidates, key=lambda candidate: candidate.input_bit_count, reverse=True)


def _is_checker_input_set(input_loads: dict[int, int]) -> bool:
    input_indexes = set(input_loads.values())
    if not input_indexes:
        return False
    bit_count = max(input_indexes) + 1
    return bit_count >= MIN_INPUT_BITS and input_indexes == set(range(bit_count))


def classify_gate(view: PEView, call_va: int) -> str:
    real_va = view.follow_jmp_thunk(call_va)
    symbol_name = view.symbols_by_va.get(real_va)
    symbol_gate_names = {
        "_Z4and_bb": "and",
        "_Z3or_bb": "or",
        "_Z4xor_bb": "xor",
        "_Z5nand_bb": "nand",
        "_Z4nor_bb": "nor",
        "_Z5nxor_bb": "nxor",
        "_Z4not_b": "not",
        "_Z5buff_b": "buff",
    }
    if symbol_name in symbol_gate_names:
        return symbol_gate_names[symbol_name]

    body = view.read_va(real_va, 80)

    if body.startswith(b"\x88\x4c\x24\x08\x0f\xb6\x44\x24\x08\xc3"):
        return "buff"
    if body.startswith(b"\x88\x4c\x24\x08") and b"\x85\xc0\x75\x09" in body:
        return "not"

    if b"\x3b\xc1\x74\x09" in body:
        return "xor"
    if b"\x3b\xc1\x75\x09" in body:
        return "nxor"

    first_set_1 = body.find(b"\xc7\x04\x24\x01\x00\x00\x00")
    first_set_0 = body.find(b"\xc7\x04\x24\x00\x00\x00\x00")
    jumps = [b for b in body if b in (0x74, 0x75)]

    if len(jumps) >= 2:
        returns_one_first = first_set_1 != -1 and (first_set_0 == -1 or first_set_1 < first_set_0)
        if jumps[0] == 0x74 and jumps[1] == 0x74:
            return "and" if returns_one_first else "nand"
        if jumps[0] == 0x75 and jumps[1] == 0x75:
            return "nor" if returns_one_first else "or"

    raise ValueError(f"could not classify gate helper at {call_va:#x} -> {real_va:#x}")


def reconstruct_expression(view: PEView, candidate: Candidate, progress: TextProgress | None = None):
    bits = [Bool(f"bit_{i}") for i in range(candidate.input_bit_count)]
    values = {stack_offset: bits[input_index] for stack_offset, input_index in candidate.input_loads.items()}
    gates: list[tuple[str, int, tuple[int, ...]]] = []
    gate_cache: dict[int, str] = {}
    last_assigned_offset = None

    i = 0
    code = candidate.code
    next_progress = 0
    while i < len(code):
        if progress is not None and i >= next_progress:
            progress.update(20.0 + (45.0 * i / max(1, len(code))), f"phase=recover_gates offset={i:#x}")
            next_progress = i + max(1, len(code) // 200)
        one = parse_movzx_temp(code, i)
        if not one:
            i += 1
            continue

        reg1, src1, j = one
        if reg1 == "eax" and code[j : j + 2] == b"\x89\xc1":
            reg1 = "ecx"
            j += 2
        call = parse_call(code, j, candidate.va)

        if reg1 == "ecx" and call:
            call_va, k = call
            store = parse_stack_store_al(code, k) or parse_rbp_store_al(code, k)
            if store:
                dst, end = store
                gate_name = gate_cache.setdefault(call_va, classify_gate(view, call_va))
                if gate_name in ("not", "buff") and src1 in values:
                    values[dst] = gate_expr(gate_name, (values[src1],))
                    gates.append((gate_name, dst, (src1,)))
                    last_assigned_offset = dst
                    i = end
                    continue

        two = parse_movzx_temp(code, j)
        if reg1 == "edx" and two:
            reg2, src2, k = two
            if reg2 == "eax" and code[k : k + 2] == b"\x89\xc1":
                reg2 = "ecx"
                k += 2
            call = parse_call(code, k, candidate.va)
            if reg2 == "ecx" and call:
                call_va, m = call
                store = parse_stack_store_al(code, m) or parse_rbp_store_al(code, m)
                if store:
                    dst, end = store
                    gate_name = gate_cache.setdefault(call_va, classify_gate(view, call_va))
                    if gate_name not in ("not", "buff") and src1 in values and src2 in values:
                        values[dst] = gate_expr(gate_name, (values[src2], values[src1]))
                        gates.append((gate_name, dst, (src2, src1)))
                        last_assigned_offset = dst
                        i = end
                        continue

        i += 1

    if last_assigned_offset is None:
        raise ValueError("no gate assignments recovered")
    return bits, values[last_assigned_offset], gates, last_assigned_offset


def bits_to_password(bit_values: list[bool]) -> str:
    if len(bit_values) % 8 != 0:
        raise ValueError("bit count is not byte-aligned")
    chars = []
    for i in range(0, len(bit_values), 8):
        value = 0
        for bit in bit_values[i : i + 8]:
            value = (value << 1) | int(bit)
        chars.append(chr(value))
    return "".join(chars)


def format_gate_source(stack_offset: int, input_loads: dict[int, int]) -> str:
    input_index = input_loads.get(stack_offset)
    if input_index is not None:
        return f"bit_{input_index}[{stack_offset:#x}]"
    return f"tmp[{stack_offset:#x}]"


def format_gate_structure(gates: list[tuple[str, int, tuple[int, ...]]], input_loads: dict[int, int]) -> str:
    gate_counts = Counter(name for name, _, _ in gates)
    counts_text = ", ".join(f"{name}={gate_counts[name]}" for name in sorted(gate_counts))
    lines = [f"gate_counts: {counts_text}", "gate_structure:"]
    for index, (name, dst, srcs) in enumerate(gates):
        src_text = ", ".join(format_gate_source(src, input_loads) for src in srcs)
        lines.append(f"  {index:03}: tmp[{dst:#x}] = {name}({src_text})")
    return "\n".join(lines) + "\n"


def print_gate_structure(gates: list[tuple[str, int, tuple[int, ...]]], input_loads: dict[int, int]):
    print(format_gate_structure(gates, input_loads), end="")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_password(path: Path, password: str, timeout: float = 10.0) -> bool:
    completed = subprocess.run(
        [str(path)],
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return "Access granted!" in completed.stdout


def write_json_result(path: Path, result: dict) -> None:
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_csv_result(path: Path, result: dict) -> None:
    fields = [
        "timestamp",
        "solver",
        "exe",
        "sha256",
        "checker_va",
        "input_bits",
        "gates",
        "password",
        "elapsed_seconds",
        "verified",
    ]
    row = {field: result.get(field, "") for field in fields}
    row["gate_counts"] = json.dumps(result.get("gate_counts", {}), sort_keys=True)
    fields.append("gate_counts")
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def print_dependencies() -> None:
    print(f"python: {sys.version.split()[0]}")
    for package in ("pefile", "z3"):
        spec = importlib.util.find_spec(package)
        status = spec.origin if spec and spec.origin else "missing"
        print(f"{package}: {status}")


def result_color(group: str) -> str:
    if not sys.stdout.isatty():
        return ""
    return LIGHT_COLORS.get(group, "")


def color_value(value, group: str) -> str:
    return color_text(value, group)


def print_result_box(result: dict, gate_stats: bool) -> None:
    print(color_text("+-- result ----------------------------------------", "mint"))
    print(f"| checker_va: {color_value(result['checker_va'], 'blue')}")
    print(f"| input_bits: {color_value(result['input_bits'], 'yellow')}")
    print(f"| input_loads: {color_value(result['input_loads'], 'yellow')}")
    print(f"| gates: {color_value(result['gates'], 'blue')}")
    print(f"| final_stack_offset: {color_value(result['final_stack_offset'], 'blue')}")
    print(f"| bits: {result['bits']}")
    if result.get("password") is not None:
        print(f"| password: {color_value(repr(result['password']), 'purple')}")
    else:
        print("| password: <not shown; recovered bit count is not byte-aligned>")
    if "verified" in result:
        verified_group = "green" if result["verified"] else "red"
        print(f"| verified: {color_value(result['verified'], verified_group)}")
    elapsed_text = f"{result['elapsed_seconds']:.3f}"
    print(f"| elapsed_seconds: {color_value(elapsed_text, 'yellow')}")
    if gate_stats:
        counts_text = ", ".join(f"{name}={count}" for name, count in sorted(result["gate_counts"].items()))
        print(f"| gate_stats: total={color_value(result['gates'], 'blue')}; {color_value(counts_text, 'blue')}")
    print(color_text("+--------------------------------------------------", "mint"))


def emit_result(result: dict, *, quiet: bool, summary: bool, verbose: bool, gate_stats: bool) -> None:
    if quiet:
        if result.get("password") is not None:
            print(color_value(result["password"], "purple"))
        else:
            print(result["bits"])
        return

    elapsed_text = f"{result['elapsed_seconds']:.3f}"
    if summary:
        print(
            f"{status_marker('ok')} solved "
            f"target={color_value(Path(result['exe']).name, 'purple')} "
            f"mode={color_value(result['solver'], 'blue')} "
            f"bits={color_value(result['input_bits'], 'yellow')} "
            f"gates={color_value(result['gates'], 'blue')} "
            f"elapsed={color_value(elapsed_text + 's', 'yellow')} "
            f"password={color_value(repr(result.get('password')), 'purple')}"
        )
        if "verified" in result:
            print(f"verified: {result['verified']}")
        if gate_stats:
            counts_text = ", ".join(f"{name}={count}" for name, count in sorted(result["gate_counts"].items()))
            print(f"gate_stats: total={color_value(result['gates'], 'blue')}; {color_value(counts_text, 'blue')}")
    else:
        print_result_box(result, gate_stats)
    if verbose:
        print(f"exe_sha256: {result['sha256']}")


def solve(path: Path, args):
    solve_start = time.perf_counter()
    dump_to_stdout = args.dump_gates == "-"
    output_enabled = not args.quiet and not dump_to_stdout
    print_banner(output_enabled, "static-z3", path)
    progress = TextProgress(enabled=not args.no_progress and not args.quiet and not dump_to_stdout)
    global And, Bool, Not, Or, Solver, Xor, is_true, sat
    from z3 import And, Bool, Not, Or, Solver, Xor, is_true, sat

    progress.update(0.0, "phase=load_target")
    view = PEView(path)
    log_status(progress, output_enabled, "ok", f"target loaded path={color_value(path.name, 'purple')}")
    progress.update(8.0, "phase=find_checker")
    candidates = find_checker_candidates(view)
    if not candidates:
        raise RuntimeError("could not find a checker function with contiguous input-bit loads")
    if len(candidates) > 1 and not args.quiet:
        progress.newline()
        print(
            f"{status_marker('warn')} found {color_value(len(candidates), 'yellow')} checker-like functions; "
            f"using {color_value(f'{candidates[0].va:#x}', 'blue')} with "
            f"{color_value(candidates[0].input_bit_count, 'yellow')} bits"
        )

    candidate = candidates[0]
    log_status(progress, output_enabled, "ok", f"checker recovered va={color_value(f'{candidate.va:#x}', 'blue')}")
    progress.update(18.0, "phase=recover_gates")
    bits, output_expr, gates, final_offset = reconstruct_expression(view, candidate, progress)
    log_status(progress, output_enabled, "ok", f"gates reconstructed count={color_value(len(gates), 'blue')}")
    progress.update(68.0, "phase=build_z3")

    if args.dump_gates:
        gate_text = format_gate_structure(gates, candidate.input_loads)
        if args.dump_gates == "-":
            progress.newline()
            print(gate_text, end="")
        else:
            Path(args.dump_gates).write_text(gate_text, encoding="utf-8")

    solver = Solver()
    solver.add(output_expr)
    result = run_with_spinner(progress, 82.0, "phase=z3_solve", solver.check)
    if result != sat:
        raise RuntimeError(f"Z3 could not satisfy output[0] == true: {result}")

    log_status(progress, output_enabled, "ok", "z3 model solved")
    progress.update(94.0, "phase=extract_model")
    model = solver.model()
    bit_values = [is_true(model.eval(bit, model_completion=True)) for bit in bits]
    bit_string = "".join("1" if bit else "0" for bit in bit_values)
    progress.finish("solved")

    password = bits_to_password(bit_values) if len(bit_values) % 8 == 0 else None
    elapsed = time.perf_counter() - solve_start
    gate_counts = Counter(name for name, _, _ in gates)
    run_result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "solver": "static-z3",
        "exe": str(path),
        "sha256": sha256_file(path),
        "checker_va": f"{candidate.va:#x}",
        "input_bits": candidate.input_bit_count,
        "input_loads": len(candidate.input_loads),
        "gates": len(gates),
        "gate_counts": dict(sorted(gate_counts.items())),
        "final_stack_offset": f"{final_offset:#x}",
        "bits": bit_string,
        "password": password,
        "elapsed_seconds": elapsed,
    }
    if args.verify_run and password is not None:
        run_result["verified"] = verify_password(path, password)
    if args.json_out:
        write_json_result(args.json_out, run_result)
    if args.csv_log:
        append_csv_result(args.csv_log, run_result)
    emit_result(run_result, quiet=args.quiet, summary=args.summary, verbose=args.verbose, gate_stats=args.gate_stats)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("-h", "--help", "--h", action="help", help="Show this help message and exit")
    parser.add_argument("exe", type=Path, nargs="?", help="Path to the compiled SBHA-style PE executable")
    parser.add_argument("--json-out", type=Path, help="Write solve result as JSON")
    parser.add_argument("--summary", action="store_true", help="Print a compact one-line summary")
    parser.add_argument("--no-progress", action="store_true", help="Disable animated progress output")
    parser.add_argument("--csv-log", type=Path, metavar="runs.csv", help="Append run result to a CSV log")
    parser.add_argument("--verify-run", action="store_true", help="Run the EXE with the recovered password and check for success text")
    parser.add_argument("--gate-stats", action="store_true", help="Print gate count statistics")
    parser.add_argument("--dump-gates", nargs="?", const="-", metavar="gates.txt", help="Write recovered gate structure to a file, or stdout if no file is given")
    parser.add_argument("--quiet", action="store_true", help="Print only the recovered password, or bits if not byte-aligned")
    parser.add_argument("--verbose", "--v", "-v", action="store_true", help="Print extra diagnostic metadata")
    parser.add_argument("--depend", action="store_true", help="Check solver dependencies and exit")
    args = parser.parse_args(argv)

    if args.depend:
        print_dependencies()
        return 0
    if args.exe is None:
        parser.error("exe is required unless --depend is used")

    try:
        solve(args.exe, args)
    except ModuleNotFoundError as exc:
        if exc.name == "z3":
            print("z3 is not installed. Install it with: python -m pip install z3-solver", file=sys.stderr)
            return 2
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
