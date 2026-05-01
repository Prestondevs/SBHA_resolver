#!/usr/bin/env python3
"""
Recover and solve SBHA-style Boolean password checks from a compiled PE EXE.

This is intentionally narrow: it targets the code shape produced by the sample
program where runprogram1(bool input[], bool output[]) is compiled as a stack
based chain of calls to tiny Boolean gate helpers.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pefile

And = Bool = Not = Or = Solver = Xor = is_true = sat = None


IMAGE_BASE_DEFAULT = 0x140000000
INPUT_BITS = 128


@dataclass(frozen=True)
class Candidate:
    va: int
    code: bytes
    input_loads: dict[int, int]


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


def parse_stack_store_al(code: bytes, i: int):
    if code[i : i + 3] == b"\x88\x44\x24":
        return code[i + 3], i + 4
    if code[i : i + 3] == b"\x88\x84\x24":
        return u32(code, i + 3), i + 7
    return None


def parse_stack_store_input(code: bytes, i: int):
    return parse_stack_store_al(code, i)


def parse_movzx_stack(code: bytes, i: int):
    short_regs = {0x4C: "ecx", 0x54: "edx"}
    long_regs = {0x8C: "ecx", 0x94: "edx"}

    if i + 5 <= len(code) and code[i : i + 2] == b"\x0f\xb6" and code[i + 2] in short_regs and code[i + 3] == 0x24:
        return short_regs[code[i + 2]], code[i + 4], i + 5

    if i + 8 <= len(code) and code[i : i + 2] == b"\x0f\xb6" and code[i + 2] in long_regs and code[i + 3] == 0x24:
        return long_regs[code[i + 2]], u32(code, i + 4), i + 8

    return None


def parse_call(code: bytes, i: int, current_va: int):
    if i + 5 <= len(code) and code[i] == 0xE8:
        return current_va + i + 5 + s32(code, i + 1), i + 5
    return None


def function_bytes_from_start(view: PEView, start_va: int, max_size: int = 0x8000) -> bytes:
    offset = start_va - view.text_va
    code = view.text_data[offset : offset + max_size]
    epilogue = code.find(b"\x48\x81\xc4")
    while epilogue != -1:
        if epilogue + 8 <= len(code) and code[epilogue + 7] == 0xC3:
            return code[: epilogue + 8]
        epilogue = code.find(b"\x48\x81\xc4", epilogue + 1)
    return code


def extract_input_loads(code: bytes) -> dict[int, int]:
    loads: dict[int, int] = {}
    i = 0
    while i + 25 < len(code):
        if (
            code[i : i + 7] == b"\xb8\x01\x00\x00\x00\x48\x6b"
            and code[i + 7] == 0xC0
            and code[i + 9 : i + 17] == b"\x48\x8b\x8c\x24\x80\x01\x00\x00"
            and code[i + 17 : i + 21] == b"\x0f\xb6\x04\x01"
        ):
            input_index = code[i + 8]
            parsed = parse_stack_store_input(code, i + 21)
            if parsed:
                stack_offset, end = parsed
                loads[stack_offset] = input_index
                i = end
                continue
        i += 1
    return loads


def find_checker_candidates(view: PEView) -> list[Candidate]:
    prologue = b"\x48\x89\x54\x24\x10\x48\x89\x4c\x24\x08\x48\x81\xec"
    candidates: list[Candidate] = []
    pos = view.text_data.find(prologue)
    while pos != -1:
        va = view.text_va + pos
        code = function_bytes_from_start(view, va)
        input_loads = extract_input_loads(code)
        if len(input_loads) == INPUT_BITS:
            candidates.append(Candidate(va, code, input_loads))
        pos = view.text_data.find(prologue, pos + 1)
    return candidates


def classify_gate(view: PEView, call_va: int) -> str:
    real_va = view.follow_jmp_thunk(call_va)
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


def reconstruct_expression(view: PEView, candidate: Candidate):
    bits = [Bool(f"bit_{i}") for i in range(INPUT_BITS)]
    values = {stack_offset: bits[input_index] for stack_offset, input_index in candidate.input_loads.items()}
    gates: list[tuple[str, int, tuple[int, ...]]] = []
    gate_cache: dict[int, str] = {}
    last_assigned_offset = None

    i = 0
    code = candidate.code
    while i < len(code):
        one = parse_movzx_stack(code, i)
        if not one:
            i += 1
            continue

        reg1, src1, j = one
        call = parse_call(code, j, candidate.va)

        if reg1 == "ecx" and call:
            call_va, k = call
            store = parse_stack_store_al(code, k)
            if store:
                dst, end = store
                gate_name = gate_cache.setdefault(call_va, classify_gate(view, call_va))
                if gate_name in ("not", "buff") and src1 in values:
                    values[dst] = gate_expr(gate_name, (values[src1],))
                    gates.append((gate_name, dst, (src1,)))
                    last_assigned_offset = dst
                    i = end
                    continue

        two = parse_movzx_stack(code, j)
        if reg1 == "edx" and two:
            reg2, src2, k = two
            call = parse_call(code, k, candidate.va)
            if reg2 == "ecx" and call:
                call_va, m = call
                store = parse_stack_store_al(code, m)
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


def print_gate_structure(gates: list[tuple[str, int, tuple[int, ...]]], input_loads: dict[int, int]):
    gate_counts = Counter(name for name, _, _ in gates)
    counts_text = ", ".join(f"{name}={gate_counts[name]}" for name in sorted(gate_counts))
    print(f"gate_counts: {counts_text}")
    print("gate_structure:")
    for index, (name, dst, srcs) in enumerate(gates):
        src_text = ", ".join(format_gate_source(src, input_loads) for src in srcs)
        print(f"  {index:03}: tmp[{dst:#x}] = {name}({src_text})")


def solve(path: Path, dump_gates: bool):
    global And, Bool, Not, Or, Solver, Xor, is_true, sat
    from z3 import And, Bool, Not, Or, Solver, Xor, is_true, sat

    view = PEView(path)
    candidates = find_checker_candidates(view)
    if not candidates:
        raise RuntimeError("could not find a checker function with 128 input-bit loads")
    if len(candidates) > 1:
        print(f"[!] found {len(candidates)} checker-like functions; using {candidates[0].va:#x}")

    candidate = candidates[0]
    bits, output_expr, gates, final_offset = reconstruct_expression(view, candidate)

    print(f"checker_va: {candidate.va:#x}")
    print(f"recovered_input_loads: {len(candidate.input_loads)}")
    print(f"recovered_gates: {len(gates)}")
    print(f"final_stack_offset: {final_offset:#x}")

    if dump_gates:
        print_gate_structure(gates, candidate.input_loads)

    solver = Solver()
    solver.add(output_expr)
    result = solver.check()
    if result != sat:
        raise RuntimeError(f"Z3 could not satisfy output[0] == true: {result}")

    model = solver.model()
    bit_values = [is_true(model.eval(bit, model_completion=True)) for bit in bits]
    bit_string = "".join("1" if bit else "0" for bit in bit_values)
    password = bits_to_password(bit_values)

    print(f"bits: {bit_string}")
    print(f"password: {password!r}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", type=Path, help="Path to the compiled SBHA-style PE executable")
    parser.add_argument("--dump-gates", action="store_true", help="Print recovered stack-slot gate operations")
    args = parser.parse_args(argv)

    try:
        solve(args.exe, args.dump_gates)
    except ModuleNotFoundError as exc:
        if exc.name == "z3":
            print("z3 is not installed. Install it with: python -m pip install z3-solver", file=sys.stderr)
            return 2
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
