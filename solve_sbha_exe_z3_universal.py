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
MIN_INPUT_BITS = 8


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


def function_bytes_from_start(view: PEView, start_va: int, max_size: int = 0x8000) -> bytes:
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


def reconstruct_expression(view: PEView, candidate: Candidate):
    bits = [Bool(f"bit_{i}") for i in range(candidate.input_bit_count)]
    values = {stack_offset: bits[input_index] for stack_offset, input_index in candidate.input_loads.items()}
    gates: list[tuple[str, int, tuple[int, ...]]] = []
    gate_cache: dict[int, str] = {}
    last_assigned_offset = None

    i = 0
    code = candidate.code
    while i < len(code):
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
        raise RuntimeError("could not find a checker function with contiguous input-bit loads")
    if len(candidates) > 1:
        print(
            f"[!] found {len(candidates)} checker-like functions; "
            f"using {candidates[0].va:#x} with {candidates[0].input_bit_count} bits"
        )

    candidate = candidates[0]
    bits, output_expr, gates, final_offset = reconstruct_expression(view, candidate)

    print(f"checker_va: {candidate.va:#x}")
    print(f"recovered_input_bits: {candidate.input_bit_count}")
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

    print(f"bits: {bit_string}")
    if len(bit_values) % 8 == 0:
        password = bits_to_password(bit_values)
        print(f"password: {password!r}")
    else:
        print("password: <not shown; recovered bit count is not byte-aligned>")


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
