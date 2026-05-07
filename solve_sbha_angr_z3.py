#!/usr/bin/env python3
"""
Solve SBHA-style password checkers with angr symbolic execution.

This variant executes the recovered checker function with symbolic bool bytes.
Tiny gate helper functions are hooked with angr SimProcedures so the solver
builds symbolic Z3/claripy expressions instead of path-exploding through every
gate helper branch.
"""

from __future__ import annotations

import argparse
import importlib.util as importlib_util
import importlib.util
import logging
import sys
import threading
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from solve_sbha_exe_z3_universal import (
        PEView,
        append_csv_result,
        classify_gate,
        find_checker_candidates,
        sha256_file,
        s32,
        verify_password,
        write_json_result,
    )
except ModuleNotFoundError:
    sibling = Path(__file__).resolve().with_name("solve_sbha_exe_z3_universal.py")
    spec = importlib_util.spec_from_file_location("solve_sbha_exe_z3_universal", sibling)
    if spec is None or spec.loader is None:
        raise
    static_solver = importlib_util.module_from_spec(spec)
    sys.modules[spec.name] = static_solver
    spec.loader.exec_module(static_solver)
    PEView = static_solver.PEView
    append_csv_result = static_solver.append_csv_result
    classify_gate = static_solver.classify_gate
    find_checker_candidates = static_solver.find_checker_candidates
    sha256_file = static_solver.sha256_file
    s32 = static_solver.s32
    verify_password = static_solver.verify_password
    write_json_result = static_solver.write_json_result


STACK_BASE = 0x700000000000
STACK_SIZE = 0x200000
INPUT_BASE = 0x710000000000
OUTPUT_BASE = 0x720000000000
RET_ADDR = 0x730000000000


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


def parse_int(value: str) -> int:
    return int(value, 0)


def bits_to_password(bit_values: list[int]) -> str:
    if len(bit_values) % 8 != 0:
        raise ValueError("bit count is not byte-aligned")

    chars = []
    for i in range(0, len(bit_values), 8):
        value = 0
        for bit in bit_values[i : i + 8]:
            value = (value << 1) | bit
        chars.append(chr(value))
    return "".join(chars)


def find_gate_call_targets(view: PEView, checker_va: int, checker_code: bytes) -> dict[int, str]:
    gates: dict[int, str] = {}
    i = 0
    while i + 5 <= len(checker_code):
        if checker_code[i] == 0xE8:
            call_va = checker_va + i + 5 + s32(checker_code, i + 1)
            if not (view.text_va <= call_va < view.text_va + len(view.text_data)):
                i += 5
                continue
            try:
                gates[call_va] = classify_gate(view, call_va)
            except ValueError:
                pass
            i += 5
            continue
        i += 1
    return gates


def find_gate_call_sequence(view: PEView, checker_va: int, checker_code: bytes) -> list[tuple[int, int, str]]:
    gates = []
    i = 0
    while i + 5 <= len(checker_code):
        if checker_code[i] == 0xE8:
            call_va = checker_va + i
            target_va = checker_va + i + 5 + s32(checker_code, i + 1)
            if view.text_va <= target_va < view.text_va + len(view.text_data):
                try:
                    gates.append((call_va, target_va, classify_gate(view, target_va)))
                except ValueError:
                    pass
            i += 5
            continue
        i += 1
    return gates


def format_gate_dump(
    gate_sequence: list[tuple[int, int, str]],
    gate_targets: dict[int, str],
    hardening_targets: dict[int, str],
    runtime_targets: dict[int, str],
) -> str:
    counts = Counter(name for _, _, name in gate_sequence)
    lines = [
        "gate_call_counts: "
        + ", ".join(f"{name}={counts[name]}" for name in sorted(counts)),
        "hooked_gate_functions:",
    ]
    for target, gate_name in sorted(gate_targets.items()):
        lines.append(f"  {target:#x}: {gate_name}")
    if hardening_targets:
        lines.append("hooked_hardening_helpers:")
        for target, helper_name in sorted(hardening_targets.items()):
            lines.append(f"  {target:#x}: {helper_name}")
    if runtime_targets:
        lines.append("hooked_runtime_helpers:")
        for target, helper_name in sorted(runtime_targets.items()):
            lines.append(f"  {target:#x}: {helper_name}")
    lines.append("gate_call_sequence:")
    for index, (call_va, target_va, gate_name) in enumerate(gate_sequence):
        lines.append(f"  {index:06}: call[{call_va:#x}] -> {target_va:#x} {gate_name}")
    return "\n".join(lines) + "\n"


def make_gate_proc(gate_name: str, angr, claripy):
    class GateProc(angr.SimProcedure):
        def run(self):
            bits = self.state.arch.bits
            one = claripy.BVV(1, bits)
            zero = claripy.BVV(0, bits)
            a = (self.state.regs.rcx & one) != zero
            b = (self.state.regs.rdx & one) != zero

            if gate_name == "and":
                result = claripy.And(a, b)
            elif gate_name == "or":
                result = claripy.Or(a, b)
            elif gate_name == "xor":
                result = a != b
            elif gate_name == "nand":
                result = claripy.Not(claripy.And(a, b))
            elif gate_name == "nor":
                result = claripy.Not(claripy.Or(a, b))
            elif gate_name == "nxor":
                result = a == b
            elif gate_name == "not":
                result = claripy.Not(a)
            elif gate_name == "buff":
                result = a
            else:
                raise angr.errors.SimProcedureError(f"unsupported gate: {gate_name}")

            return claripy.If(result, one, zero)

    GateProc.__name__ = f"{gate_name}_gate_proc"
    return GateProc


def make_const_proc(value: int, angr, claripy):
    class ConstProc(angr.SimProcedure):
        def run(self, *args):
            return claripy.BVV(value, self.state.arch.bits)

    ConstProc.__name__ = f"const_{value}_proc"
    return ConstProc


def hook_hardening_helpers(project, view: PEView, angr, claripy) -> dict[int, str]:
    helpers = {
        "opaque_true": 1,
        "opaque_false": 0,
        "volatile_noise": 0,
        "flattened_guard": 1,
        "decoy_checksum": 0,
    }
    hooked: dict[int, str] = {}
    for symbol_name, va in view.symbols_by_name.items():
        for helper_name, return_value in helpers.items():
            if helper_name in symbol_name:
                project.hook(va, make_const_proc(return_value, angr, claripy)(), replace=True)
                hooked[va] = helper_name
                break
    return hooked


def hook_runtime_helpers(project, view: PEView, angr, claripy) -> dict[int, str]:
    hooked: dict[int, str] = {}
    for symbol_name, va in view.symbols_by_name.items():
        if "chkstk" in symbol_name:
            project.hook(va, make_const_proc(0, angr, claripy)(), replace=True)
            hooked[va] = symbol_name
    return hooked


def execute_single_path(project, state, ret_addr: int, progress: TextProgress, checker_va: int, checker_size: int, max_steps: int = 1000000):
    simgr = project.factory.simulation_manager(state, save_unconstrained=False)
    steps = 0
    last_terminal = None
    last_error_state = None
    last_active = None

    while simgr.active and steps < max_steps:
        active = simgr.active[0]
        last_active = active
        if active.addr == ret_addr:
            return active

        if checker_va <= active.addr < checker_va + checker_size:
            offset_percent = (active.addr - checker_va) / max(1, checker_size)
            percent = 42.0 + min(34.0, 34.0 * offset_percent)
        else:
            percent = 58.0
        progress.update(percent, f"phase=symbolic_exec step={steps}")

        simgr.step()
        steps += 1

        for dead in simgr.deadended:
            if dead.addr == ret_addr:
                return dead
            last_terminal = dead

        for errored in simgr.errored:
            last_error_state = errored.state

        if last_terminal is not None and not simgr.active:
            return last_terminal
        if last_error_state is not None and not simgr.active:
            return last_error_state
        if simgr.unconstrained and not simgr.active:
            return simgr.unconstrained[-1]

        # The target checkers are intended to be single-path once helper/noise
        # functions are hooked. Keep only active states to reduce retained data.
        if len(simgr.active) > 1:
            simgr.active = simgr.active[:1]
        simgr.drop(stash="deadended")
        simgr.drop(stash="unconstrained")
        simgr.drop(stash="unsat")
        simgr.drop(stash="errored")

    for dead in simgr.deadended:
        if dead.addr == ret_addr:
            return dead
        last_terminal = dead
    for errored in simgr.errored:
        last_error_state = errored.state
    if last_terminal is not None:
        return last_terminal
    if last_error_state is not None:
        return last_error_state
    if simgr.unconstrained:
        return simgr.unconstrained[-1]
    return last_active


def choose_checker(view: PEView, checker_va: int | None, bit_count: int | None):
    candidates = find_checker_candidates(view)

    if checker_va is not None:
        for candidate in candidates:
            if candidate.va == checker_va:
                if bit_count is not None and bit_count != candidate.input_bit_count:
                    print(
                        f"{status_marker('warn')} overriding recovered bit count "
                        f"{color_value(candidate.input_bit_count, 'yellow')} with --bits "
                        f"{color_value(bit_count, 'yellow')}"
                    )
                return checker_va, candidate.code, bit_count or candidate.input_bit_count

        if bit_count is None:
            raise RuntimeError("--bits is required when --checker-va is not auto-recognized")
        code = view.read_va(checker_va, 0x800000)
        return checker_va, code, bit_count

    if not candidates:
        raise RuntimeError("could not auto-detect checker; pass --checker-va and --bits")

    candidate = candidates[0]
    return candidate.va, candidate.code, bit_count or candidate.input_bit_count


def print_dependencies() -> None:
    print(f"python: {sys.version.split()[0]}")
    for package in ("pefile", "z3", "angr", "claripy"):
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
    print(f"| hooked_gate_functions: {color_value(result['hooked_gate_functions'], 'blue')}")
    print(f"| hooked_hardening_helpers: {color_value(result['hooked_hardening_helpers'], 'blue')}")
    print(f"| hooked_runtime_helpers: {color_value(result['hooked_runtime_helpers'], 'blue')}")
    print(f"| gate_calls: {color_value(result['gate_calls'], 'blue')}")
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
        print(f"| gate_stats: total_calls={color_value(result['gate_calls'], 'blue')}; {color_value(counts_text, 'blue')}")
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
            f"gate_calls={color_value(result['gate_calls'], 'blue')} "
            f"elapsed={color_value(elapsed_text + 's', 'yellow')} "
            f"password={color_value(repr(result.get('password')), 'purple')}"
        )
        if "verified" in result:
            print(f"verified: {result['verified']}")
        if gate_stats:
            counts_text = ", ".join(f"{name}={count}" for name, count in sorted(result["gate_counts"].items()))
            print(f"gate_stats: total_calls={color_value(result['gate_calls'], 'blue')}; {color_value(counts_text, 'blue')}")
    else:
        print_result_box(result, gate_stats)
    if verbose:
        print(f"exe_sha256: {result['sha256']}")


def solve_with_angr(path: Path, checker_va: int | None, bit_count: int | None, args):
    solve_start = time.perf_counter()
    dump_to_stdout = args.dump_gates == "-"
    output_enabled = not args.quiet and not dump_to_stdout
    print_banner(output_enabled, "angr-z3", path)
    progress = TextProgress(enabled=not args.no_progress and not args.quiet and not dump_to_stdout)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

    def import_angr_modules():
        # Python 3.13 on some Windows Store installs can hang in
        # platform.system() while querying WMI during angr import.
        import platform

        platform.system = lambda: "Windows"
        import angr
        import claripy

        return angr, claripy

    try:
        angr, claripy = run_with_spinner(progress, 2.0, "importing angr", import_angr_modules)
    except ModuleNotFoundError as exc:
        if exc.name in {"angr", "claripy"}:
            progress.newline()
            print(f"{status_marker('err')} angr is not installed. Install it with: python -m pip install angr", file=sys.stderr)
            return 2
        raise

    progress.update(0.0, "phase=load_target")
    view = PEView(path)
    log_status(progress, output_enabled, "ok", f"target loaded path={color_value(path.name, 'purple')}")
    progress.update(8.0, "phase=find_checker")
    checker_va, checker_code, bit_count = choose_checker(view, checker_va, bit_count)
    log_status(progress, output_enabled, "ok", f"checker recovered va={color_value(f'{checker_va:#x}', 'blue')}")

    progress.update(16.0, "phase=load_angr_project")
    project = angr.Project(str(path), auto_load_libs=False)

    progress.update(24.0, "phase=hook_helpers")
    gate_targets = find_gate_call_targets(view, checker_va, checker_code)
    gate_sequence = find_gate_call_sequence(view, checker_va, checker_code)
    for target, gate_name in gate_targets.items():
        project.hook(target, make_gate_proc(gate_name, angr, claripy)(), replace=True)
    hardening_targets = hook_hardening_helpers(project, view, angr, claripy)
    runtime_targets = hook_runtime_helpers(project, view, angr, claripy)
    log_status(
        progress,
        output_enabled,
        "ok",
        f"helpers hooked gates={color_value(len(gate_targets), 'blue')} "
        f"hardening={color_value(len(hardening_targets), 'blue')} runtime={color_value(len(runtime_targets), 'blue')}",
    )

    if args.dump_hooks and not args.quiet:
        progress.newline()
        print("hooked_gates:")
        for target, gate_name in sorted(gate_targets.items()):
            print(f"  {target:#x}: {gate_name}")
        if hardening_targets:
            print("hooked_hardening_helpers:")
            for target, helper_name in sorted(hardening_targets.items()):
                print(f"  {target:#x}: {helper_name}")
        if runtime_targets:
            print("hooked_runtime_helpers:")
            for target, helper_name in sorted(runtime_targets.items()):
                print(f"  {target:#x}: {helper_name}")

    if args.dump_gates:
        gate_text = format_gate_dump(gate_sequence, gate_targets, hardening_targets, runtime_targets)
        if args.dump_gates == "-":
            progress.newline()
            print(gate_text, end="")
        else:
            Path(args.dump_gates).write_text(gate_text, encoding="utf-8")

    progress.update(34.0, "phase=build_symbolic_state")
    state = project.factory.blank_state(addr=checker_va)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.LAZY_SOLVES)

    stack_top = STACK_BASE + STACK_SIZE - 0x1000
    state.regs.rsp = stack_top
    state.regs.rbp = 0
    state.memory.store(stack_top, claripy.BVV(RET_ADDR, state.arch.bits), endness=state.arch.memory_endness)

    symbolic_bits = []
    for i in range(bit_count):
        bit = claripy.BVS(f"input_bit_{i}", 8)
        state.solver.add(claripy.Or(bit == 0, bit == 1))
        state.memory.store(INPUT_BASE + i, bit)
        symbolic_bits.append(bit)

    state.memory.store(OUTPUT_BASE, claripy.BVV(0, 8))

    # Windows x64 uses rcx/rdx. Setting rdi/rsi as well makes this friendlier to
    # PE files built by toolchains that internally resemble SysV lowering.
    state.regs.rcx = INPUT_BASE
    state.regs.rdx = OUTPUT_BASE
    state.regs.rdi = INPUT_BASE
    state.regs.rsi = OUTPUT_BASE

    returned_state = execute_single_path(project, state, RET_ADDR, progress, checker_va, len(checker_code))
    if returned_state is None:
        raise RuntimeError("checker did not return under symbolic execution")
    log_status(progress, output_enabled, "ok", "symbolic execution completed")

    progress.update(82.0, "phase=z3_solve")
    solved_state = None
    candidate = returned_state.copy()
    output_byte = candidate.memory.load(OUTPUT_BASE, 1)
    candidate.solver.add(output_byte != 0)
    if candidate.solver.satisfiable():
        solved_state = candidate

    if solved_state is None:
        raise RuntimeError("checker returned, but output[0] could not be true")
    log_status(progress, output_enabled, "ok", "z3 model solved")

    progress.update(94.0, "phase=extract_model")
    bit_values = [solved_state.solver.eval(bit, cast_to=int) & 1 for bit in symbolic_bits]
    bit_string = "".join(str(bit) for bit in bit_values)
    progress.finish("solved")

    password = bits_to_password(bit_values) if bit_count % 8 == 0 else None
    elapsed = time.perf_counter() - solve_start
    gate_counts = Counter(name for _, _, name in gate_sequence)
    run_result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "solver": "angr-z3",
        "exe": str(path),
        "sha256": sha256_file(path),
        "checker_va": f"{checker_va:#x}",
        "input_bits": bit_count,
        "hooked_gate_functions": len(gate_targets),
        "hooked_hardening_helpers": len(hardening_targets),
        "hooked_runtime_helpers": len(runtime_targets),
        "gate_calls": len(gate_sequence),
        "gates": len(gate_sequence),
        "gate_counts": dict(sorted(gate_counts.items())),
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

    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("-h", "--help", "--h", action="help", help="Show this help message and exit")
    parser.add_argument("exe", type=Path, nargs="?", help="Path to the compiled SBHA-style PE executable")
    parser.add_argument("--checker-va", type=parse_int, help="Checker function virtual address")
    parser.add_argument("--bits", type=int, help="Input bit count override")
    parser.add_argument("--dump-hooks", action="store_true", help="Print hooked gate helper addresses")
    parser.add_argument("--json-out", type=Path, help="Write solve result as JSON")
    parser.add_argument("--summary", action="store_true", help="Print a compact one-line summary")
    parser.add_argument("--no-progress", action="store_true", help="Disable animated progress output")
    parser.add_argument("--csv-log", type=Path, metavar="runs.csv", help="Append run result to a CSV log")
    parser.add_argument("--verify-run", action="store_true", help="Run the EXE with the recovered password and check for success text")
    parser.add_argument("--gate-stats", action="store_true", help="Print gate call statistics")
    parser.add_argument("--dump-gates", nargs="?", const="-", metavar="gates.txt", help="Write recovered gate/hook structure to a file, or stdout if no file is given")
    parser.add_argument("--quiet", action="store_true", help="Print only the recovered password, or bits if not byte-aligned")
    parser.add_argument("--verbose", "--v", "-v", action="store_true", help="Print extra diagnostic metadata")
    parser.add_argument("--depend", action="store_true", help="Check solver dependencies and exit")
    args = parser.parse_args(argv)

    if args.depend:
        print_dependencies()
        return 0
    if args.exe is None:
        parser.error("exe is required unless --depend is used")

    return solve_with_angr(args.exe, args.checker_va, args.bits, args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
