import z3

#input_gates = length of password & returns solver.model or if unsat none/null
def analyze_gates(input_gates: int) -> modelRef | None:

    # 1 char = 8 bits, 16 chars = 128
    chars = z3.BitVec('chars', input_gates*8)
    solver = z3.Solver()

    # printable ascii char restraints " " - "~"
    solver.add(chars > 0x20)
    solver.add(chars < 0x7E)

    return solver.model()


if __name__ == "__main__":
    analyze_gates(16)