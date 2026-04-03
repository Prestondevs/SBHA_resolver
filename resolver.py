import z3

def analyze_gates(input_gates: int):

    # 1 char = 8 bits, 16 chars = 128
    chars = z3.BitVec('chars', 128)
    solver = z3.Solver()

    # printable ascii char restraints " " - "~"
    solver.add(chars > 0x20)
    solver.add(chars < 0x7E)

    return solver.model()


if __name__ == "__main__":
    analyze_gates(16)