import z3

input = z3.BitVec('char', 128)
solver = z3.Solver()

solver.add(char > 0x20)
solver.add(char < 0x7E)


