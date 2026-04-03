import z3

#1 char = 8 bits, 16 chars = 128
input = z3.BitVec('char', 128)
solver = z3.Solver()

#printable ascii char restraints " " & ""
solver.add(char > 0x20)
solver.add(char < 0x7E)


