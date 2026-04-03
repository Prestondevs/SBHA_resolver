import angr
import claripy

# The binary reads exactly 16 characters via std::getline (source confirmed).
# runprogram1 checks all 128 bits of the password in one giant AND chain,
# so the password is a single fixed value — angr will find it via SAT.
password_length = 16

main_address    = 0x1400125e0  # FUN_1400125e0 (main)
success_address = 0x1400127b5  # "Access granted!"
failure_address = 0x14001299a  # "Access denied!"

project = angr.Project(
    "./executables/sbha_16.exe"
)

# std::getline reads until '\n', so the newline terminates the line but is NOT
# part of pw — match exactly what the source does.
flag_chars = [claripy.BVS(f"flag_char_{i}", 8) for i in range(password_length)]
flag = claripy.Concat(*flag_chars, claripy.BVV(b"\n"))

# full_init_state is required here because the binary uses std::cin / std::getline
# which depend on the C++ runtime being properly initialized.
state = project.factory.full_init_state(
    args=["./executables/sbha_16.exe"],
    add_options={
        angr.options.UNICORN,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    },
    stdin=angr.SimFile(name="stdin", content=flag, size=password_length + 1),
)

# Constrain every character to printable ASCII, non-newline
for k in flag_chars:
    state.solver.add(k != 0x0A)  # not newline
    state.solver.add(k >= 0x20)  # printable low bound
    state.solver.add(k <= 0x7E)  # printable high bound

sim_manager = project.factory.simulation_manager(state)
sim_manager.explore(find=success_address, avoid=failure_address)

if sim_manager.found:
    for found in sim_manager.found:
        password_bytes = b"".join(
            found.solver.eval(k, cast_to=bytes) for k in flag_chars
        )
        print(f"[+] Password found: {password_bytes.decode('ascii', errors='replace')}")
else:
    print("[-] No solution found.")