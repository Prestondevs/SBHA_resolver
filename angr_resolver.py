import angr
import claripy

password_length = 16

base_address = 0x
success_address = 0x
failure_address = 0x

project = angr.project(".\executables\sbha_16.exe", main_opts = {"base_address" : base_address})
flag_chars = [claripy.BVS(f"flag_char{i}", 8) for i in range(password_length)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')]) # enters the password

state = project.factory.full_init_state(
    args = [".\executables\sbha_16.exe"],
            add_options = angr.options.unicorn,
            stdin=flag
)

for k in flag_chars:
    state.solver.add(k >= 0x20)
    state.solver.add(k <= 0x7E)
sim_manager = project.factory.simulation_manager(state)
sim_manager.explore(find=success_address, avoid=failure_address)

if sim_manager.found > 0:
    for found in sim_manager.found:
        print(found.posix.dump(0))