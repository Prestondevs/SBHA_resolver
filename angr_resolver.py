import angr
import claripy

password_length = 16

base_address = 0x140000000 #entry
success_address = 0x1400127b5 #success "access granted!"
failure_address = 0x14001299a #failed "access denied!"

project = angr.Project("./executables/sbha_16.exe", main_opts={"base_address": base_address})
flag_chars = [claripy.BVS(f"flag_char{i}", 8) for i in range(password_length)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')]) # enters the password

state = project.factory.full_init_state(
    args = ["/executables/sbha_16.exe"],
            add_options={angr.options.UNICORN},
            stdin=flag
)

for k in flag_chars:
    state.solver.add(flag_chars[-1] != 0x0a)
    state.solver.add(k >= 0x20)
    state.solver.add(k <= 0x7E)


sim_manager = project.factory.simulation_manager(state)
sim_manager.explore(find=success_address, avoid=failure_address)

if sim_manager.found:
    for found in sim_manager.found:
        print(found.posix.dump(0))