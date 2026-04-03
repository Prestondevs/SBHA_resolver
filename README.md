# sbha_16 angr Password Solver

Symbolic execution solver for `sbha_16.exe`, a CTF-style "Secure Login System"
binary. The binary reads a password, runs it through a custom validation
routine, and either prints **Access granted!** (and decodes a hidden flag) or
**Access denied!**. Instead of reversing the validation by hand, this script
lets [angr](https://angr.io/) find a satisfying password automatically.

## How the binary works (Ghidra analysis)

```
main loop
│
├─ print "Password: "
├─ read password string  →  local_f0  (std::string)
│
├─ expand password into a 128-byte bit array  (local_98)
│   each byte of the password produces 8 bits → 0x00 or 0x01
│
├─ print the bit array as "Binary representation: 0100..."
│
├─ call thunk_FUN_1400102f0(local_98, local_117)
│   validation: sets local_117[0] = 0x01 on success, 0x00 on failure
│
├─ [FAIL]  local_117[0] == 0  →  "Access denied!"
│
└─ [PASS]  local_117[0] != 0  →  "Access granted!"
    XOR-decrypt 47-byte flag with the password (cycling key) and print it
```

The flag is stored as the `local_d0` byte array (47 bytes, indices 0x00 to 0x2e).
Each byte is XOR'd with `password[ i % len(password) ]`.

## Bug fixes applied to the original script

| # | Problem in original | Fix |
|---|---|---|
| 1 | `flag_chars[-1] != 0x0a` inside the `for k in flag_chars` loop — only the **last** character got the newline exclusion constraint; all other characters could be `\n` | Moved the `!= 0x0A` constraint inside the loop so it applies to **every** character |
| 2 | `stdin=flag` passed a raw `claripy.BVV` bitvector directly — angr expects a `SimFile` object for structured stdin | Changed to `stdin=angr.SimFile(name="stdin", content=flag, size=password_length + 1)` |
| 3 | `found.posix.dump(0)` dumps the entire stdin buffer as raw bytes, making the output unreadable and including the trailing newline | Replaced with per-character `solver.eval(k, cast_to=bytes)` and decoded as ASCII |

## Requirements

```
pip install angr
```

angr pulls in claripy automatically. A 64-bit Python 3.10+ environment is
recommended; angr's Windows PE support requires the `pefile` extra and a
working `unicorn` install.

## Usage

```bash
python solve.py
```

Expected output (example; actual password depends on the binary):

```
[+] Password found: S0m3P4ssw0rd1234
```

Place `sbha_16.exe` inside an `executables/` subdirectory next to `solve.py`,
or edit the path constants at the top of the script.

## Configuration

| Constant | Default | Description |
|---|---|---|
| `password_length` | `16` | Number of symbolic characters angr explores |
| `base_address` | `0x140000000` | PE image base (match Ghidra's rebase address) |
| `success_address` | `0x1400127b5` | Address of the "Access granted!" branch |
| `failure_address` | `0x14001299a` | Address of the "Access denied!" branch |

If you rebase the binary in Ghidra, update `base_address` to match.

## Notes

`UNICORN` mode is enabled for faster concrete execution of non-symbolic blocks. The printable ASCII constraint (`0x20` to `0x7E`) prunes the search space significantly and prevents angr from finding unprintable solutions. angr may find multiple satisfying inputs and the script prints all of them. Execution can be slow (5 to 30 min) depending on the complexity of the validation function; consider adding a `timeout` to `sim_manager.explore()` for long runs.