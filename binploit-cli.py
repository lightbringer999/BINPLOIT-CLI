#!/usr/bin/env python3
from pwn import *
import sys
import json
from pwnlib.term.text import cyan, green, white
def banner():
    print(cyan(r"""
██████╗ ██╗███╗   ██╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔══██╗██║████╗  ██║██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██████╔╝██║██╔██╗ ██║██████╔╝██║     ██║   ██║██║   ██║   
██╔══██╗██║██║╚██╗██║██╔═══╝ ██║     ██║   ██║██║   ██║   
██████╔╝██║██║ ╚████║██║     ███████╗╚██████╔╝██║   ██║   
╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
"""))
    print(green("   binploit-cli :: Stack BOF Analyzer"))
    print(white("   Version : v1.0"))
    print(white("   Author  : lightbringer999\n"))

banner()


context.os = "linux"
context.log_level = "error"


if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <binary>")
    sys.exit(1)


binary = sys.argv[1]
elf = ELF(binary)
context.binary = elf

arch = elf.arch
bits = 64 if arch == "amd64" else 32


results = {
    "binary": binary,
    "architecture": arch,
    "bits": bits,
    "protections": {},
    "stack": {},
    "libc": {}
}


results["protections"] = {
    "PIE": elf.pie,
    "NX": elf.nx,
    "Canary": elf.canary,
    "RELRO": elf.relro
}


pattern = cyclic(1000)

p = process(binary)
p.sendline(pattern)
p.wait()

core = p.corefile

if bits == 64:
    crash_value = core.read(core.rsp, 8)
    offset = cyclic_find(crash_value)
else:
    offset = cyclic_find(core.eip)

results["stack"]["offset"] = offset

def get_symbol(obj, name):
    return hex(obj[name]) if name in obj else None

results["stack"]["puts_plt"] = get_symbol(elf.plt, "puts")
results["stack"]["puts_got"] = get_symbol(elf.got, "puts")
results["stack"]["main"] = get_symbol(elf.symbols, "main")

wins = []
for sym in elf.symbols:
    if "win" in sym.lower():
        wins.append({sym: hex(elf.symbols[sym])})

results["stack"]["win_functions"] = wins if wins else None

libc = elf.libc
results["libc"]["path"] = libc.path

results["libc"]["system"] = hex(libc.symbols["system"])
results["libc"]["exit"] = hex(libc.symbols["exit"])
results["libc"]["bin_sh"] = hex(next(libc.search(b"/bin/sh")))

print("\n[+] binploit-cli :: Stack BOF Analysis\n")
print(json.dumps(results, indent=4))

output_file = binary.split("/")[-1] + "stack_analysis.json"
with open(output_file, "w") as f:

    json.dump(results,f,indent=4)
print(f"\n[+] Results written to: {output_file}")
