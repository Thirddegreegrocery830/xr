#!/usr/bin/env python3
"""
Analyze GOT slots for libharlem-shake.so:
- Identify all GLOB_DAT + JUMP_SLOT relocations to undef symbols
- Sort by GOT slot address
- Assign sequential extern VAs (IDA's confirmed algorithm)
- Scan the binary for FF 15 (CALL [RIP+disp]) and FF 25 (JMP [RIP+disp])
  to find which GOT slots are actually referenced by code
- Compare with IDA ground truth xrefs to understand the "skip" criterion
"""
import json
import struct
import sys
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("pip install pyelftools")
    sys.exit(1)

BINARY = Path(__file__).parent.parent / "testcases" / "TARGET_BINARY"
XREFS  = Path(__file__).parent.parent / "testcases" / "TARGET_BINARY.xrefs.json"
PIE_BASE = 0x400000

def main():
    with open(BINARY, "rb") as f:
        elf = ELFFile(f)
        data = f.read()  # read full file for binary scanning

    with open(BINARY, "rb") as f:
        data = f.read()

    with open(BINARY, "rb") as f:
        elf = ELFFile(f)

        # ── 1. Collect PT_LOAD segments ────────────────────────────────────────
        pt_loads = []
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                pt_loads.append((seg.header.p_vaddr, seg.header.p_memsz))
        extern_base = max(va + msz for va, msz in pt_loads) + PIE_BASE + 0x20
        print(f"extern_base = {extern_base:#x}")

        # ── 2. Collect GLOB_DAT + JUMP_SLOT relocations to SHN_UNDEF symbols ──
        dynsym = elf.get_section_by_name(".dynsym")
        rela_dyn  = elf.get_section_by_name(".rela.dyn")
        rela_plt  = elf.get_section_by_name(".rela.plt")

        # Build undef symbol set (by dynsym index)
        undef_syms = {}  # idx -> name
        for i, sym in enumerate(dynsym.iter_symbols()):
            if sym.entry.st_shndx == "SHN_UNDEF":
                undef_syms[i] = sym.name

        print(f"\nTotal SHN_UNDEF symbols in .dynsym: {len(undef_syms)}")

        # Collect all GLOB_DAT (type 6) and JUMP_SLOT (type 7) relocs to undef syms
        # R_X86_64_GLOB_DAT = 6, R_X86_64_JUMP_SLOT = 7
        R_X86_64_GLOB_DAT  = 6
        R_X86_64_JUMP_SLOT = 7

        relocs = []
        for relsec in [rela_dyn, rela_plt]:
            if relsec is None:
                continue
            for rel in relsec.iter_relocations():
                rtype = rel.entry.r_info_type
                sym_idx = rel.entry.r_info_sym
                if rtype in (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT):
                    if sym_idx in undef_syms:
                        got_va = rel.entry.r_offset + PIE_BASE  # rebased GOT slot VA
                        sym_name = undef_syms[sym_idx]
                        sym = dynsym.get_symbol(sym_idx)
                        bind = sym.entry.st_info["bind"]   # STB_GLOBAL / STB_WEAK
                        stype = sym.entry.st_info["type"]  # STT_FUNC / STT_NOTYPE
                        relocs.append({
                            "got_va": got_va,
                            "sym_idx": sym_idx,
                            "sym_name": sym_name,
                            "bind": bind,
                            "type": stype,
                            "rtype": "GLOB_DAT" if rtype == R_X86_64_GLOB_DAT else "JUMP_SLOT",
                            "section": relsec.name,
                        })

        # Sort by GOT slot address (IDA's assignment order)
        relocs.sort(key=lambda r: r["got_va"])

        print(f"Total GLOB_DAT+JUMP_SLOT relocs to SHN_UNDEF: {len(relocs)}")

        # Assign extern VAs sequentially
        for i, r in enumerate(relocs):
            r["extern_va"] = extern_base + i * 8

    # ── 3. Scan the binary for FF 15 xx xx xx xx (CALL [RIP+disp32]) ──────────
    #    and FF 25 xx xx xx xx (JMP  [RIP+disp32])
    # We need to find the file offset → VA mapping for each PT_LOAD
    with open(BINARY, "rb") as f:
        elf2 = ELFFile(f)
        load_segs = []
        for seg in elf2.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                load_segs.append({
                    "file_off": seg.header.p_offset,
                    "file_sz":  seg.header.p_filesz,
                    "va":       seg.header.p_vaddr + PIE_BASE,
                    "exec":     bool(seg.header.p_flags & 1),
                })

    def file_offset_to_va(off):
        for seg in load_segs:
            if seg["file_off"] <= off < seg["file_off"] + seg["file_sz"]:
                return seg["va"] + (off - seg["file_off"])
        return None

    # Build a map: got_va → reloc info
    got_va_to_reloc = {r["got_va"]: r for r in relocs}

    # Scan executable segments for FF 15 / FF 25
    referenced_got_vas = set()  # GOT slot VAs actually referenced by code
    call_refs = {}   # got_va -> list of (from_va, 'CALL')
    jmp_refs  = {}   # got_va -> list of (from_va, 'JMP')

    for seg in load_segs:
        if not seg["exec"]:
            continue
        seg_data = data[seg["file_off"]: seg["file_off"] + seg["file_sz"]]
        base_va = seg["va"]
        for i in range(len(seg_data) - 5):
            b0, b1 = seg_data[i], seg_data[i+1]
            if b0 == 0xff and b1 in (0x15, 0x25):
                disp = struct.unpack_from("<i", seg_data, i + 2)[0]
                # RIP = VA of next instruction = base_va + i + 6
                next_ip = base_va + i + 6
                got_va = next_ip + disp
                if got_va in got_va_to_reloc:
                    referenced_got_vas.add(got_va)
                    if b1 == 0x15:
                        call_refs.setdefault(got_va, []).append((base_va + i, "CALL"))
                    else:
                        jmp_refs.setdefault(got_va, []).append((base_va + i, "JMP"))

    print(f"\nGOT slots referenced by CALL [RIP+disp] or JMP [RIP+disp]: {len(referenced_got_vas)}")
    unreferenced = [r for r in relocs if r["got_va"] not in referenced_got_vas]
    print(f"GOT slots NOT referenced by any CALL/JMP in code: {len(unreferenced)}")

    # ── 4. Load IDA ground truth and find which extern VAs appear ────────────
    with open(XREFS) as f:
        xrefs_data = json.load(f)

    # Collect all extern-segment target VAs from IDA (addresses >= extern_base)
    ida_extern_targets = set()
    ida_extern_calls = set()   # extern VAs that are targets of Call xrefs
    for x in xrefs_data:
        to_va = x.get("to") or x.get("to_va") or x.get("target")
        if to_va is None:
            # Try different key names
            for k in x:
                if "to" in k.lower() or "target" in k.lower():
                    to_va = x[k]
                    break
        if to_va is not None and to_va >= extern_base:
            ida_extern_targets.add(to_va)
            kind = x.get("kind") or x.get("type") or x.get("xref_type", "")
            if isinstance(kind, str) and "call" in kind.lower():
                ida_extern_calls.add(to_va)

    print(f"\nIDA extern segment xref targets: {len(ida_extern_targets)}")
    print(f"IDA extern segment Call xref targets: {len(ida_extern_calls)}")

    # Map our predicted extern VAs back to IDA targets
    predicted_extern_vas = {r["extern_va"] for r in relocs}
    matched = ida_extern_targets & predicted_extern_vas
    unmatched_ida = ida_extern_targets - predicted_extern_vas
    print(f"\nMatched (predicted ∩ IDA): {len(matched)}")
    print(f"IDA targets not in our predictions: {len(unmatched_ida)}")

    # ── 5. Cross-reference: assigned (in IDA) vs skipped ──────────────────────
    print("\n── All relocs, sorted by GOT slot VA ──────────────────────────────────")
    print(f"{'idx':>4}  {'GOT VA':>12}  {'extern_VA':>12}  {'in_IDA':>6}  {'code_ref':>8}  "
          f"{'bind':>10}  {'type':>10}  {'reloc':>10}  name")
    for i, r in enumerate(relocs):
        in_ida = "YES" if r["extern_va"] in ida_extern_targets else "NO"
        is_called = "YES" if r["got_va"] in referenced_got_vas else "NO"
        print(f"{i:>4}  {r['got_va']:#012x}  {r['extern_va']:#012x}  {in_ida:>6}  "
              f"{is_called:>8}  {r['bind']:>10}  {r['type']:>10}  {r['rtype']:>10}  {r['sym_name']}")

    # ── 6. Summary: what predicts IDA skip? ───────────────────────────────────
    print("\n── Skipped by IDA (extern_va NOT in IDA xrefs) ────────────────────────")
    skipped = [r for r in relocs if r["extern_va"] not in ida_extern_targets]
    print(f"Total skipped: {len(skipped)}")
    for r in skipped:
        is_called = "called" if r["got_va"] in referenced_got_vas else "NOT_called"
        print(f"  {r['got_va']:#x} → {r['extern_va']:#x}  {is_called:11}  "
              f"{r['bind']:10} {r['type']:10} {r['rtype']:10}  {r['sym_name']}")

    # ── 7. Correlation: code_ref vs in_IDA ────────────────────────────────────
    both = sum(1 for r in relocs if r["got_va"] in referenced_got_vas and r["extern_va"] in ida_extern_targets)
    code_only = sum(1 for r in relocs if r["got_va"] in referenced_got_vas and r["extern_va"] not in ida_extern_targets)
    ida_only = sum(1 for r in relocs if r["got_va"] not in referenced_got_vas and r["extern_va"] in ida_extern_targets)
    neither = sum(1 for r in relocs if r["got_va"] not in referenced_got_vas and r["extern_va"] not in ida_extern_targets)

    print(f"\n── Correlation: code reference vs IDA assignment ──────────────────────")
    print(f"  code_ref=YES, in_IDA=YES : {both}")
    print(f"  code_ref=YES, in_IDA=NO  : {code_only}")
    print(f"  code_ref=NO,  in_IDA=YES : {ida_only}")
    print(f"  code_ref=NO,  in_IDA=NO  : {neither}")

    if code_only == 0 and neither == len(skipped):
        print("\n✓ PERFECT CORRELATION: IDA assigns extern VA iff the GOT slot is referenced by code!")
    elif code_only == 0:
        print(f"\n✓ All code-referenced slots are in IDA. {ida_only} IDA slots have no code ref (IDA might use other criteria too).")
    else:
        print(f"\n✗ Imperfect: {code_only} code-referenced slots are NOT in IDA ground truth")

    # ── 8. For our purposes: just emit got_map for all code-referenced slots ──
    print(f"\n── Summary for got_map implementation ─────────────────────────────────")
    print(f"  Total GOT slots: {len(relocs)}")
    print(f"  Slots referenced by CALL/JMP in code: {len(referenced_got_vas)}")
    print(f"  IDA-assigned extern VAs: {len(matched)}")
    print(f"  Recommendation: emit got_map for ALL {len(relocs)} slots (sequential VAs)")
    print(f"  TP calls expected: ~{both + ida_only} (all IDA-assigned slots)")

    # ── 9. Print JSON for got_map: got_va -> extern_va ────────────────────────
    print(f"\n── got_map (first 10 entries) ─────────────────────────────────────────")
    for r in relocs[:10]:
        print(f"  {r['got_va']:#x} -> {r['extern_va']:#x}  ({r['sym_name']})")

    # Check the xref JSON structure
    print(f"\n── Sample IDA xref record ─────────────────────────────────────────────")
    for x in xrefs_data[:3]:
        print(f"  {x}")


if __name__ == "__main__":
    main()
