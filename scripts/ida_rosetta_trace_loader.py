"""
IDA Pro loader plugin for Rosetta hardware trace files.

Parses trace files produced by:
  ROSETTA_HARDWARE_TRACING_PATH=/path/to/trace ./runtime_loader ./binary

Loads all Type 3 (JIT Code Emitted) records as ARM64 code segments,
allowing disassembly and analysis of Rosetta's JIT output.

The rt_routines segment is a copy of the runtime binary's stub page. Stub
functions are labeled at their offsets within it.

Two stub layouts are supported:

  stock  -- the reference Rosetta runtime's page at 0x20000 (98 stubs, from the
            g_rt_* pointer table at 0x31080). This is the built-in table.
  custom -- rosettax87's own runtime_entry.S blob, which runtime_loader maps over
            that region. Its layout differs for most stubs and adds xrstor/xsave,
            so the stock table mislabels nearly everything on such a trace.

Generate the custom table with:
  scripts/extract_stub_offsets.py -o stub_offsets.json

The loader finds it via $ROSETTA_STUB_OFFSETS, or as stub_offsets.json beside the
trace file, beside this script, or in build/. Selection is controlled by
$ROSETTA_STUB_LAYOUT = auto (default) | custom | stock.

Installation:
  Copy (or symlink) this file to <IDA>/loaders/
  e.g. /Applications/IDA Professional 9.3.app/Contents/MacOS/loaders/
"""

import json
import os
import struct
import ida_idaapi
import ida_ida
import ida_funcs
import ida_loader
import ida_segment
import ida_bytes
import ida_entry
import ida_name
import ida_idp
import ida_kernwin
import ida_ua
import ida_xref
import idc


HEADER_SIZE = 48
HEADER_FMT = '<6Q'

EVENT_TYPE_JIT_CREATED = 1
EVENT_TYPE_AOT_FREED = 2
EVENT_TYPE_JIT_CODE = 3
EVENT_TYPE_JIT_FREED = 4
EVENT_TYPE_RT_ROUTINES = 5
EVENT_TYPE_RT_BINARY = 6

VALID_EVENT_TYPES = {1, 2, 3, 4, 5, 6}

PAGE_SIZE = 0x4000
COALESCE_GAP = 0x100000

# (offset_from_base, size, name)
# Derived from runtime.i64 g_rt_* pointer table at 0x31080.
# The rt_routines page is a 0x4000-byte copy of the stub page at 0x20000.
# Offsets here are target_addr - 0x20000, names match the dereferenced stubs.
RT_ROUTINE_STUBS = [
    (0x0000, 0x34, "stub_far_jmp"),
    (0x0034, 0x34, "stub_far_ret"),
    (0x0068, 0x34, "stub_far_call"),
    (0x009C, 0x34, "stub_far_ret_single_step"),
    (0x00D0, 0x34, "stub_mov_segment"),
    (0x0104, 0x34, "stub_mov_segment_and_reg"),
    (0x0138, 0x64, "stub_indirect_jmp"),
    (0x019C, 0x64, "stub_indirect_call"),
    (0x0200, 0x34, "stub_syscall_handler"),
    (0x0234, 0x34, "stub_toggle_single_step"),
    (0x0268, 0x34, "stub_load_segment_limit"),
    (0x029C, 0x34, "stub_rdrand"),
    (0x02D0, 0x64, "stub_mxcsr_to_fpcr_fpsr"),
    (0x0334, 0x68, "stub_read_mxcsr"),
    (0x039C, 0x34, "stub_pcmpestri"),
    (0x03D0, 0x34, "stub_pcmpestrm"),
    (0x0404, 0x34, "stub_pcmpistri"),
    (0x0438, 0x34, "stub_pcmpistrm"),
    (0x046C, 0x34, "stub_f2xm1"),
    (0x04A0, 0x34, "stub_fabs"),
    (0x04D4, 0x34, "stub_fchs"),
    (0x0508, 0x34, "stub_fcos"),
    (0x053C, 0x34, "stub_fdecstp"),
    (0x0570, 0x34, "stub_fincstp"),
    (0x05A4, 0x34, "stub_fpatan"),
    (0x05D8, 0x34, "stub_fprem"),
    (0x060C, 0x34, "stub_fprem1"),
    (0x0640, 0x34, "stub_fptan"),
    (0x0674, 0x34, "stub_frndint"),
    (0x06A8, 0x34, "stub_fscale"),
    (0x06DC, 0x34, "stub_fsin"),
    (0x0710, 0x34, "stub_fsincos"),
    (0x0744, 0x34, "stub_fsqrt"),
    (0x0778, 0x34, "stub_fxam"),
    (0x07AC, 0x34, "stub_fxtract"),
    (0x07E0, 0x34, "stub_fyl2x"),
    (0x0814, 0x34, "stub_fyl2xp1"),
    (0x0848, 0x34, "stub_fbstp"),
    (0x087C, 0x34, "stub_ffree"),
    (0x08B0, 0x34, "stub_fild"),
    (0x08E4, 0x34, "stub_fld_STi"),
    (0x0918, 0x34, "stub_fld_constant"),
    (0x094C, 0x34, "stub_fld_fp32"),
    (0x0980, 0x34, "stub_fld_fp64"),
    (0x09B4, 0x34, "stub_fxch"),
    (0x09E8, 0x34, "stub_fadd_f32"),
    (0x0A1C, 0x34, "stub_fadd_f64"),
    (0x0A50, 0x34, "stub_fdiv_f32"),
    (0x0A84, 0x34, "stub_fdiv_f64"),
    (0x0AB8, 0x34, "stub_fdivr_f32"),
    (0x0AEC, 0x34, "stub_fdivr_f64"),
    (0x0B20, 0x34, "stub_fiadd"),
    (0x0B54, 0x34, "stub_fidiv"),
    (0x0B88, 0x34, "stub_fidivr"),
    (0x0BBC, 0x34, "stub_fimul"),
    (0x0BF0, 0x34, "stub_fisub"),
    (0x0C24, 0x34, "stub_fisubr"),
    (0x0C58, 0x34, "stub_fmul_f32"),
    (0x0C8C, 0x34, "stub_fmul_f64"),
    (0x0CC0, 0x34, "stub_fsub_f32"),
    (0x0CF4, 0x34, "stub_fsub_f64"),
    (0x0D28, 0x34, "stub_fsubr_f32"),
    (0x0D5C, 0x34, "stub_fsubr_f64"),
    (0x0D90, 0x34, "stub_fist_i16"),
    (0x0DC4, 0x34, "stub_fist_i32"),
    (0x0DF8, 0x34, "stub_fist_i64"),
    (0x0E2C, 0x34, "stub_fistt_i16"),
    (0x0E60, 0x34, "stub_fistt_i32"),
    (0x0E94, 0x34, "stub_fistt_i64"),
    (0x0EC8, 0x34, "stub_fst_fp32"),
    (0x0EFC, 0x34, "stub_fst_fp64"),
    (0x0F30, 0x34, "stub_fst_fp80"),
    (0x0F64, 0x34, "stub_fbld"),
    (0x0F98, 0x34, "stub_fld_fp80"),
    (0x0FCC, 0x34, "stub_fcmov"),
    (0x1000, 0x34, "stub_fcom_f32"),
    (0x1034, 0x34, "stub_fcom_f64"),
    (0x1068, 0x34, "stub_fcom_ST"),
    (0x109C, 0x34, "stub_fcomi"),
    (0x10D0, 0x34, "stub_ficom"),
    (0x1104, 0x34, "stub_fst_STi"),
    (0x1138, 0x34, "stub_fucom"),
    (0x116C, 0x34, "stub_fucomi"),
    (0x11A0, 0x34, "stub_fadd_ST"),
    (0x11D4, 0x34, "stub_fdiv_ST"),
    (0x1208, 0x34, "stub_fdivr_ST"),
    (0x123C, 0x34, "stub_fmul_ST"),
    (0x1270, 0x34, "stub_fsub_ST"),
    (0x12A4, 0x34, "stub_fsubr_ST"),
    (0x12D8, 0x40, "stub_read_timer_nanoseconds"),
    (0x1318, 0x34, "stub_indirect_jmp_dyld_stub"),
    (0x134C, 0x0C, "stub_get_cpu_number"),
    (0x1358, 0x0C, "stub_get_tls_base"),
    (0x1364, 0x0C, "stub_cpuid"),
    (0x22C8, 0x34, "stub_branch_slot"),
    (0x22FC, 0x64, "stub_return_stack_miss"),
    (0x27D8, 0x08, "stub_wide_udiv_64"),
    (0x27E0, 0x08, "stub_wide_sdiv_64"),
]


# ── Custom (rosettax87) stub layout ───────────────────────────────────────────
#
# RT_ROUTINE_STUBS above describes the STOCK Rosetta runtime's stub page. When a
# trace is produced under rosettax87's runtime_loader, our own runtime_entry.S
# blob is mapped over that region instead, and the layouts differ for most stubs
# (86 of 98 measured) plus we add xrstor/xsave. Using the stock table on such a
# trace mislabels nearly every stub.
#
# scripts/extract_stub_offsets.py reads the linked libRuntimeRosettax87 symbol
# table and writes the same triples as JSON. Point STUB_OFFSETS_JSON at it, or
# drop stub_offsets.json next to this file / in the trace's directory.
STUB_OFFSETS_ENV = "ROSETTA_STUB_OFFSETS"
STUB_OFFSETS_BASENAME = "stub_offsets.json"

# Which table to use. "auto" prefers the extracted one when it is found AND its
# blob size matches the traced region, else falls back to stock.
#   auto | custom | stock
LAYOUT_MODE_ENV = "ROSETTA_STUB_LAYOUT"


def _candidate_json_paths(trace_path):
    """Where to look for the extracted offsets, most specific first."""
    paths = []
    env = os.environ.get(STUB_OFFSETS_ENV)
    if env:
        paths.append(env)
    if trace_path:
        paths.append(os.path.join(os.path.dirname(os.path.abspath(trace_path)),
                                  STUB_OFFSETS_BASENAME))
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, STUB_OFFSETS_BASENAME))
    # Also try the repo layout: <repo>/scripts/../build/bin next to scripts/.
    paths.append(os.path.join(here, "..", "build", STUB_OFFSETS_BASENAME))
    return paths


def _load_custom_stubs(trace_path):
    """Load extracted stub triples. Returns (stubs, blob_size, source) or None."""
    for path in _candidate_json_paths(trace_path):
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            stubs = [(s["offset"], s["size"], s["name"]) for s in data["stubs"]]
            if not stubs:
                continue
            return stubs, data.get("blob_size", 0), path
        except Exception as exc:
            ida_kernwin.msg("  WARNING: could not read %s: %s\n" % (path, exc))
    return None


def _select_stub_layout(trace_path, rt_routines_size):
    """Pick the stub table to label with.

    Returns (stubs, description). Honours ROSETTA_STUB_LAYOUT:
      stock  — always the built-in reference table
      custom — the extracted table; errors out loudly if unavailable
      auto   — extracted when present and consistent, else stock
    """
    mode = os.environ.get(LAYOUT_MODE_ENV, "auto").strip().lower()

    if mode == "stock":
        return RT_ROUTINE_STUBS, "stock (forced by %s)" % LAYOUT_MODE_ENV

    loaded = _load_custom_stubs(trace_path)

    if mode == "custom":
        if not loaded:
            ida_kernwin.warning(
                "%s=custom but no %s found.\nRun scripts/extract_stub_offsets.py "
                "-o %s" % (LAYOUT_MODE_ENV, STUB_OFFSETS_BASENAME, STUB_OFFSETS_BASENAME))
            return RT_ROUTINE_STUBS, "stock (custom requested but unavailable)"
        stubs, blob_size, path = loaded
        return stubs, "custom from %s (%d stubs)" % (path, len(stubs))

    # auto
    if not loaded:
        return RT_ROUTINE_STUBS, "stock (no %s found)" % STUB_OFFSETS_BASENAME

    stubs, blob_size, path = loaded
    # A traced region smaller than the extracted blob means the trace came from a
    # different build (or the stock runtime); labelling it with our table would
    # place stubs past the end of the segment.
    if rt_routines_size and blob_size and blob_size > rt_routines_size:
        return (RT_ROUTINE_STUBS,
                "stock (extracted blob 0x%X exceeds traced region 0x%X — "
                "mismatched build?)" % (blob_size, rt_routines_size))
    return stubs, "custom from %s (%d stubs)" % (path, len(stubs))


def _parse_records(li):
    """Parse all records from the trace file, returning raw tuples."""
    li.seek(0, 2)
    file_size = li.tell()
    li.seek(0)
    data = li.read(file_size)

    records = []
    offset = 0
    while offset + HEADER_SIZE <= len(data):
        fields = struct.unpack_from(HEADER_FMT, data, offset)
        event_type, mach_thread_port, f2, f3, f4, payload_len = fields

        if event_type not in VALID_EVENT_TYPES:
            break

        offset += HEADER_SIZE
        if offset + payload_len > len(data):
            break

        payload = data[offset:offset + payload_len]
        offset += payload_len
        offset += (8 - (payload_len % 8)) % 8

        records.append((event_type, mach_thread_port, f2, f3, f4, payload))

    return records


def _coalesce_ranges(sorted_ranges):
    if not sorted_ranges:
        return []

    merged = [sorted_ranges[0]]
    for start, end in sorted_ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + COALESCE_GAP:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _apply_rt_routine_labels(base, stubs, region_size=0):
    """Name and define functions for all known runtime routine stubs.

    Stubs falling outside [base, base+region_size) are skipped rather than
    labelled at a bogus address — that happens when the table and the traced
    region come from different builds.
    """
    count = 0
    skipped = 0
    for offset, size, name in stubs:
        if region_size and (offset < 0 or offset + size > region_size):
            skipped += 1
            continue
        addr = base + offset
        ida_name.set_name(addr, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        ida_funcs.add_func(addr, addr + size)
        count += 1
    if skipped:
        ida_kernwin.msg("  WARNING: %d stub(s) outside the traced region were skipped\n"
                        % skipped)
    return count


REG_X22 = 129 + 22
REG_X24 = 129 + 24
REG_X25 = 129 + 25


def _fixup_stub_branches(segments, page_align, rt_routines_base):
    """Mark BR/BLR to rt_routines stubs with proper xrefs.

    For BR Xn → stub: marks as tail call (fl_JN to the stub)
    For BLR Xn → stub: marks as call (fl_CN to the stub)

    This helps IDA understand function boundaries:
    - BR to stub_branch_slot = tail jump, function ends here
    - BLR to stub_branch_slot = call, execution continues at next insn
    """
    fixups = 0
    for seg_start, seg_end in segments:
        seg_start = page_align(seg_start, down=True)
        seg_end = page_align(seg_end, down=False)

        ea = seg_start
        while ea < seg_end and ea != ida_idaapi.BADADDR:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length == 0:
                ea += 4
                continue

            mnem = insn.get_canon_mnem()
            if mnem in ("BR", "BLR") and insn.ops[0].type == 1:
                target_reg = insn.ops[0].reg
                # Look backwards for LDR Xn, =<literal> that loaded the stub address
                stub_addr = _find_ldr_literal_for_reg(ea, seg_start, target_reg)
                if stub_addr and rt_routines_base and \
                        rt_routines_base <= stub_addr < rt_routines_base + PAGE_SIZE:
                    if mnem == "BR":
                        ida_xref.add_cref(ea, stub_addr, ida_xref.fl_JN | ida_xref.XREF_USER)
                    else:
                        ida_xref.add_cref(ea, stub_addr, ida_xref.fl_CN | ida_xref.XREF_USER)
                    fixups += 1

            ea += length

    ida_kernwin.msg("  Stub branch fixups: %d\n" % fixups)


def _find_ldr_literal_for_reg(branch_ea, seg_start, target_reg):
    """Walk backwards from branch_ea looking for LDR target_reg, =<addr>.

    In Rosetta JIT, this is typically:
      LDR X24, =stub_xxx    (literal pool at end of function)
    Returns the loaded address or None.
    """
    scan = branch_ea - 4
    for _ in range(16):
        if scan < seg_start:
            return None
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, scan) == 0:
            scan -= 4
            continue
        mnem = insn.get_canon_mnem()
        if mnem == "LDR" and insn.ops[0].type == 1 and insn.ops[0].reg == target_reg:
            # op[1] is the memory operand — for LDR Xn, [PC, #offset] (literal)
            # IDA resolves this as type o_mem (2) with addr field
            if insn.ops[1].type == 2:  # o_mem
                lit_addr = insn.ops[1].addr
                # Read the 8 bytes at the literal pool address
                val = ida_bytes.get_qword(lit_addr)
                if val:
                    return val
            elif insn.ops[1].type == 5:  # o_imm (some IDA versions)
                return insn.ops[1].value
            break
        # If we hit another instruction that writes to target_reg, stop
        if insn.ops[0].type == 1 and insn.ops[0].reg == target_reg:
            break
        scan -= 4
    return None



def _resolve_branch_targets(seg_start, seg_end):
    """Resolve BR/BLR → stub by finding MOV X22, #x86_addr above each branch.

    Adds a comment and code xref to the target jit_<addr> function.
    """
    ea = seg_start
    resolved = 0

    while ea < seg_end and ea != ida_idaapi.BADADDR:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length == 0:
            ea += 4
            continue

        mnem = insn.get_canon_mnem()
        if mnem in ("BLR", "BR"):
            scan = ea - 4
            for _ in range(12):
                if scan < seg_start:
                    break
                prev = ida_ua.insn_t()
                if ida_ua.decode_insn(prev, scan) == 0:
                    scan -= 4
                    continue
                pmnem = prev.get_canon_mnem()
                if pmnem in ("MOV", "MOVZ") and prev.ops[0].type == 1 \
                        and prev.ops[0].reg == REG_X22 and prev.ops[1].type == 5:
                    x86_target = prev.ops[1].value
                    jit_name = "jit_%X" % x86_target
                    jit_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, jit_name)
                    if jit_ea != ida_idaapi.BADADDR:
                        idc.set_cmt(ea, "-> %s (x86 0x%X)" % (jit_name, x86_target), 0)
                        ida_xref.add_cref(ea, jit_ea, ida_xref.fl_CN | ida_xref.XREF_USER)
                        resolved += 1
                    else:
                        idc.set_cmt(ea, "-> x86 0x%X (not in trace)" % x86_target, 0)
                    break
                scan -= 4

        ea += length

    return resolved


def accept_file(li, filename):
    """Check if this is a Rosetta hardware trace file."""
    li.seek(0)
    header = li.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        return 0

    fields = struct.unpack_from(HEADER_FMT, header, 0)
    event_type = fields[0]

    if event_type not in VALID_EVENT_TYPES:
        return 0

    if event_type == EVENT_TYPE_RT_BINARY:
        text_size = fields[3]
        if text_size == 0 or text_size > 0x10000000:
            return 0
    elif event_type == EVENT_TYPE_JIT_CODE:
        code_size = fields[3]
        payload_len = fields[5]
        if code_size != payload_len or code_size == 0:
            return 0
    elif event_type == EVENT_TYPE_RT_ROUTINES:
        pass
    else:
        return 0

    return {"format": "Rosetta Hardware Trace (ARM64 JIT)", "processor": "arm"}


def load_file(li, neflags, format):
    """Load the Rosetta trace file into the IDA database."""
    ida_idp.set_processor_type("arm", ida_idp.SETPROC_LOADER)

    ida_ida.inf_set_64bit(True)
    idc.set_inf_attr(idc.INF_COMPILER, 6)  # COMP_GNU = 6

    records = _parse_records(li)
    if not records:
        ida_kernwin.warning("No records found in trace file")
        return 0

    jit_records = []
    rt_binary_base = 0
    rt_routines_base = 0
    rt_routines_size = 0

    for rec in records:
        event_type, timestamp, f2, f3, f4, payload = rec
        if event_type == EVENT_TYPE_RT_BINARY:
            rt_binary_base = f2
        elif event_type == EVENT_TYPE_RT_ROUTINES:
            rt_routines_base = f2
            rt_routines_size = f3
        elif event_type == EVENT_TYPE_JIT_CODE:
            jit_records.append(rec)

    if not jit_records:
        ida_kernwin.warning("No JIT code records (Type 3) in trace")
        return 0

    ranges = sorted((r[2], r[2] + r[3]) for r in jit_records)
    segments = _coalesce_ranges(ranges)

    page_align = lambda addr, down=True: (addr & ~(PAGE_SIZE - 1)) if down else ((addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

    for idx, (seg_start, seg_end) in enumerate(segments):
        seg_start = page_align(seg_start, down=True)
        seg_end = page_align(seg_end, down=False)

        seg_name = "jit_%d" % idx if len(segments) > 1 else "jit_code"
        ida_segment.add_segm(0, seg_start, seg_end, seg_name, "CODE")

        seg_obj = ida_segment.getseg(seg_start)
        if seg_obj:
            seg_obj.perm = 5  # SEGPERM_READ(4) | SEGPERM_EXEC(1)
            seg_obj.bitness = 2  # 64-bit

    import ida_auto
    for idx, rec in enumerate(jit_records):
        event_type, mach_thr, arm64_addr, code_size, x86_addr, code_bytes = rec
        ida_bytes.put_bytes(arm64_addr, code_bytes)
        name = "jit_%X" % x86_addr
        ida_name.set_name(arm64_addr, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        ida_auto.auto_make_code(arm64_addr)

        comment = "x86_64: 0x%X | arm64: 0x%X | size: %d (0x%X) | thr: 0x%X | order: #%d" % (
            x86_addr, arm64_addr, code_size, code_size, mach_thr, idx)
        idc.set_cmt(arm64_addr, comment, 0)

    if rt_routines_base and rt_routines_size:
        ida_segment.add_segm(0, rt_routines_base,
                             rt_routines_base + rt_routines_size,
                             "rt_routines", "CODE")
        seg_obj = ida_segment.getseg(rt_routines_base)
        if seg_obj:
            seg_obj.bitness = 2
            seg_obj.perm = 5

        stub_table, layout_desc = _select_stub_layout(
            ida_loader.get_path(ida_loader.PATH_TYPE_CMD), rt_routines_size)
        ida_kernwin.msg("  Stub layout: %s\n" % layout_desc)

        stub_count = _apply_rt_routine_labels(rt_routines_base, stub_table,
                                              rt_routines_size)

        rt_comment = ("Rosetta runtime routines (trampolines/stubs)\n"
                      "Base: 0x%X  Size: 0x%X  Stubs: %d\n"
                      "Stub layout: %s\n"
                      "Runtime binary at: 0x%X" % (
                          rt_routines_base, rt_routines_size,
                          stub_count, layout_desc, rt_binary_base))
        idc.set_cmt(rt_routines_base, rt_comment, 0)

    first_addr = jit_records[0][2]
    ida_entry.add_entry(0, first_addr, "start", 0)

    header_cmt = ("Rosetta Hardware Trace -- %d JIT translations\n"
                  "Runtime binary base: 0x%X\n"
                  "Runtime routines: 0x%X (size 0x%X)\n"
                  "JIT heap: 0x%X - 0x%X\n"
                  "\n"
                  "Label format: jit_<x86_64_source_addr>\n"
                  "To find which x86 code produced a given ARM64 block,\n"
                  "check the comment or parse the label suffix as hex." % (
                      len(jit_records), rt_binary_base,
                      rt_routines_base, rt_routines_size,
                      ranges[0][0], ranges[-1][1]))
    idc.set_cmt(first_addr, header_cmt, 1)

    ida_kernwin.msg("Rosetta Trace loaded: %d JIT fragments in %d segment(s)\n"
                    % (len(jit_records), len(segments)))
    ida_kernwin.msg("  JIT address range: %s - %s\n"
                    % (hex(ranges[0][0]), hex(ranges[-1][1])))
    if rt_binary_base:
        ida_kernwin.msg("  Runtime binary base: %s\n" % hex(rt_binary_base))
    if rt_routines_base:
        ida_kernwin.msg("  Runtime routines: %s (size %s, %d stubs labeled)\n"
                        % (hex(rt_routines_base), hex(rt_routines_size), stub_count))


    # Nuke any functions auto-analysis created (it may have merged
    # everything into one giant "start" function or created bad chunks).
    for seg_start, seg_end in segments:
        s = page_align(seg_start, down=True)
        e = page_align(seg_end, down=False)
        ea = s
        while ea < e:
            f = ida_funcs.get_func(ea)
            if f:
                ida_funcs.del_func(f.start_ea)
                ea = f.end_ea
            else:
                ea += 4

    # Create functions with exact boundaries from the trace records.
    func_created = 0
    for idx, rec in enumerate(jit_records):
        event_type, mach_thr, arm64_addr, code_size, x86_addr, code_bytes = rec
        ida_funcs.add_func(arm64_addr, arm64_addr + code_size)
        func_comment = "Rosetta JIT translation of x86_64 @ 0x%X\nARM64 code: %d bytes at 0x%X\nMach thread port: 0x%X" % (
            x86_addr, code_size, arm64_addr, mach_thr)
        idc.set_func_cmt(arm64_addr, func_comment, 1)
        func_created += 1

    ida_kernwin.msg("  Functions created: %d\n" % func_created)
    # ida_auto.auto_wait()
    # Fix flow: mark BR Xn (to stub) as function-ending tail calls.
    # IDA already treats BLR as a call that returns, but BR with an indirect
    # register target confuses the analysis. We scan for BR X24/X25 where the
    # target register was loaded from literal pool (pointing to stub_branch_slot
    # or similar), and add a code xref with fl_JN (jump near) so IDA knows
    # the function terminates here.
    # _fixup_stub_branches(segments, page_align, rt_routines_base)

    # branch_resolved = 0
    # for seg_start, seg_end in segments:
    #     seg_start = page_align(seg_start, down=True)
    #     seg_end = page_align(seg_end, down=False)
    #     branch_resolved += _resolve_branch_targets(seg_start, seg_end)

    # ida_kernwin.msg("  Branch targets resolved: %d\n" % branch_resolved)

    return 1
