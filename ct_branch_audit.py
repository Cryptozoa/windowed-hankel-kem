"""
Static constant-time branch audit for compiled ARM64 functions (otool disassembly).

Flow-sensitive forward dataflow over the function's control-flow graph. At every program point
each general-purpose register, each stack slot ([sp|x29, #off]) and the condition flags carry a
bit: *public* (derived only from immediates, loop counters, public pointer arguments, the stack
pointer, or other public values) or *non-public* (anything loaded from non-stack memory --
matrices, vectors, secrets -- or computed from such values, or returned by a call).
The meet over control-flow joins is AND (public only if public on every incoming path).

Reported findings:
  - a conditional branch (b.cond / cbz / cbnz / tbz / tbnz) whose condition is non-public
  - division instructions (data-dependent latency)
  - calls to functions outside an allowlist of audited branch-free or public-input helpers

Limitations: memory loads from non-stack addresses are always treated as non-public (sound for
branch auditing, conservative for public tables); memory *addressing* by secret indices is not
checked here and is covered by source review (all indices in the audited kernels are loop indices).
"""
import re
import subprocess

INSN = re.compile(r"^([0-9a-f]+)\s+(\S+)\s*(.*)$")
GPR = re.compile(r"^[wx](\d+)$")

FLAG_SETTERS_NODEST = ("cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fccmp")
FLAG_SETTERS_DEST = ("subs", "adds", "ands", "bics", "negs", "sbcs", "adcs")
FLAG_READERS = ("csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg",
                "ccmp", "ccmn", "adc", "sbc", "adcs", "sbcs")
COND_BRANCH_REG = ("cbz", "cbnz", "tbz", "tbnz")


def norm(r):
    r = r.strip().strip("[]!").strip()
    m = GPR.match(r)
    if m:
        return "x" + m.group(1)
    if r in ("sp", "wsp"):
        return "sp"
    if r in ("wzr", "xzr"):
        return "xzr"
    return r


def split_ops(ops):
    out, depth, cur = [], 0, ""
    for ch in ops.split(";")[0]:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def mem_slot(operand):
    m = re.match(r"\[(sp|x29)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]!?", operand.strip())
    if not m:
        return None
    off = m.group(2) or "0"
    return (m.group(1), int(off, 16) if "0x" in off else int(off))


def disassemble(lib, symbol):
    out = subprocess.check_output(["otool", "-tvV", lib]).decode()
    body, on = [], False
    for line in out.splitlines():
        if line.startswith(symbol + ":"):
            on = True
            continue
        if on and re.match(r"^_\w+:", line):
            break
        if on:
            m = INSN.match(line.strip())
            if m:
                body.append((int(m.group(1), 16), m.group(2), split_ops(m.group(3)), line.strip()))
    if not body:
        raise LookupError(f"symbol {symbol} not found in {lib}")
    return body


def _branch_target(ops):
    for o in reversed(ops):
        o = o.strip()
        if re.match(r"^0x[0-9a-f]+$", o):
            return int(o, 16)
    return None


def _successors(body, idx):
    addr, mn, ops, raw = body[idx]
    nxt = [idx + 1] if idx + 1 < len(body) else []
    addr_to_idx = _successors.addr_to_idx
    if mn == "ret":
        return []
    if mn == "b" or mn == "br":
        t = _branch_target(ops)
        return [addr_to_idx[t]] if t in addr_to_idx else []
    if mn.startswith("b.") or mn in COND_BRANCH_REG:
        t = _branch_target(ops)
        return nxt + ([addr_to_idx[t]] if t in addr_to_idx else [])
    return nxt


def _gp_sources(ops):
    srcs = []
    for o in ops:
        for tok in re.split(r"[\s,\[\]!]+", o):
            r = norm(tok)
            if r.startswith("x") and r[1:].isdigit():
                srcs.append(r)
    return srcs


def _transfer(state, insn):
    addr, mn, ops, raw = insn
    st = dict(state)
    regs, slots = st["regs"], st["slots"]
    regs = dict(regs)
    slots = dict(slots)

    def pub(r):
        return r in ("sp", "xzr", "x29") or regs.get(r, False)

    if mn == "blr" and ops and norm(ops[0]) == "x16":
        # ___chkstk_darwin (stack probe, called via x16) preserves all registers except x16/x17
        regs["x16"] = regs["x17"] = False
    elif mn in ("bl", "blr"):
        for i in range(19):
            regs[f"x{i}"] = False
        regs["x30"] = True
        st["flags"] = False
    elif mn.startswith("st"):  # stores: track stack slots
        mem = next((o for o in ops if o.strip().startswith("[")), None)
        slot = mem_slot(mem) if mem else None
        srcs = [norm(o) for o in ops if not o.strip().startswith("[") and not o.strip().startswith("#")]
        if slot and mn in ("str", "stur", "stp", "strh", "strb", "sturh", "sturb"):
            for i, r in enumerate(srcs[:2] if mn == "stp" else srcs[:1]):
                if r.startswith("x") or r == "xzr":
                    slots[(slot[0], slot[1] + i * 8)] = pub(r)
    elif mn.startswith("ld") and ops:
        mem = next((o for o in ops if o.strip().startswith("[")), None)
        slot = mem_slot(mem) if mem else None
        dests = [norm(o) for o in (ops[:2] if mn == "ldp" else ops[:1])]
        for i, d in enumerate(dests):
            if not (d.startswith("x") and d[1:].isdigit()):
                continue
            if "literal pool" in raw:
                regs[d] = True
            elif slot and mn in ("ldr", "ldur", "ldp", "ldrsw", "ldrh", "ldrb"):
                regs[d] = slots.get((slot[0], slot[1] + i * 8), False)
            else:
                regs[d] = False
    elif mn in FLAG_SETTERS_NODEST:
        src = _gp_sources(ops)
        flag_in = st["flags"] if mn in ("ccmp", "ccmn") else True
        st["flags"] = flag_in and all(pub(r) for r in src)
    elif ops and norm(ops[0]).startswith("x") and norm(ops[0])[1:].isdigit():
        d = norm(ops[0])
        src = _gp_sources(ops[1:])
        val = all(pub(r) for r in src)
        if mn in FLAG_READERS:
            val = val and st["flags"]
        if mn in ("adrp", "adr"):
            val = True
        if mn in ("movk",):
            val = val and pub(d)
        regs[d] = val
        if mn in FLAG_SETTERS_DEST:
            st["flags"] = val
    elif mn in FLAG_SETTERS_DEST:
        st["flags"] = all(pub(r) for r in _gp_sources(ops[1:]))
    # SIMD/FP instructions do not write general-purpose registers (umov/fmov to GPR treated below)
    if mn in ("umov", "smov", "fmov", "mov") and ops and norm(ops[0]).startswith("x") and \
            any(o.strip().startswith(("v", "q", "d", "s", "h", "b")) and not o.strip().startswith("sp") for o in ops[1:]):
        regs[norm(ops[0])] = False  # value moved out of a vector register: data
    st["regs"], st["slots"] = regs, slots
    return st


def _meet(a, b):
    regs = {r: a["regs"].get(r, False) and b["regs"].get(r, False) for r in set(a["regs"]) | set(b["regs"])}
    slots = {s: a["slots"].get(s, False) and b["slots"].get(s, False) for s in set(a["slots"]) | set(b["slots"])}
    return {"regs": regs, "slots": slots, "flags": a["flags"] and b["flags"]}


def audit(lib, symbol, public_args=("x0",), allowed_calls=()):
    body = disassemble(lib, symbol)
    _successors.addr_to_idx = {insn[0]: i for i, insn in enumerate(body)}

    entry_regs = {f"x{i}": (f"x{i}" in public_args) for i in range(31)}
    for i in range(19, 31):
        entry_regs[f"x{i}"] = True  # callee-saved / frame registers hold caller state
    entry = {"regs": entry_regs, "slots": {}, "flags": True}

    in_states = {0: entry}
    work = [0]
    visits = 0
    while work:
        i = work.pop()
        visits += 1
        if visits > 200000:
            raise RuntimeError("dataflow did not converge")
        out = _transfer(in_states[i], body[i])
        for s in _successors(body, i):
            if s not in in_states:
                in_states[s] = out
                work.append(s)
            else:
                merged = _meet(in_states[s], out)
                if merged != in_states[s]:
                    in_states[s] = merged
                    work.append(s)

    findings, counts = [], {"public_branch": 0, "stack_canary": 0}
    for i, (addr, mn, ops, raw) in enumerate(body):
        if mn in ("udiv", "sdiv"):
            findings.append(("division", raw))
        if mn in ("bl", "blr", "br"):
            ctx = " ".join(r for _, _, _, r in body[max(0, i - 3):i + 1])
            allowed = ("___chkstk_darwin", "___stack_chk_fail") + tuple(allowed_calls)
            if not any(a in ctx for a in allowed):
                findings.append(("call", raw))
        if i not in in_states:
            continue  # unreachable from entry
        stt = in_states[i]
        if mn in COND_BRANCH_REG:
            r = norm(ops[0])
            if stt["regs"].get(r, False):
                counts["public_branch"] += 1
            else:
                findings.append(("branch on non-public register", raw))
        elif mn.startswith("b."):
            ctx = " ".join(r for _, _, _, r in body[max(0, i - 5):i])
            if "___stack_chk_guard" in ctx:
                counts["stack_canary"] += 1
            elif stt["flags"]:
                counts["public_branch"] += 1
            else:
                findings.append(("branch on non-public flags", raw))
    return len(body), counts, findings
