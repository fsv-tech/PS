// Exercises probes1400.js against a mock syscall gateway, to prove the
// verdict logic -- not the exploit. If a probe reports GATED for a wait that
// returns instantly and SLEEPS for one that blocks, the instrument is honest.
import { runProbes } from "../probes1400.js";

function mockCtx(mode) {
  const map = new Map();
  let next = 0x10000000;
  const ctx = {
    keepAlive: [],
    mark: () => {},
    allowDeviceProbe: false,
    anchorRva: 0,
    bufAddr(ab) {
      const a = next;
      next += 0x10000;
      map.set(a, ab);
      return a;
    },
    errno: () => 0,
    sc(num, ...args) {
      const i32 = (v) => ({ i32: v });
      if (num === 20) return i32(1234);          // getpid
      if (num === 24) return i32(1);             // getuid
      if (num === 669) {                          // aio_submit_cmd
        if (mode === "closed") return i32(-1);
        const ids = map.get(args[4]);
        if (ids) {
          const dv = new DataView(ids);
          for (let i = 0; i < args[2]; i++) dv.setInt32(i * 4, 0x40 + i, true);
        }
        return i32(0);
      }
      if (num === 663) {                          // aio_multi_wait
        if (mode === "sleeps") {
          const t = Date.now();
          while (Date.now() - t < 50) { /* block */ }
        }
        return i32(0);
      }
      if (num === 666 || num === 662) {           // cancel / delete
        const st = map.get(args[2]);
        if (st) { const dv = new DataView(st); for (let i = 0; i < st.byteLength; i += 4) dv.setInt32(i, 0, true); }
        return i32(0);
      }
      if (num === 664) {                          // poll
        const st = map.get(args[2]);
        if (st) { const dv = new DataView(st); for (let i = 0; i < st.byteLength; i += 4) dv.setInt32(i, 0, true); }
        return i32(0);
      }
      if (num === 202) return i32(-1);            // sysctl: closed
      return i32(-1);
    },
  };
  return ctx;
}

let fails = 0;
function expect(name, cond, detail) {
  if (cond) console.log("ok   " + name);
  else { fails++; console.log("FAIL " + name + (detail ? "  -> " + detail : "")); }
}
const find = (rs, n) => rs.find((r) => r.name === n);

const gated = await runProbes(mockCtx("gated"));
const w1 = find(gated, "AIO-WAIT");
expect("instant wait reads GATED", w1 && w1.verdict === "GATED", JSON.stringify(w1));
expect("delete reads ALIVE", (find(gated, "AIO-DELETE") || {}).verdict === "ALIVE");
expect("poll reads ALIVE", (find(gated, "AIO-POLL") || {}).verdict === "ALIVE");
expect("dipsw skipped unless armed", (find(gated, "DIPSW") || {}).verdict === "SKIPPED");
expect("sysctl closed reported", (find(gated, "SYSCTL-ROUTE") || {}).verdict === "CLOSED");

const sleeps = await runProbes(mockCtx("sleeps"));
const w2 = find(sleeps, "AIO-WAIT");
expect("blocking wait reads SLEEPS", w2 && w2.verdict === "SLEEPS", JSON.stringify(w2));

const closed = await runProbes(mockCtx("closed"));
const w3 = find(closed, "AIO-WAIT");
expect("failed submit reads CLOSED", w3 && w3.verdict === "CLOSED", JSON.stringify(w3));
expect("baseline still passes", (find(closed, "BASELINE") || {}).verdict === "PASS");

console.log(fails === 0 ? "\nALL CHECKS PASSED" : "\n" + fails + " CHECK(S) FAILED");
process.exit(fails === 0 ? 0 : 1);
