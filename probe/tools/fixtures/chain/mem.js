// Fixture chain, mem half. installWindowP publishes a p that reads nothing but
// zeroes, which is exactly what a wrong module base looks like: the port must
// refuse it at the bases stage rather than scan from address 0.
function zero() {
  return { low: 0, hi: 0, add32: zero, sub32: zero };
}

export const pairStatus = { state: "fixture", promoted: false };

export function installWindowP() {
  globalThis.p = {
    read1: function () {
      return 0;
    },
    read2: function () {
      return 0;
    },
    read4: function () {
      return 0;
    },
    read8: zero,
    write1: function () {},
    write2: function () {},
    write4: function () {},
    write8: function () {},
    leakval: zero,
  };
  return globalThis.p;
}
