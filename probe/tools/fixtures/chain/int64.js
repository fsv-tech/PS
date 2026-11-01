// Fixture chain, int64 half: just enough shape for boot.js to pass it through.
export function int64(low, hi) {
  this.low = low >>> 0;
  this.hi = hi >>> 0;
}

int64.prototype.add32 = function (v) {
  const lo = (this.low + v) >>> 0;
  return new int64(lo, lo < this.low ? (this.hi + 1) >>> 0 : this.hi);
};

int64.prototype.sub32 = function (v) {
  const lo = (this.low - v) >>> 0;
  return new int64(lo, lo > this.low ? (this.hi - 1) >>> 0 : this.hi);
};

export default int64;
