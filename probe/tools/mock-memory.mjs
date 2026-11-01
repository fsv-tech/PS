// tools/mock-memory.mjs -- the smallest `p` that fcall.js accepts, backed by a
// flat byte image instead of a console.
//
// It models three things the port actually depends on:
//   * a 64-bit address space whose base is above 4 GB and 0x4000-aligned, so
//     looksAligned() sees what it sees on hardware;
//   * unmapped reads throw, which is how the scan-fault path gets exercised;
//   * the ArrayBuffer graph -- leakval(obj) hands back a cell, cell+0x10 is the
//     impl, impl+0x10 is the data pointer -- so bufAddr() resolves for real.
//
// leakval seeds that graph for every fresh object. Tests that need a different
// shape (Math.expm1's JSFunction, for instance) write over it afterwards.

export class I64 {
  constructor(low, hi) {
    this.low = low >>> 0;
    this.hi = hi >>> 0;
  }
  add32(v) {
    const lo = (this.low + v) >>> 0;
    return new I64(lo, lo < this.low ? (this.hi + 1) >>> 0 : this.hi);
  }
  sub32(v) {
    const lo = (this.low - v) >>> 0;
    return new I64(lo, lo > this.low ? (this.hi - 1) >>> 0 : this.hi);
  }
  equals(o) {
    return !!o && o.low === this.low && o.hi === this.hi;
  }
  toString(radix) {
    const r = radix || 16;
    return (
      (this.hi >>> 0).toString(r) +
      (this.low >>> 0).toString(r).padStart(8, "0")
    );
  }
}

export function makeImage(size, baseLow, baseHi) {
  return {
    u8: new Uint8Array(size),
    base: new I64(
      baseLow === undefined ? 0x10000000 : baseLow,
      baseHi === undefined ? 0x00000008 : baseHi,
    ),
  };
}

function absOf(addr) {
  if (typeof addr === "number") return addr;
  if (!addr || typeof addr.low !== "number")
    throw new TypeError("mock: address must be a number or {low,hi}");
  return addr.hi * 0x100000000 + addr.low;
}

export function mem(img) {
  const absBase = absOf(img.base);
  const cells = new Map();
  let scratch = img.u8.length - 0x400;

  function indexOf(addr, len) {
    const a = absOf(addr);
    const i = a - absBase;
    if (!Number.isFinite(i) || i < 0 || i + len > img.u8.length)
      throw new RangeError("mock: unmapped 0x" + a.toString(16));
    return i;
  }

  function at(off) {
    if (img.base.low + off > 0xffffffff)
      throw new RangeError("mock: at() crosses a 32-bit boundary");
    return new I64(img.base.low + off, img.base.hi);
  }

  function u32At(i) {
    return (
      (img.u8[i] |
        (img.u8[i + 1] << 8) |
        (img.u8[i + 2] << 16) |
        (img.u8[i + 3] << 24)) >>>
      0
    );
  }

  function put32(i, v) {
    img.u8[i] = v & 0xff;
    img.u8[i + 1] = (v >>> 8) & 0xff;
    img.u8[i + 2] = (v >>> 16) & 0xff;
    img.u8[i + 3] = (v >>> 24) & 0xff;
  }

  function unpack(v) {
    if (v instanceof I64) return { lo: v.low, hi: v.hi };
    if (typeof v === "number") {
      if (!Number.isFinite(v) || Math.floor(v) !== v)
        throw new TypeError("mock: non-integer value " + v);
      return { lo: v >>> 0, hi: v < 0 ? 0xffffffff : 0 };
    }
    if (v && typeof v.low === "number")
      return { lo: v.low >>> 0, hi: (v.hi === undefined ? 0 : v.hi) >>> 0 };
    throw new TypeError("mock: value must be int64 or number");
  }

  function write8(addr, value) {
    const i = indexOf(addr, 8);
    const p = unpack(value);
    put32(i, p.lo);
    put32(i + 4, p.hi);
  }

  const p = {
    at: at,
    cells: cells,

    read1(addr) {
      return img.u8[indexOf(addr, 1)];
    },
    read2(addr) {
      const i = indexOf(addr, 2);
      return (img.u8[i] | (img.u8[i + 1] << 8)) >>> 0;
    },
    read4(addr) {
      return u32At(indexOf(addr, 4));
    },
    read8(addr) {
      const i = indexOf(addr, 8);
      return new I64(u32At(i), u32At(i + 4));
    },

    write1(addr, v) {
      img.u8[indexOf(addr, 1)] = (v === undefined ? 0 : v) & 0xff;
    },
    write4(addr, v) {
      put32(indexOf(addr, 4), v >>> 0);
    },
    write8: write8,

    // Writes raw bytes at an absolute address, for building images.
    poke(addr, bytes) {
      const i = indexOf(addr, bytes.length);
      img.u8.set(bytes, i);
    },

    // cell -> impl -> data, so fcall's bufAddr() walk lands somewhere real.
    leakval(obj) {
      if (cells.has(obj)) return cells.get(obj);
      const cellOff = scratch;
      const implOff = scratch - 0x40;
      const dataOff = scratch - 0x140;
      scratch -= 0x180;
      if (scratch < 0) throw new RangeError("mock: out of scratch");

      write8(at(cellOff + 0x10), at(implOff));
      write8(at(implOff + 0x10), at(dataOff));

      const cell = at(cellOff);
      cells.set(obj, cell);
      return cell;
    },
  };

  return p;
}
