// Fixture chain, core half. Exists so boot.js's stage machine can be walked in
// node: same exports jb.js expects, no console, nothing that touches memory.
export async function establishPrimitive(options) {
  const opts = options || {};
  if (typeof opts.onEvent === "function") opts.onEvent("PRIMITIVE", "fixture carrier");
  return { aim: function () {} };
}
