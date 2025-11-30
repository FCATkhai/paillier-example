/// <reference lib="webworker" />

// ---- entropy random bigint ----
function randomBigInt(bits: number): bigint {
  const bytes = Math.ceil(bits / 8);
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  let hex = "";
  array.forEach((b) => (hex += b.toString(16).padStart(2, "0")));
  let n = BigInt("0x" + hex);

  // set bit cao nhất để đủ bit length
  const shift = BigInt(bits) - 1n;
  n |= 1n << shift;

  return n;
}

function bitLength(n: bigint): number {
  if (n === 0n) return 0;
  return n.toString(2).length;
}

function toBigInt(x: any): bigint {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") return BigInt(x);
  if (typeof x === "string") {
    try {
      return BigInt(x);
    } catch {
      return BigInt("0x" + x);
    }
  }
  throw new Error("Cannot convert to BigInt");
}

// ---- secure random in range [0, max] ----
function randomBigIntBelow(max: bigint): bigint {
  if (max <= 0n) return 0n;

  const bits = max.toString(2).length; // number of bits needed for max
  const bytes = Math.ceil(bits / 8);

  while (true) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);

    let hex = "";
    array.forEach((b) => (hex += b.toString(16).padStart(2, "0")));
    let x = BigInt("0x" + hex);

    const extraBits = BigInt(bytes * 8 - bits);
    if (extraBits > 0n) x >>= extraBits; // trim to desired bit-length

    if (x <= max) return x; // rejection sampling
  }
}

function randomBetween(min: bigint, max: bigint): bigint {
  if (max < min) throw new Error("invalid range");
  const range = max - min;
  const r = randomBigIntBelow(range);
  return min + r;
}

// ---- modular exponentiation ----
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;

  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

// ---- Miller-Rabin test ----
function isProbPrime(n: bigint, k = 16): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  let r = 0n;
  let d = n - 1n;

  while (!(d & 1n)) {
    d >>= 1n;
    r++;
  }

  loop: for (let i = 0; i < k; i++) {
    // secure random base a in [2, n-2]
    const a = randomBetween(2n, n - 2n);
    let x = modPow(a, d, n);

    if (x === 1n || x === n - 1n) continue;

    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) continue loop;
    }

    return false;
  }

  return true;
}

// ---- generate prime of bit length ----
function generatePrime(bits: number): bigint {
  while (true) {
    let p = randomBigInt(bits);
    if (p % 2n === 0n) p += 1n;
    if (isProbPrime(p)) return p;
  }
}

// ---- generate Paillier keypair ----
function lcm(a: bigint, b: bigint): bigint {
  return (a * b) / gcd(a, b);
}

function gcd(a: bigint, b: bigint): bigint {
  return b === 0n ? a : gcd(b, a % b);
}

function L(u: bigint, n: bigint): bigint {
  return (u - 1n) / n;
}

function modInv(a: bigint, m: bigint) {
  // Extended Euclid
  let m0 = m,
    x0 = 0n,
    x1 = 1n;

  while (a > 1n) {
    const q = a / m;
    [a, m] = [m, a % m];
    [x0, x1] = [x1 - q * x0, x0];
  }
  if (x1 < 0n) x1 += m0;
  return x1;
}

function generatePaillier(bits: number) {
  const half = bits / 2;
  // Aim for exact bit length of n; retry until n matches desired bits
  let p: bigint, q: bigint, n: bigint, n2: bigint;
  while (true) {
    p = generatePrime(Math.floor(half));
    q = generatePrime(Math.ceil(half));
    if (p === q) continue;
    n = p * q;
    if (n.toString(2).length === bits) {
      n2 = n * n;
      break;
    }
  }

  const lambda = lcm(p - 1n, q - 1n);
  const g = n + 1n;

  const gl = modPow(g, lambda, n2);
  const mu = modInv(L(gl, n), n);

  return {
    publicKey: { n, g, n2 },
    privateKey: { lambda, mu, p, q },
  };
}

// ---- Paillier operations ----
function encrypt(publicKey: { n: bigint; g: bigint }, m: bigint): bigint {
  const n = toBigInt(publicKey.n);
  const g = toBigInt(publicKey.g);
  const n2 = n * n;

  const mm = toBigInt(m);
  if (mm < 0n || mm >= n) throw new Error("message out of range");

  let r: bigint;
  do {
    r = randomBigIntBelow(n - 1n) + 1n; // in [1, n-1]
  } while (gcd(r, n) !== 1n);

  const gm = modPow(g, mm, n2);
  const rn = modPow(r, n, n2);
  return (gm * rn) % n2;
}

function homomorphicAdd(
  publicKey: { n: bigint },
  c1: bigint,
  c2: bigint
): bigint {
  const n = toBigInt(publicKey.n);
  const n2 = n * n;
  return (toBigInt(c1) * toBigInt(c2)) % n2;
}

function homomorphicScalarMul(
  publicKey: { n: bigint },
  c: bigint,
  k: bigint
): bigint {
  const n = toBigInt(publicKey.n);
  const n2 = n * n;
  return modPow(toBigInt(c), toBigInt(k), n2);
}

function decrypt(
  publicKey: { n: bigint },
  privateKey: { lambda: bigint; mu: bigint },
  c: bigint
): bigint {
  const n = toBigInt(publicKey.n);
  const n2 = n * n;
  const lambda = toBigInt(privateKey.lambda);
  const mu = toBigInt(privateKey.mu);

  const u = modPow(toBigInt(c), lambda, n2);
  const lOfU = L(u, n);
  let m = (lOfU * mu) % n;
  if (m < 0n) m += n;
  return m;
}

// --- Worker message handler ----
self.onmessage = (e) => {
  const data = e.data || {};
  const op = data.op;

  try {
    if (!op) {
      // backward compatibility: if no op provided, assume key generation
      const bits = data.bits || 1024;
      const result = generatePaillier(bits);
      postMessage(result);
      return;
    }

    switch (op) {
      case "generate": {
        const bits = data.bits || 1024;
        const result = generatePaillier(bits);
        postMessage({ ok: true, result });
        break;
      }
      case "encrypt": {
        const { publicKey, m } = data;
        const c = encrypt(publicKey, toBigInt(m));
        postMessage({ ok: true, result: c });
        break;
      }
      case "decrypt": {
        const { publicKey, privateKey, c } = data;
        const m = decrypt(publicKey, privateKey, toBigInt(c));
        postMessage({ ok: true, result: m });
        break;
      }
      case "add": {
        const { publicKey, c1, c2 } = data;
        const r = homomorphicAdd(publicKey, toBigInt(c1), toBigInt(c2));
        postMessage({ ok: true, result: r });
        break;
      }
      case "scalarMul": {
        const { publicKey, c, k } = data;
        const r = homomorphicScalarMul(publicKey, toBigInt(c), toBigInt(k));
        postMessage({ ok: true, result: r });
        break;
      }
      default:
        postMessage({ ok: false, error: "unknown op" });
    }
  } catch (err: any) {
    postMessage({ ok: false, error: err?.message || String(err) });
  }
};
