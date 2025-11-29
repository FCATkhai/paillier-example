export async function generatePaillierKey(bits = 1024) {
  const Worker = await import("../workers/paillier-worker?worker");
  const worker = new Worker.default();

  return new Promise((resolve) => {
    worker.onmessage = (msg) => {
      resolve(msg.data);
      worker.terminate();
    };
    worker.postMessage({ bits });
  });
}

// Internal util to call worker with an operation and get the result
async function callPaillierWorker<T>(payload: any): Promise<T> {
  const Worker = await import("../workers/paillier-worker?worker");
  const worker = new Worker.default();
  return new Promise((resolve, reject) => {
    worker.onmessage = (msg) => {
      const data = msg.data;
      worker.terminate();
      if (data && typeof data === "object" && "ok" in data) {
        if (data.ok) return resolve(data.result as T);
        return reject(new Error(data.error || "worker error"));
      }
      // Fallback: if worker responded without {ok,result}, return raw
      resolve(data as T);
    };
    worker.postMessage(payload);
  });
}

// Encryption: c = g^m * r^n mod n^2
export async function encryptPaillier(
  publicKey: { n: bigint; g: bigint },
  m: bigint | number | string
) {
  return callPaillierWorker<bigint>({ op: "encrypt", publicKey, m });
}

// Decryption: m = L(c^lambda mod n^2) * mu mod n
export async function decryptPaillier(
  publicKey: { n: bigint },
  privateKey: { lambda: bigint; mu: bigint },
  c: bigint | number | string
) {
  return callPaillierWorker<bigint>({
    op: "decrypt",
    publicKey,
    privateKey,
    c,
  });
}

// Homomorphic addition: corresponds to m1 + m2
export async function homomorphicAddPaillier(
  publicKey: { n: bigint },
  c1: bigint | number | string,
  c2: bigint | number | string
) {
  return callPaillierWorker<bigint>({ op: "add", publicKey, c1, c2 });
}

// Scalar multiply: corresponds to k * m
export async function homomorphicScalarMulPaillier(
  publicKey: { n: bigint },
  c: bigint | number | string,
  k: bigint | number | string
) {
  return callPaillierWorker<bigint>({ op: "scalarMul", publicKey, c, k });
}

// Serialization helpers (hex strings without 0x prefix)
export function serializePublicKey(pk: { n: bigint; g: bigint; n2?: bigint }) {
  return {
    n: pk.n.toString(16),
    g: pk.g.toString(16),
    n2: (pk as any).n2 ? (pk as any).n2.toString(16) : undefined,
  } as { n: string; g: string; n2?: string };
}

export function deserializePublicKey(data: {
  n: string;
  g: string;
  n2?: string;
}) {
  const toBI = (s: string) =>
    s.startsWith("0x") ? BigInt(s) : BigInt("0x" + s);
  return {
    n: toBI(data.n),
    g: toBI(data.g),
    ...(data.n2 ? { n2: toBI(data.n2) } : {}),
  } as { n: bigint; g: bigint; n2?: bigint };
}

export function serializePrivateKey(sk: { lambda: bigint; mu: bigint }) {
  return {
    lambda: sk.lambda.toString(16),
    mu: sk.mu.toString(16),
  } as { lambda: string; mu: string };
}

export function deserializePrivateKey(data: { lambda: string; mu: string }) {
  const toBI = (s: string) =>
    s.startsWith("0x") ? BigInt(s) : BigInt("0x" + s);
  return {
    lambda: toBI(data.lambda),
    mu: toBI(data.mu),
  } as { lambda: bigint; mu: bigint };
}
