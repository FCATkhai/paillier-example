// paillier.ts
import crypto from 'crypto'

/**
 * Paillier cryptosystem basic implementation in TypeScript (Node.js).
 * - Key generation follows the algorithm in your file (choose p,q, n=pq, lambda = lcm(p-1,q-1), choose g, compute mu).
 * - Encryption: c = g^m * r^n (mod n^2) with r in Z_n^* (i.e., gcd(r,n)==1)
 * - Decryption: m = L(c^lambda mod n^2) * mu mod n, where L(u) = (u-1)/n
 *
 * This is educational code with inline comments for important parts.
 */

/* -------------------------
   Utilities for BigInt math
   ------------------------- */

/** Compute (a * b) mod m */
function modMul(a: bigint, b: bigint, m: bigint): bigint {
    return (a * b) % m
}

/** Compute (a ^ e) mod m using binary exponentiation */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    if (mod === 1n) return 0n
    let result = 1n
    let b = base % mod
    let e = exp
    while (e > 0) {
        if (e & 1n) result = (result * b) % mod
        e >>= 1n
        b = (b * b) % mod
    }
    return result
}

/** Extended GCD: returns [g, x, y] such that a*x + b*y = g = gcd(a,b) */
function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
    if (b === 0n) return [a, 1n, 0n]
    let [g, x1, y1] = egcd(b, a % b)
    let x = y1
    let y = x1 - (a / b) * y1
    return [g, x, y]
}

/** Modular inverse of a modulo m. Throws if inverse doesn't exist. */
function modInv(a: bigint, m: bigint): bigint {
    const [g, x] = (() => {
        const t = egcd(a < 0n ? ((a % m) + m) % m : a, m)
        return [t[0], t[1]]
    })()
    if (g !== 1n) throw new Error('modInv: inverse does not exist')
    // ensure positive
    return ((x % m) + m) % m
}

/** gcd */
function gcd(a: bigint, b: bigint): bigint {
    while (b !== 0n) {
        const t = a % b
        a = b
        b = t
    }
    return a < 0n ? -a : a
}

/** lcm */
function lcm(a: bigint, b: bigint): bigint {
    return (a / gcd(a, b)) * b
}

/* -------------------------
   Random BigInt / Primes
   ------------------------- */

/** produce a random BigInt of specified bitLength (msb may be 0) */
function randomBigInt(bitLength: number): bigint {
    const byteLength = Math.ceil(bitLength / 8)
    const buf = crypto.randomBytes(byteLength)
    // set top bit to ensure desired bit length
    const firstByte = buf[0] as number
    const topBits = bitLength % 8
    if (topBits === 0) {
        // set highest bit of first byte
        buf[0] = firstByte | 0x80
    } else {
        buf[0] = firstByte | (1 << (topBits - 1))
    }
    return BigInt('0x' + buf.toString('hex'))
}

/** Miller-Rabin probable prime test */
function isProbablePrime(n: bigint, k = 16): boolean {
    if (n === 2n || n === 3n) return true
    if (n < 2n || n % 2n === 0n) return false

    // write n-1 as d * 2^s
    let s = 0n
    let d = n - 1n
    while ((d & 1n) === 0n) {
        d >>= 1n
        s += 1n
    }

    // witnesses: use random bases
    for (let i = 0; i < k; i++) {
        const a = 2n + (randomBigInt(n.toString(2).length) % (n - 4n)) // random in [2, n-2]
        let x = modPow(a, d, n)
        if (x === 1n || x === n - 1n) continue
        let cont = false
        for (let r = 1n; r < s; r++) {
            x = (x * x) % n
            if (x === n - 1n) {
                cont = true
                break
            }
        }
        if (cont) continue
        return false
    }
    return true
}

/** Generate a random probable prime with given bit length */
function generatePrime(bitLength: number): bigint {
    while (true) {
        let p = randomBigInt(bitLength)
        // make odd
        p |= 1n
        if (isProbablePrime(p)) return p
    }
}

/* -------------------------
   Paillier primitives
   ------------------------- */

/** L function: L(u) = (u - 1) / n (u should be mod n^2) */
function L(u: bigint, n: bigint): bigint {
    return (u - 1n) / n
}

/** Generate Paillier keypair
 * @param keyBits desired bit length of n (e.g., 512, 1024, 2048)
 * @returns {publicKey: {n,g,n2}, privateKey: {lambda,mu}}
 */
export async function generateKeypair(keyBits = 1024) {
    // Choose prime sizes roughly half of keyBits
    const pBits = Math.floor(keyBits / 2) + 1
    const qBits = Math.floor(keyBits / 2)

    // 1) generate p and q primes
    let p: bigint, q: bigint, n: bigint
    while (true) {
        p = generatePrime(pBits)
        q = generatePrime(qBits)
        if (p === q) continue
        n = p * q
        // ensure bitlength
        if (n.toString(2).length === keyBits) break
    }

    const n2 = n * n

    // 2) lambda = lcm(p-1, q-1) (Carmichael's function)
    const lambda = lcm(p - 1n, q - 1n)

    // 3) choose g in Z_{n^2}^* such that gcd(L(g^lambda mod n^2), n) = 1
    let g: bigint
    let mu: bigint
    for (;;) {
        // pick random g in [1, n^2-1]
        g = BigInt('0x' + crypto.randomBytes(n2.toString(2).length / 8 + 1).toString('hex')) % n2
        if (g <= 1n) continue
        const gl = modPow(g, lambda, n2)
        const lVal = L(gl, n)
        if (gcd(lVal, n) === 1n) {
            // mu = (L(g^lambda mod n^2))^{-1} mod n
            mu = modInv(lVal % n, n)
            break
        }
    }

    const publicKey = { n, g, n2 }
    const privateKey = { lambda, mu }

    return { publicKey, privateKey }
}

/** Encrypt message m (0 <= m < n) with publicKey
 * Returns ciphertext c (bigint)
 */
export function encrypt(publicKey: { n: bigint; g: bigint; n2: bigint }, m: bigint) {
    const { n, g, n2 } = publicKey
    if (m < 0n || m >= n) throw new Error('message out of range')

    // choose random r in [1, n-1] with gcd(r, n) == 1
    let r: bigint
    do {
        r = BigInt('0x' + crypto.randomBytes(Math.ceil(n.toString(2).length / 8)).toString('hex')) % n
        if (r === 0n) r = 1n
    } while (gcd(r, n) !== 1n)

    // c = g^m * r^n mod n^2
    const gm = modPow(g, m, n2)
    const rn = modPow(r, n, n2)
    const c = (gm * rn) % n2
    return c
}

/** Homomorphic addition of ciphertexts: c1 * c2 mod n^2 corresponds to m1 + m2 */
export function homomorphicAdd(publicKey: { n: bigint; n2: bigint }, c1: bigint, c2: bigint) {
    return (c1 * c2) % publicKey.n2
}

/** Scalar multiply ciphertext: c^k mod n^2 corresponds to k * m */
export function homomorphicScalarMul(publicKey: { n: bigint; n2: bigint }, c: bigint, k: bigint) {
    return modPow(c, k, publicKey.n2)
}

/**
 * Giải mã Ciphertext c sử dụng PrivateKey
 * Công thức: m = L(c^lambda mod n^2) * mu mod n
 * * @param publicKey Chứa n, g, n2
 * @param privateKey Chứa lambda, mu
 * @param c Số đã mã hóa (Ciphertext)
 */
export function decrypt(
    publicKey: { n: bigint; g: bigint; n2: bigint }, 
    privateKey: { lambda: bigint; mu: bigint }, 
    c: bigint
): bigint {
    // Destructuring để lấy các tham số cần thiết
    const { n, n2 } = publicKey;
    const { lambda, mu } = privateKey;

    // 1. Tính u = c^lambda mod n^2
    const u = modPow(c, lambda, n2);

    // 2. Tính L(u) = (u - 1) / n
    // Hàm L phải được định nghĩa trong file này: const L = (u: bigint, n: bigint) => (u - 1n) / n;
    const lOfU = L(u, n);

    // 3. Tính m = (L(u) * mu) mod n
    let m = (lOfU * mu) % n;

    // 4. Xử lý trường hợp % ra số âm trong JS
    if (m < 0n) {
        m += n;
    }

    return m;
}
/* -------------------------
   Serialization helpers
   ------------------------- */

export function serializePublicKey(pk: { n: bigint; g: bigint; n2: bigint }) {
    return {
        n: pk.n.toString(16),
        g: pk.g.toString(16),
        n2: pk.n2.toString(16)
    }
}

export function deserializePublicKey(data: { n: string; g: string; n2: string }) {
    return {
        n: BigInt(data.n.startsWith('0x') ? data.n : '0x' + data.n),
        g: BigInt(data.g.startsWith('0x') ? data.g : '0x' + data.g),
        n2: BigInt(data.n2.startsWith('0x') ? data.n2 : '0x' + data.n2)
    }
}

export function serializePrivateKey(sk: { lambda: bigint; mu: bigint; p?: bigint; q?: bigint }) {
    return {
        lambda: sk.lambda.toString(16),
        mu: sk.mu.toString(16)
    }
}

export function deserializePrivateKey(data: { lambda: string; mu: string; p?: string; q?: string }) {
    return {
        lambda: BigInt(data.lambda),
        mu: BigInt(data.mu)
    }
}

/* -------------------------
   Example usage
   ------------------------- */
export function exampleUsage() {
    ;(async () => {
        console.log('Generating keypair (this can take some time)...')
        const { publicKey, privateKey } = await generateKeypair(512) // 512 for demo; use >= 2048 for real
        console.log('public.n (bits):', publicKey.n.toString(2).length)

        // sample messages
        const m1 = 1n
        const m2 = 0n
        console.log('Encrypting m1, m2...')
        const c1 = encrypt(publicKey, m1)
        const c2 = encrypt(publicKey, m2)

        // homomorphic add
        const cSum = homomorphicAdd(publicKey, c1, c2)

        // decrypt
        const dec1 = decrypt(publicKey, privateKey, c1)
        const decSum = decrypt(publicKey, privateKey, cSum)

        console.log('m1:', m1.toString(), 'dec1:', dec1.toString())
        console.log('sum decrypted:', decSum.toString())

        // show serialization example
        const pubSer = serializePublicKey(publicKey)
        const privSer = serializePrivateKey(privateKey)
        console.log('Serialized public key:', pubSer)
    })()
}
