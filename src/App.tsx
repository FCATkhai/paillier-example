import { useState } from "react";
import reactLogo from "./assets/react.svg";
import viteLogo from "/vite.svg";
import "./App.css";
import {
  generatePaillierKey,
  encryptPaillier,
  decryptPaillier,
  homomorphicAddPaillier,
} from "./hooks/usePaillierKeygen";

function App() {
  const [count, setCount] = useState(0);

  const handleGen = async () => {
    console.log("Generating key...");
    const { publicKey, privateKey } = await generatePaillierKey(1024);
    console.log("Public:", publicKey);
    console.log("Private:", privateKey);

    const m1 = 123n;
    const m2 = 456n;

    console.log("Encrypting messages...");
    const c1 = await encryptPaillier(publicKey, m1);
    const c2 = await encryptPaillier(publicKey, m2);
    console.log("Ciphertext 1:", c1);
    console.log("Ciphertext 2:", c2);

    console.log("Performing homomorphic addition...");
    const cSum = await homomorphicAddPaillier(publicKey, c1, c2);
    console.log("Ciphertext Sum:", cSum);

    console.log("Decrypting sum...");
    const mSum = await decryptPaillier(publicKey, privateKey, cSum);
    console.log("Decrypted Sum:", mSum); // Should be m1 + m2 = 579n
  };

  handleGen();

  return (
    <>
      <div>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </>
  );
}

export default App;
