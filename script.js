import { MlKem768 } from "https://esm.sh/mlkem"; // Corrected import based on 768 CT size
import pqcSignFalcon512 from "https://cdn.jsdelivr.net/npm/@dashlane/pqc-sign-falcon-512-browser@1.0.0/dist/pqc-sign-falcon-512.min.js";

// --- CENTRALIZED CONSTANTS ---
const CONSTANTS = {
  // These fixed lengths are used for sizing checks and padding, NOT for component slicing.
  SIZE_FIELD_LEN: 4,     // Length of the Uint32 field used to store a size (4 bytes)
  AES_IV_LEN: 12,        // AES-GCM IV length (fixed)
};
const { SIZE_FIELD_LEN, AES_IV_LEN } = CONSTANTS;

// The size of the dynamic metadata header is 2 * 4 bytes = 8 bytes.
// Structure: [ML-KEM CT Length (4)] [Falcon Sig Length (4)]

// --- GLOBAL UTILITIES (Defined once) ---
const _standardBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const _standardCharToInt = (() => {
  const map = {};
  for (let i = 0; i < _standardBase64Chars.length; i++) {
    map[_standardBase64Chars[i]] = i;
  }
  return map;
})();

// Standard Base64
const toBase64 = u8 => btoa(String.fromCharCode(...u8));
const fromBase64 = s => { try { return new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0))); } catch { return null; } };

let encoderAlphabet = '';
let globalAlertRef; 

/**
 * Loads the custom encoder alphabet from a file.
 */
async function loadEncoderAlphabet() {
  try {
    const response = await fetch('encoderalphabet.txt');
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    encoderAlphabet = await response.text();
  } catch (error) {
    console.error("error loading encoder alphabet:", error); // console.error kept for serious errors
    encoderAlphabet = ' '; 
    if (globalAlertRef) globalAlertRef("error loading encoder alphabet: " + (error?.message || error), true);
  }
}

// --- BASE64/Custom Encoding Functions (Text Mode Only) ---

function encodeBase64ToCustom(base64String) {
  if (encoderAlphabet.length !== 4096) {
    console.warn(`warning: encoderAlphabet length is ${encoderAlphabet.length}, expected 4096`); // console.warn kept for warnings
  }

  const cleanBase64String = base64String.replace(/=+$/, '');
  const mappedResult = [];

  for (let i = 0; i < cleanBase64String.length; i += 2) {
    if (i + 1 < cleanBase64String.length) {
      const value1 = _standardCharToInt[cleanBase64String[i]];
      const value2 = _standardCharToInt[cleanBase64String[i + 1]];
      if (value1 === undefined || value2 === undefined) continue;
      const combined12BitValue = (value1 << 6) | value2;
      mappedResult.push(encoderAlphabet[combined12BitValue]);
    } else {
      mappedResult.push(cleanBase64String[i]);
    }
  }
  return mappedResult.join("");
}

function decodeCustomToBase64(mappedString) {
  if (encoderAlphabet.length !== 4096) {
    console.warn(`warning: encoderAlphabet length is ${encoderAlphabet.length}, expected 4096`); // console.warn kept for warnings
  }

  const customCharToInt = {};
  for (let i = 0; i < encoderAlphabet.length; i++) {
    customCharToInt[encoderAlphabet[i]] = i;
  }

  const decoded = [];

  for (const char of mappedString) {
    const charValue = customCharToInt[char];
    if (charValue === undefined) {
      if (_standardCharToInt[char] !== undefined) decoded.push(char);
      continue;
    }
    const v1 = (charValue >> 6) & 0x3F;
    const v2 = charValue & 0x3F;
    decoded.push(_standardBase64Chars[v1], _standardBase64Chars[v2]);
  }

  while (decoded.length % 4 !== 0) decoded.push('=');
  return decoded.join('');
}

// --- Compression Utilities ---

async function compressString(str) {
  const stream = new CompressionStream('gzip');
  const writer = stream.writable.getWriter();
  writer.write(new TextEncoder().encode(str));
  writer.close();
  const chunks = [];
  const reader = stream.readable.getReader();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return toBase64(new Uint8Array(await new Blob(chunks).arrayBuffer()));
}

async function decompressString(base64Str) {
  const data = fromBase64(base64Str);
  if (!data) return null;
  const stream = new DecompressionStream('gzip');
  const writer = stream.writable.getWriter();
  writer.write(data);
  writer.close();
  const chunks = [];
  const reader = stream.readable.getReader();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return new TextDecoder().decode(await new Blob(chunks).arrayBuffer());
}


// --- MAIN APPLICATION LOGIC (Scoped inside DOMContentLoaded) ---

document.addEventListener('DOMContentLoaded', async () => {
  // 1. DOM Elements
  const genKeysBtn = document.getElementById('genKeysBtn');
  const yourPub = document.getElementById('yourPublicKey');
  const yourPriv = document.getElementById('yourPrivateKey');
  const impExp = document.getElementById('importExportKeys');
  const importBtn = document.getElementById('importKeysBtn');
  const exportBtn = document.getElementById('exportKeysBtn');
  const recPub = document.getElementById('recipientPublicKey');
  const inp = document.getElementById('inputText');
  const encBtn = document.getElementById('encryptSignBtn');
  const decBtn = document.getElementById('decryptVerifyBtn');
  const out = document.getElementById('outputText');
  const res = document.getElementById('verifyResult');
  const alertPopup = document.getElementById('alertPopup');
  const alertMessage = document.getElementById('alertMessage');
  const alertProgressBar = document.getElementById('alertProgressBar');

  const realFileInput = document.getElementById('realFileInput');
  const fakeFileBtn = document.getElementById('fakeFileBtn');
  const chosenFileName = document.getElementById('chosenFileName');
  const encryptFileBtn = document.getElementById('encryptFileBtn');
  const decryptFileBtn = document.getElementById('decryptFileBtn');
  const downloadLink = document.getElementById('downloadLink');
  const fileVerifyResult = document.getElementById('fileVerifyResult');

  // 2. Helper functions (Scoped)
  let alertTimeout;
  function showAlert(message, isError = false) {
    const lowerCaseMessage = message.toLowerCase(); // Lowercase the alert message
    if (isError) {
      console.error("alert error:", message); // keep original message for debugging
    }
    alertMessage.textContent = lowerCaseMessage;
    alertPopup.classList.remove('alert-success', 'alert-error');
    alertPopup.classList.add(isError ? 'alert-error' : 'alert-success');
    alertPopup.classList.add('show');

    alertProgressBar.style.animation = 'none';
    void alertProgressBar.offsetWidth;
    alertProgressBar.style.animation = null;

    clearTimeout(alertTimeout);
    alertTimeout = setTimeout(() => alertPopup.classList.remove('show'), 3000);
  }
  globalAlertRef = showAlert; // Assign reference for use in loadEncoderAlphabet

  function clearOutput() {
    out.value = "";
    res.textContent = "";
  }

  function clearFileOutput() {
    fileVerifyResult.textContent = "";
    downloadLink.classList.add('hidden');
    downloadLink.href = "#";
    downloadLink.download = "";
    downloadLink.textContent = "download decrypted file";
  }
  
  // 3. Load critical asynchronous resource (Alphabet)
  await loadEncoderAlphabet();


  // --- CENTRALIZED CRYPTO FUNCTIONS ---

  /**
   * Handles ML-KEM key exchange and Falcon signing setup for TEXT mode.
   */
  async function setupEncryptionText(dataToSignBytes, recipientPublicKey, yourPrivateKey) {
    const [rkpStrCustom, _] = recipientPublicKey.split("|");
    const rkp = fromBase64(decodeCustomToBase64(rkpStrCustom));
    if (!rkp) throw new Error("invalid recipient public key");

    const [__, faPrivCustom] = yourPrivateKey.split("|"); 
    const faPriv = fromBase64(decodeCustomToBase64(faPrivCustom));
    if (!faPriv) throw new Error("your private key is missing or invalid");

    // 1. Key Encapsulation (ML-KEM)
    const kem = new MlKem768(); // ✅ Corrected usage
    const [ctMLKem, shared] = await kem.encap(rkp);

    // 2. Sign
    const falcon = await pqcSignFalcon512();
    const signatureBytes = (await falcon.sign(dataToSignBytes, faPriv)).signature;

    return {
      ctMLKem,
      shared, // The raw key material for AES
      signatureBytes
    };
  }
  
  /**
   * Handles ML-KEM key exchange and Falcon signing setup for FILE mode.
   * Signs the SHA-256 hash of the content, not the content itself.
   */
  async function setupEncryptionFile(fileBytes, recipientPublicKey, yourPrivateKey) {
    // 1. Prepare keys
    const [rkpStrCustom, _] = recipientPublicKey.split("|");
    const rkp = fromBase64(decodeCustomToBase64(rkpStrCustom));
    if (!rkp) throw new Error("invalid recipient public key");

    const [__, faPrivCustom] = yourPrivateKey.split("|");
    const faPriv = fromBase64(decodeCustomToBase64(faPrivCustom));
    if (!faPriv) throw new Error("your private key is missing or invalid");

    // 2. Hash the file content for signing (necessary for large files)
    const dataToSignBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', fileBytes));
    // console.log("[encrypt] hashed file content length (sha-256):", dataToSignBytes.length); // REMOVED

    // 3. Key Encapsulation (ML-KEM)
    const kem = new MlKem768(); // ✅ Corrected usage
    const [ctMLKem, shared] = await kem.encap(rkp);
    // console.log("[encrypt] ml-kem ciphertext length:", ctMLKem.length); // REMOVED

    // 4. Sign the HASH
    const falcon = await pqcSignFalcon512();
    const signatureBytes = (await falcon.sign(dataToSignBytes, faPriv)).signature;
    // console.log("[encrypt] falcon signature length:", signatureBytes.length); // REMOVED

    return {
      ctMLKem,
      shared, // The raw key material for AES
      signatureBytes
    };
  }


  /**
   * Decrypts and verifies text data (TEXT MODE ONLY)
   */
  async function decryptVerifyText(input, yourPrivateKey, senderPublicKey) {
    const [privMLCustom, ___] = yourPrivateKey.split("|");
    const [____, pubFACustom] = senderPublicKey.split("|");

    const sK = fromBase64(decodeCustomToBase64(privMLCustom)); // ML-KEM Private Key
    const pF = fromBase64(decodeCustomToBase64(pubFACustom)); // Falcon Public Key

    if (!sK || !pF) throw new Error("invalid or missing decryption/verification keys");

    // Text mode uses custom encoding/standard base64
    const [ctKStr, ivStrCustom, ctStrCustom] = input.split("|");
    const ctK = fromBase64(decodeCustomToBase64(ctKStr));
    const aesIv = fromBase64(decodeCustomToBase64(ivStrCustom));
    const aesCiphertext = fromBase64(decodeCustomToBase64(ctStrCustom));
    if (!ctK || !aesIv || !aesCiphertext) throw new Error("invalid encoded text data");

    // a. key decapsulation (ml-kem)
    const kem = new MlKem768(); // ✅ Corrected usage
    const shared = await kem.decap(ctK, sK);
    const aesKey = await crypto.subtle.importKey("raw", shared, "aes-gcm", false, ["decrypt"]);

    // b. decrypt data (aes-gcm)
    let decryptedBytes;
    try {
      decryptedBytes = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: aesIv }, aesKey, aesCiphertext));
    } catch (e) {
      if (e.message?.includes('operation failed')) {
        throw new Error("decryption failed (ciphertext is corrupted or keys are wrong)");
      }
      throw e;
    }

    // c. verify signature (falcon)
    // decrypted bytes contain the compressed json payload
    const decompressed = await decompressString(toBase64(decryptedBytes));
    const { m, s } = JSON.parse(decompressed);
    if (!m || !s) throw new Error("missing message or signature in payload");
    const dataToVerify = new TextEncoder().encode(m);
    const signatureBase64 = s;
    
    const falcon = await pqcSignFalcon512();
    const valid = await falcon.verify(fromBase64(signatureBase64), dataToVerify, pF);

    return {
      decryptedData: m, // set output to the plain message text
      validSignature: valid,
    };
  }

  // --- EVENT HANDLERS ---
  
  genKeysBtn.addEventListener('click', async () => {
    genKeysBtn.disabled = true;
    genKeysBtn.textContent = "generating...";
    try {
      const kem = new MlKem768(); // ✅ Corrected usage
      const [mlkemPub, mlkemPriv] = await kem.generateKeyPair();
      const falcon = await pqcSignFalcon512();
      const fk = await falcon.keypair();

      const mlkemPubCustom = encodeBase64ToCustom(toBase64(mlkemPub));
      const mlkemPrivCustom = encodeBase64ToCustom(toBase64(mlkemPriv));
      const faPubCustom = encodeBase64ToCustom(toBase64(fk.publicKey));
      const faPrivCustom = encodeBase64ToCustom(toBase64(fk.privateKey));

      yourPub.value = `${mlkemPubCustom}|${faPubCustom}`;
      yourPriv.value = `${mlkemPrivCustom}|${faPrivCustom}`;

      showAlert("keys generated successfully");
    } catch (e) {
      showAlert("key generation failed: " + (e?.message || e), true);
    } finally {
      genKeysBtn.disabled = false;
      genKeysBtn.textContent = "generate new keys";
      clearOutput();
      clearFileOutput();
    }
  });

  // Export/Import buttons (Logic unchanged)
  exportBtn.addEventListener('click', async () => {
    if (!yourPub.value || !yourPriv.value) return showAlert("generate or import keys first", true);
    try {
      const [mlkemPubCustom, faPubCustom] = yourPub.value.split("|");
      const [mlkemPrivCustom, faPrivCustom] = yourPriv.value.split("|");

      const mlkemPubBase64 = decodeCustomToBase64(mlkemPubCustom);
      const faPubBase64 = decodeCustomToBase64(faPubCustom);
      const mlkemPrivBase64 = decodeCustomToBase64(mlkemPrivCustom);
      const faPrivBase64 = decodeCustomToBase64(faPrivCustom);

      const rawKeys = JSON.stringify({
        mlkemPub: mlkemPubBase64,
        faPub: faPubBase64,
        mlkemPriv: mlkemPrivBase64,
        faPriv: faPrivBase64,
      });

      impExp.value = await compressString(rawKeys);
      showAlert("keys exported and compressed");
    } catch (e) {
      showAlert("export failed: " + (e?.message || e), true);
    }
  });

  importBtn.addEventListener('click', async () => {
    const compressedData = impExp.value.trim();
    if (!compressedData) return showAlert("paste key data into the field first", true);
    try {
      const decompressed = await decompressString(compressedData);
      if (!decompressed) return showAlert("decompression failed", true);

      const keys = JSON.parse(decompressed);
      const mlkemPubCustom = encodeBase64ToCustom(keys.mlkemPub);
      const faPubCustom = encodeBase64ToCustom(keys.faPub);
      const mlkemPrivCustom = encodeBase64ToCustom(keys.mlkemPriv);
      const faPrivCustom = encodeBase64ToCustom(keys.faPriv);

      yourPub.value = `${mlkemPubCustom}|${faPubCustom}`;
      yourPriv.value = `${mlkemPrivCustom}|${faPrivCustom}`;

      showAlert("keys imported successfully");
      clearOutput();
      clearFileOutput();
    } catch (e) {
      showAlert("import failed: " + (e?.message || e), true);
    }
  });


  // Encrypt & Sign (Text)
  encBtn.addEventListener('click', async () => {
    clearOutput();
    const msg = inp.value.trim();
    const rec = recPub.value.trim();
    const priv = yourPriv.value.trim();
    if (!msg || !rec || !priv) return showAlert("message, recipient key, and your private key required", true);
    
    encBtn.disabled = true;
    encBtn.textContent = "encrypting...";

    try {
      const msgBytes = new TextEncoder().encode(msg);
      
      const textSetup = await setupEncryptionText(msgBytes, rec, priv); 

      // 1. Compress & Encrypt Payload (Message + Signature)
      const payload = JSON.stringify({ m: msg, s: toBase64(textSetup.signatureBytes) });
      const compressed = await compressString(payload);
      const compressedBytes = fromBase64(compressed);
      
      const aesKey = await crypto.subtle.importKey("raw", textSetup.shared, "aes-gcm", false, ["encrypt"]);
      const aesIv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN)); 
      const aesCiphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: aesIv }, aesKey, compressedBytes));
      
      // 2. Encode to custom format
      const encoded = [
        encodeBase64ToCustom(toBase64(textSetup.ctMLKem)),
        encodeBase64ToCustom(toBase64(aesIv)),
        encodeBase64ToCustom(toBase64(aesCiphertext))
      ].join("|");

      out.value = encoded;
      showAlert("encryption & signing complete");
    } catch (e) {
      showAlert("encryption failed: " + (e?.message || e), true);
    } finally {
      encBtn.disabled = false;
      encBtn.textContent = "encrypt & sign";
    }
  });

  // Decrypt & Verify (Text)
  decBtn.addEventListener('click', async () => {
    clearOutput();
    const val = inp.value.trim();
    const sender = recPub.value.trim(); 
    const priv = yourPriv.value.trim();
    if (!val || !sender || !priv) return showAlert("encrypted input, sender's public key, and your private key required", true);

    decBtn.disabled = true;
    decBtn.textContent = "decrypting...";

    try {
      const result = await decryptVerifyText(val, priv, sender); 
      
      out.value = result.decryptedData;
      res.textContent = result.validSignature ? "valid signature" : "the sender could not be verified! (check the recipient public key)";
      res.style.color = result.validSignature ? "#50fa7b" : "#ff5555"; 

      showAlert("decryption & verification complete");
    } catch (e) {
      showAlert("decryption or verification failed: " + (e?.message || e), true)
    } finally {
      decBtn.disabled = false;
      decBtn.textContent = "decrypt & verify";
    }
  });
  
  // File input handler
  fakeFileBtn.addEventListener('click', () => {
    realFileInput.click();
  });

  realFileInput.addEventListener('change', () => {
    if (realFileInput.files.length > 0) {
      chosenFileName.textContent = realFileInput.files[0].name;
      clearFileOutput();
    } else {
      chosenFileName.textContent = "no file chosen";
    }
  });

  // ----- ENCRYPT FILE (with Dynamic Metadata) -----
  encryptFileBtn.addEventListener('click', async () => {
    encryptFileBtn.disabled = true;
    encryptFileBtn.textContent = "encrypting...";
    clearFileOutput();
    // console.log("[encrypt] starting file encryption."); // REMOVED

    const file = realFileInput.files[0];
    const rec = recPub.value.trim();
    const priv = yourPriv.value.trim();
    if (!file || !rec || !priv) {
        encryptFileBtn.disabled = false;
        encryptFileBtn.textContent = "encrypt file";
        return showAlert("file, recipient key, and your private key required", true);
    }

    try {
        const fileBytes = new Uint8Array(await file.arrayBuffer());
        // console.log(`[encrypt] original file size: ${fileBytes.length} bytes`); // REMOVED

        // 1. kem and sign setup (signs the file's hash)
        const setupResult = await setupEncryptionFile(fileBytes, rec, priv);
        
        const ctMLKem = setupResult.ctMLKem;
        const signatureBytes = setupResult.signatureBytes;
        
        const MLKEM_CT_LEN_ACTUAL = ctMLKem.length;
        const FALCON_SIG_LEN_ACTUAL = signatureBytes.length;

        // 2. aes encryption
        const aesIv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
        const aesKey = await crypto.subtle.importKey("raw", setupResult.shared, "aes-gcm", false, ["encrypt"]);
        const aesCiphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: aesIv }, aesKey, fileBytes));
        
        // --- 3. construct metadata header (dynamic sizes) ---
        // structure: [ml-kem ct len (4)] [falcon sig len (4)]
        const METADATA_LEN = 2 * SIZE_FIELD_LEN;
        const metadata = new Uint8Array(METADATA_LEN);
        const metadataView = new DataView(metadata.buffer);
        
        // write ml-kem ct length (0-3 bytes, big endian)
        metadataView.setUint32(0, MLKEM_CT_LEN_ACTUAL, false); 
        
        // write falcon signature length (4-7 bytes, big endian)
        metadataView.setUint32(SIZE_FIELD_LEN, FALCON_SIG_LEN_ACTUAL, false);

        const HEADER_LENGTH = METADATA_LEN + MLKEM_CT_LEN_ACTUAL + AES_IV_LEN + FALCON_SIG_LEN_ACTUAL;
        const totalLength = HEADER_LENGTH + aesCiphertext.length;
        
        // console.log(`[encrypt] meta size: ${METADATA_LEN} bytes. mlkem ct actual: ${MLKEM_CT_LEN_ACTUAL} bytes. falcon sig actual: ${FALCON_SIG_LEN_ACTUAL} bytes.`); // REMOVED
        // console.log(`[encrypt] combined header length (dynamic): ${HEADER_LENGTH} bytes`); // REMOVED
        // console.log(`[encrypt] total encrypted file size: ${totalLength} bytes`); // REMOVED

        // --- 4. combine all components ---
        // final structure: [metadata (8)] [ml-kem ct] [aes iv] [falcon sig] [aes ciphertext]
        const combined = new Uint8Array(totalLength);
        let offset = 0;
        
        combined.set(metadata, offset);
        offset += METADATA_LEN;
        // console.log(`[encrypt] offset after metadata: ${offset}`); // REMOVED
        
        combined.set(ctMLKem, offset);
        offset += MLKEM_CT_LEN_ACTUAL;
        // console.log(`[encrypt] offset after ml-kem ct: ${offset}`); // REMOVED

        combined.set(aesIv, offset);
        offset += AES_IV_LEN;
        // console.log(`[encrypt] offset after aes iv: ${offset}`); // REMOVED

        combined.set(signatureBytes, offset);
        offset += FALCON_SIG_LEN_ACTUAL;
        // console.log(`[encrypt] offset after falcon signature: ${offset}`); // REMOVED

        combined.set(aesCiphertext, offset);
        offset += aesCiphertext.length;
        // console.log(`[encrypt] final offset: ${offset}`); // REMOVED
        
        // 5. create downloadable blob (show text link instead of auto-download)
        const blob = new Blob([combined]);
        const url = URL.createObjectURL(blob);
        
        downloadLink.href = url;
        downloadLink.download = file.name + ".flame";
        downloadLink.textContent = `download: ${file.name}.flame`;
        downloadLink.classList.remove('hidden');
        
        showAlert(`encryption complete. file ready to download as '${downloadLink.download}'`);
    } catch (e) {
        showAlert("file encryption failed: " + (e?.message || e), true);
    } finally {
        encryptFileBtn.disabled = false;
        encryptFileBtn.textContent = "encrypt file";
    }
  });
  
  // ----- DECRYPT FILE (with Dynamic Metadata) -----
  decryptFileBtn.addEventListener('click', async () => {
    decryptFileBtn.disabled = true;
    decryptFileBtn.textContent = "decrypting...";
    clearFileOutput();
    // console.log("[decrypt] starting file decryption."); // REMOVED

    const file = realFileInput.files[0];
    const priv = yourPriv.value.trim();
    const senderPub = recPub.value.trim();
  
    if (!file || !priv || !senderPub) {
        decryptFileBtn.disabled = false;
        decryptFileBtn.textContent = "decrypt file";
        return showAlert("file, your private key, and sender's public key required", true);
    }
  
    // key parsing (assumes these are correctly parsed)
    const [privMLCustom, ___] = priv.split("|");
    const sK = fromBase64(decodeCustomToBase64(privMLCustom)); 
    const [____, pubFACustom] = senderPub.split("|");
    const pF = fromBase64(decodeCustomToBase64(pubFACustom)); 
    
    if (!sK || !pF) {
        decryptFileBtn.disabled = false;
        decryptFileBtn.textContent = "decrypt file";
        return showAlert("invalid or missing decryption/verification keys", true);
    }
  
    try {
        const fileBytes = new Uint8Array(await file.arrayBuffer());
        // console.log(`[decrypt] input encrypted file size: ${fileBytes.length} bytes`); // REMOVED
        
        const METADATA_LEN = 2 * SIZE_FIELD_LEN; // 8 bytes for two sizes
        const MIN_HEADER_LENGTH = METADATA_LEN + AES_IV_LEN; // 8 bytes for sizes + 12 for iv = 20 bytes minimum
        
        if (fileBytes.length < MIN_HEADER_LENGTH) {
            throw new Error(`file too small. expected min ${MIN_HEADER_LENGTH} bytes, got ${fileBytes.length}.`);
        }

        // 1. read metadata (dynamic component lengths)
        let offset = 0;
        const metadata = fileBytes.slice(0, METADATA_LEN);
        const metadataView = new DataView(metadata.buffer);

        // read lengths (big endian)
        const MLKEM_CT_LEN_READ = metadataView.getUint32(0, false);
        const FALCON_SIG_LEN_READ = metadataView.getUint32(SIZE_FIELD_LEN, false);
        
        offset += METADATA_LEN; // offset is now 8
        // console.log(`[decrypt] read metadata: mlkem ct size: ${MLKEM_CT_LEN_READ} bytes. falcon sig size: ${FALCON_SIG_LEN_READ} bytes. offset: ${offset}`); // REMOVED

        const EXPECTED_HEADER_LENGTH = offset + MLKEM_CT_LEN_READ + AES_IV_LEN + FALCON_SIG_LEN_READ;
        if (fileBytes.length < EXPECTED_HEADER_LENGTH) {
            throw new Error(`file header incomplete. calculated total size ${EXPECTED_HEADER_LENGTH} bytes, got ${fileBytes.length}.`);
        }

        // 2. extract components based on read lengths
        
        // ml-kem ct
        const ctMLKem = fileBytes.slice(offset, offset + MLKEM_CT_LEN_READ);
        if (ctMLKem.length !== MLKEM_CT_LEN_READ) throw new Error("invalid ml-kem ciphertext size slice based on metadata.");
        offset += MLKEM_CT_LEN_READ;
        // console.log(`[decrypt] ml-kem ct slice: ${ctMLKem.length} bytes. offset now: ${offset}.`); // REMOVED
        
        // aes iv (fixed length)
        const aesIv = fileBytes.slice(offset, offset + AES_IV_LEN);
        if (aesIv.length !== AES_IV_LEN) throw new Error("invalid aes iv size slice.");
        offset += AES_IV_LEN;
        // console.log(`[decrypt] aes iv slice: ${aesIv.length} bytes. offset now: ${offset}.`); // REMOVED
        
        // falcon sig
        const signatureBytes = fileBytes.slice(offset, offset + FALCON_SIG_LEN_READ);
        if (signatureBytes.length !== FALCON_SIG_LEN_READ) throw new Error("invalid falcon signature size slice based on metadata.");
        offset += FALCON_SIG_LEN_READ;
        // console.log(`[decrypt] falcon sig slice: ${signatureBytes.length} bytes. offset now: ${offset}.`); // REMOVED
        
        // aes ciphertext (remaining data)
        const aesCiphertext = fileBytes.slice(offset);
        // console.log(`[decrypt] aes ciphertext slice (remaining): ${aesCiphertext.length} bytes. starting at offset ${offset}.`); // REMOVED

        // 3. key decapsulation (ml-kem)
        const kem = new MlKem768(); // ✅ Corrected usage
        const shared = await kem.decap(ctMLKem, sK);
        const aesKey = await crypto.subtle.importKey("raw", shared, "aes-gcm", false, ["decrypt"]);

        // 4. decrypt data (aes-gcm)
        let decryptedBytes;
        try {
          decryptedBytes = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: aesIv }, aesKey, aesCiphertext));
          // console.log(`[decrypt] decrypted file size: ${decryptedBytes.length} bytes`); // REMOVED
        } catch (e) {
          console.error("[decrypt] decryption error:", e); // console.error kept
          if (e.message?.includes('operation failed')) {
            throw new Error("decryption failed (wrong key or corrupted aes ciphertext/tag).");
          }
          throw e;
        }

        // 5. verify signature (falcon) against the hash
        const dataToVerify = new Uint8Array(await crypto.subtle.digest('SHA-256', decryptedBytes));
        // console.log(`[decrypt] hash of decrypted data length: ${dataToVerify.length} bytes`); // REMOVED
        
        const falcon = await pqcSignFalcon512();
        const valid = await falcon.verify(signatureBytes, dataToVerify, pF);

        // 6. update results and save
        fileVerifyResult.textContent = valid ? "signature valid" : "signature verification failed: sender could not be verified!";
        fileVerifyResult.style.color = valid ? "#50fa7b" : "#ff5555";
        if (!valid) throw new Error("signature verification failed");

        const originalFileName = file.name.endsWith('.flame') ? file.name.slice(0, -6) : "decrypted_file.dat";
        const blob = new Blob([decryptedBytes]);
        const url = URL.createObjectURL(blob);
        downloadLink.href = url;
        downloadLink.download = originalFileName;
        downloadLink.textContent = `download: ${originalFileName}`;
        downloadLink.classList.remove('hidden');

        showAlert("file decryption & verification complete");

    } catch (e) {
        showAlert("file decryption or verification failed: " + (e?.message || e), true)
    } finally {
        decryptFileBtn.disabled = false;
        decryptFileBtn.textContent = "decrypt file";
    }
  });
  
  // tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const tgt = btn.getAttribute('data-tab');
      document.querySelectorAll('.tab-content').forEach(sec => {
        sec.classList.toggle('hidden', sec.id !== tgt);
      });
    });
  });

}); // end domcontentloaded
