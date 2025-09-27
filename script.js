// new script

import { MlKem768 } from "./libs/mlkem.mjs";
import pqcSignFalcon512 from "./libs/pqc-sign-falcon-512.js";

// --- CENTRALIZED CONSTANTS ---
const CONSTANTS = {
  // These fixed lengths are used for sizing checks and padding, NOT for component slicing.
  SIZE_FIELD_LEN: 4, // Length of the Uint32 field used to store a size (4 bytes)
  AES_IV_LEN: 12, // AES-GCM IV length (fixed)
  AES_TAG_LEN: 16, // AES-GCM Authentication Tag length (fixed) <--- ADDED
  MAX_HEADER_SIZE: 65536, // Max allowed size for dynamic components (ML-KEM CT, Falcon Sig)
  DOMAIN_TEXT: "FLAME_TEXT_V1:", // Domain separation prefix for text signing
  DOMAIN_FILE: "FLAME_FILE_V1:", // Domain separation prefix for file signing
  FILE_CHUNK_SIZE: 16 * 1024 * 1024, // 16 MB chunk size for streaming (MUST be constant) <--- ADDED
  // --- PASSWORD ENCRYPTION CONSTANTS ---
  PBKDF2_SALT_LEN: 16, // Salt length for PBKDF2
  PBKDF2_ITERATIONS: 100000, // Iterations for PBKDF2
  PBKDF2_KEY_LEN: 32, // Key length (256 bits for AES-256)
  PENC_HEADER: "FLAME_PENC_V1:", // Prefix for password-encrypted data
  // --- DEVELOPER CONSTANTS ---
  DEV_MODE: true, // Set to true to enable verbose console logging of errors
};
// UPDATED DESTRUCTURING
const { SIZE_FIELD_LEN, AES_IV_LEN, AES_TAG_LEN, MAX_HEADER_SIZE, DOMAIN_TEXT, DOMAIN_FILE, FILE_CHUNK_SIZE, PBKDF2_SALT_LEN, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN, PENC_HEADER, DEV_MODE } = CONSTANTS;

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

// Standard Base64 (Using more robust ArrayBuffer -> BinaryString conversion for btoa/atob safety)
const toBase64 = u8 => {
  const binary = u8.reduce((acc, byte) => acc + String.fromCharCode(byte), '');
  return btoa(binary);
}
const fromBase64 = s => {
  try {
    const binary = atob(s);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch { return null; }
};

let encoderAlphabet = '';
let globalAlertRef;

// === SECURE IN-MEMORY PRIVATE KEY STORAGE ===
let _privateKeyPair = {
  mlkem: null, // Custom-encoded ML-KEM private key string (for export/import only)
  mlkemKey: null, // Uint8Array of the raw ML-KEM private key (used for decap)
  falcon: null, // Custom-encoded Falcon private key string (for export/import only)
  falconKey: null, // Uint8Array of the raw Falcon private key
};

/**
 * Loads the custom encoder alphabet from a file.
 */
async function loadEncoderAlphabet() {
  try {
    const response = await fetch('encoderalphabet.txt');
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    encoderAlphabet = await response.text();
    if (encoderAlphabet.length !== 4096) throw new Error("encoder alphabet size mismatch");
    // Basic uniqueness check (full check is better but this is better than nothing)
    if (new Set(encoderAlphabet).size !== 4096) throw new Error("encoder alphabet contains duplicates or invalid chars");

  } catch (error) {
    if (DEV_MODE) console.error("error loading encoder alphabet:", error);
    encoderAlphabet = ' ';
    if (globalAlertRef) globalAlertRef("error loading encoder alphabet", true, error);
  }
}

// --- BASE64/Custom Encoding Functions (Text Mode Only) ---

function encodeBase64ToCustom(base64String) {
  if (encoderAlphabet.length !== 4096) throw new Error("invalid encoder alphabet loaded");

  const cleanBase64String = base64String.replace(/=+$/, '');
  const mappedResult = [];

  for (let i = 0; i < cleanBase64String.length; i += 2) {
    if (i + 1 < cleanBase64String.length) {
      const value1 = _standardCharToInt[cleanBase64String[i]];
      const value2 = _standardCharToInt[cleanBase64String[i + 1]];
      if (value1 === undefined || value2 === undefined) throw new Error("invalid base64 character in input");
      const combined12BitValue = (value1 << 6) | value2;
      mappedResult.push(encoderAlphabet[combined12BitValue]);
    } else {
      // Unmapped single trailing character (should only be A-Z, a-z, 0-9, + , /)
      const char = cleanBase64String[i];
      if (_standardCharToInt[char] === undefined) throw new Error("invalid base64 trailing character");
      mappedResult.push(char);
    }
  }
  return mappedResult.join("");
}

function decodeCustomToBase64(mappedString) {
  if (encoderAlphabet.length !== 4096) throw new Error("invalid encoder alphabet loaded");

  const customCharToInt = {};
  for (let i = 0; i < encoderAlphabet.length; i++) {
    customCharToInt[encoderAlphabet[i]] = i;
  }

  const decoded = [];

  for (const char of mappedString) {
    const charValue = customCharToInt[char];
    if (charValue === undefined) {
      // Should be a trailing single standard Base64 character
      if (_standardCharToInt[char] !== undefined) decoded.push(char);
      else throw new Error("invalid custom encoded character");
      continue;
    }
    const v1 = (charValue >> 6) & 0x3F;
    const v2 = charValue & 0x3F;
    decoded.push(_standardBase64Chars[v1], _standardBase64Chars[v2]);
  }

  while (decoded.length % 4 !== 0) decoded.push('=');
  return decoded.join('');
}

// --- Key Derivation Function (HKDF) ---

/**
 * Derives a key using HKDF-SHA256 from the ML-KEM shared secret.
 * @param {Uint8Array} sharedSecret - The raw shared secret from KEM.
 * @param {Uint8Array} salt - A non-secret random value (e.g., KEM CT).
 * @param {string} info - Application-specific context.
 * @returns {Promise<CryptoKey>} The derived AES-GCM key.
 */
async function deriveKey(sharedSecret, salt, info) {
  const prk = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: salt,
      info: new TextEncoder().encode(info),
      hash: "SHA-256",
    },
    prk,
    { name: "AES-GCM", length: 256 },
    false, // Derived key is NOT exportable
    ["encrypt", "decrypt"]
  );
}

// --- Password-Based Encryption/Decryption Functions ---

/**
 * Derives an AES-GCM key from a password using PBKDF2.
 * @param {string} password - The user's password.
 * @param {Uint8Array} salt - The salt for PBKDF2.
 * @returns {Promise<CryptoKey>} The derived AES-GCM key.
 */
async function deriveKeyFromPassword(password, salt) {
  const passwordBytes = new TextEncoder().encode(password);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, // Derived key is NOT exportable
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts data using a password-derived key.
 * Format: PENC_HEADER + Base64(Salt | IV | Ciphertext | Tag)
 * @param {Uint8Array} dataBytes - The data to encrypt.
 * @param {string} password - The user's password.
 * @returns {Promise<string>} The password-encrypted, Base64-encoded string.
 */
async function encryptWithPassword(dataBytes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LEN));
  const aesIv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  
  const aesKey = await deriveKeyFromPassword(password, salt);
  
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: aesIv },
    aesKey,
    dataBytes
  ));

  // Combine Salt (16), IV (12), and Ciphertext+Tag (variable)
  const combined = new Uint8Array(PBKDF2_SALT_LEN + AES_IV_LEN + encrypted.length);
  combined.set(salt, 0);
  combined.set(aesIv, PBKDF2_SALT_LEN);
  combined.set(encrypted, PBKDF2_SALT_LEN + AES_IV_LEN);

  return PENC_HEADER + toBase64(combined);
}

/**
 * Decrypts data using a password-derived key.
 * @param {string} encryptedString - The Base64-encoded encrypted string (with PENC_HEADER prefix).
 * @param {string} password - The user's password.
 * @returns {Promise<Uint8Array>} The decrypted data bytes.
 */
async function decryptWithPassword(encryptedString, password) {
  if (!encryptedString.startsWith(PENC_HEADER)) {
    throw new Error("data not recognized as password-encrypted");
  }

  const base64Data = encryptedString.substring(PENC_HEADER.length);
  const combined = fromBase64(base64Data);
  if (!combined) throw new Error("invalid base64 format");
  
  const MIN_LEN = PBKDF2_SALT_LEN + AES_IV_LEN + AES_TAG_LEN;
  if (combined.length < MIN_LEN) {
    throw new Error("encrypted data too short or corrupted");
  }

  // Extract Salt, IV, and Ciphertext
  const salt = combined.slice(0, PBKDF2_SALT_LEN);
  const aesIv = combined.slice(PBKDF2_SALT_LEN, PBKDF2_SALT_LEN + AES_IV_LEN);
  const aesCiphertext = combined.slice(PBKDF2_SALT_LEN + AES_IV_LEN);
  
  const aesKey = await deriveKeyFromPassword(password, salt);

  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: aesIv },
      aesKey,
      aesCiphertext
    ));
  } catch (e) {
    // This typically happens if the password is wrong, leading to GCM Tag mismatch.
    throw new Error("decryption failed, check your password");
  }
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
  if (!data) throw new Error("invalid base64 input for decompression");
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
  const impExp = document.getElementById('importExportKeys');
  const importBtn = document.getElementById('importKeysBtn');
  const exportBtn = document.getElementById('exportKeysBtn');
  const keyPassword = document.getElementById('keyPassword'); // ADDED
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
  const fileVerifyResult = document.getElementById('fileVerifyResult');

  // 2. Helper functions (Scoped)
  let alertTimeout;
  /**
   * Shows a user-facing alert message. Logs verbose error details to console if DEV_MODE is true.
   * @param {string} message - The user-facing message.
   * @param {boolean} isError - True if this is an error message.
   * @param {Error|string} [errorDetails] - Optional: The full error object or message for console logging.
   */
  function showAlert(message, isError = false, errorDetails = null) {
    const lowerCaseMessage = message.toLowerCase();
    
    if (isError && DEV_MODE && errorDetails) {
      const fullErrorMsg = errorDetails?.message || String(errorDetails);
      console.error("alert error:", fullErrorMsg);
    } else if (isError && DEV_MODE) {
      console.error("alert error (no details provided):", message);
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
  }

  // Check for in-memory private key presence (using the raw key reference)
  function hasPrivateKey() {
    return _privateKeyPair.mlkemKey !== null && _privateKeyPair.falconKey !== null;
  }
  
  // 3. Load critical asynchronous resource (Alphabet)
  await loadEncoderAlphabet();


  // --- CENTRALIZED CRYPTO FUNCTIONS ---

  /**
   * Helper to prepare the canonical data to sign for TEXT mode.
   * @param {string} msg - The raw message string.
   * @returns {Uint8Array} The canonical byte array to sign.
   */
  function prepareDataToSignText(msg) {
    const canonical = DOMAIN_TEXT + msg;
    return new TextEncoder().encode(canonical);
  }

  /**
   * Helper to prepare the canonical data to sign for FILE mode (hash with domain sep).
   * @param {Uint8Array} fileHashBytes - The SHA-256 hash of the file.
   * @returns {Uint8Array} The canonical byte array to sign.
   */
  function prepareDataToSignFile(fileHashBytes) {
    const domainBytes = new TextEncoder().encode(DOMAIN_FILE);
    const combined = new Uint8Array(domainBytes.length + fileHashBytes.length);
    combined.set(domainBytes, 0);
    combined.set(fileHashBytes, domainBytes.length);
    return combined;
  }


  /**
   * Handles ML-KEM key exchange and Falcon signing setup for TEXT mode.
   * @param {string} dataToSignMsg - The raw message string (for canonicalization).
   * @param {string} recipientPublicKey - Recipient's public key (custom-encoded).
   */
  async function setupEncryptionText(dataToSignMsg, recipientPublicKey) {
    const [rkpStrCustom, _] = recipientPublicKey.split("|");
    const rkp = fromBase64(decodeCustomToBase64(rkpStrCustom));
    if (!rkp) throw new Error("invalid recipient public key");

    if (!_privateKeyPair.falconKey) throw new Error("your private key is missing or invalid");
    const faPriv = _privateKeyPair.falconKey; // Use raw key from memory

    // 1. Prepare canonical data to sign
    const dataToSignBytes = prepareDataToSignText(dataToSignMsg);

    // 2. Key Encapsulation (ML-KEM)
    const kem = new MlKem768();
    const [ctMLKem, shared] = await kem.encap(rkp);

    // 3. Derive AES key using HKDF-SHA256, with CT as salt
    const aesKey = await deriveKey(shared, ctMLKem, "AES_GCM_ENCRYPT_TEXT");

    // 4. Sign canonical data
    const falcon = await pqcSignFalcon512();
    const signatureBytes = (await falcon.sign(dataToSignBytes, faPriv)).signature;

    return {
      ctMLKem,
      aesKey,
      signatureBytes
    };
  }

  /**
   * Handles ML-KEM key exchange and Falcon signing setup for FILE mode.
   * Signs the SHA-256 hash of the content, with domain separation.
   * NOTE: This function reads the entire file content into memory ONCE to compute the signature hash.
   * The file content memory is immediately flushed after hashing.
   * @param {File} file - The file object.
   * @param {string} recipientPublicKey - Recipient's public key (custom-encoded).
   */
  async function setupEncryptionFile(file, recipientPublicKey) { // CHANGED INPUT TO FILE
    // 1. Prepare keys
    const [rkpStrCustom, _] = recipientPublicKey.split("|");
    const rkp = fromBase64(decodeCustomToBase64(rkpStrCustom));
    if (!rkp) throw new Error("invalid recipient public key");

    if (!_privateKeyPair.falconKey) throw new Error("your private key is missing or invalid");
    const faPriv = _privateKeyPair.falconKey; // Use raw key from memory

    // 2. Hash the file content (Temporary full read for hashing only)
    let fileBytesForHash = new Uint8Array(await file.arrayBuffer());
    const fileHashBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', fileBytesForHash));
    // Explicitly flush the memory used for hashing the file <--- MEMORY CLEAR
    fileBytesForHash = null; 

    // 3. Prepare canonical data to sign (Hash with domain separation)
    const dataToSignBytes = prepareDataToSignFile(fileHashBytes);
    
    // 4. Key Encapsulation (ML-KEM)
    const kem = new MlKem768();
    const [ctMLKem, shared] = await kem.encap(rkp);

    // 5. Derive AES key using HKDF-SHA256, with CT as salt
    const aesKey = await deriveKey(shared, ctMLKem, "AES_GCM_ENCRYPT_FILE");

    // 6. Sign the canonical data
    const falcon = await pqcSignFalcon512();
    const signatureBytes = (await falcon.sign(dataToSignBytes, faPriv)).signature;

    return {
      ctMLKem,
      aesKey,
      signatureBytes,
      fileHashBytes // for verification logging
    };
  }

  /**
   * Encrypts a file chunk by chunk using the derived AES key.
   * The output is a Blob containing the header followed by a sequence of [Chunk IV | Chunk Ciphertext + Tag].
   */
  async function streamEncryptFile(file, setupResult) {
    const { ctMLKem, aesKey, signatureBytes } = setupResult;

    const MLKEM_CT_LEN_ACTUAL = ctMLKem.length;
    const FALCON_SIG_LEN_ACTUAL = signatureBytes.length;

    // 1. Construct static header components
    const METADATA_LEN = 2 * SIZE_FIELD_LEN;
    const metadata = new Uint8Array(METADATA_LEN);
    const metadataView = new DataView(metadata.buffer);
    metadataView.setUint32(0, MLKEM_CT_LEN_ACTUAL, false);
    metadataView.setUint32(SIZE_FIELD_LEN, FALCON_SIG_LEN_ACTUAL, false);

    // Header parts: [metadata (8 bytes)], [ctMLKem (var)], [signatureBytes (var)]
    const headerParts = [metadata, ctMLKem, signatureBytes];

    // 2. Prepare AAD bytes (used for *every* chunk, binds all chunks to the same KEM exchange)
    // AAD: [MLKEM_CT_LEN | FALCON_SIG_LEN | KEM_CT]
    const aadBytes = new Uint8Array(METADATA_LEN + MLKEM_CT_LEN_ACTUAL);
    aadBytes.set(metadata, 0);
    aadBytes.set(ctMLKem, METADATA_LEN);

    // 3. Process file chunk by chunk
    const fileSize = file.size;
    const CHUNK_SIZE = FILE_CHUNK_SIZE;
    const encryptedChunks = [];

    for (let i = 0; i < fileSize; i += CHUNK_SIZE) {
      const slice = file.slice(i, i + CHUNK_SIZE);
      // Read the slice into a temporary buffer
      let chunkBytes = new Uint8Array(await new Response(slice).arrayBuffer());

      // New IV for every chunk (as requested: treat each chunk as new file)
      const aesIv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));

      // Encrypt the chunk (AES-GCM adds the 16-byte tag to the output)
      const aesCiphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: aesIv, additionalData: aadBytes },
        aesKey,
        chunkBytes
      ));

      // Combine IV (12 bytes) and Ciphertext+Tag (ChunkSize + 16 bytes)
      // Stored as: [IV | Ciphertext | Tag]
      const chunkCombined = new Uint8Array(AES_IV_LEN + aesCiphertext.length);
      chunkCombined.set(aesIv, 0);
      chunkCombined.set(aesCiphertext, AES_IV_LEN);

      encryptedChunks.push(chunkCombined);

      // Explicitly clear memory of current chunk <--- MEMORY CLEAR
      chunkBytes = null;
    }

    // 4. Combine header and chunks into a single Blob
    return new Blob([...headerParts, ...encryptedChunks]);
  }

  /**
   * Decrypts a file chunk by chunk, verifies the signature, and returns a promise for the decrypted Blob.
   * @param {File} file - The file object containing encrypted data.
   * @param {string} yourPrivateKey - Your ML-KEM private key (custom-encoded string) (UNUSED, uses in-memory).
   * @param {string} senderPublicKey - Sender's full public key (ML-KEM + Falcon, custom-encoded string).
   * @returns {Promise<{decryptedBlob: Blob, validSignature: boolean, originalFileName: string}>}
   */
  async function streamDecryptVerifyFile(file, yourPrivateKey, senderPublicKey) {
    if (!file || file.size < (2 * SIZE_FIELD_LEN) + MlKem768.CT_SIZE + pqcSignFalcon512.SIG_SIZE) {
        throw new Error("file is too small or corrupted");
    }

    // 1. Prepare keys
    const sK = _privateKeyPair.mlkemKey; // ML-KEM Private Key (Uint8Array)
    const [____, pubFACustom] = senderPublicKey.split("|");
    const pF = fromBase64(decodeCustomToBase64(pubFACustom)); // Falcon Public Key

    if (!sK || !pF) throw new Error("invalid or missing decryption/verification keys");
    
    // 2. Read metadata and header (fixed size for KEM CT Length and Falcon Sig Length)
    const METADATA_LEN = 2 * SIZE_FIELD_LEN;
    const metadataBuffer = await new Response(file.slice(0, METADATA_LEN)).arrayBuffer();
    const metadataView = new DataView(metadataBuffer);
    const MLKEM_CT_LEN_ACTUAL = metadataView.getUint32(0, false);
    const FALCON_SIG_LEN_ACTUAL = metadataView.getUint32(SIZE_FIELD_LEN, false);

    if (MLKEM_CT_LEN_ACTUAL > MAX_HEADER_SIZE || FALCON_SIG_LEN_ACTUAL > MAX_HEADER_SIZE) {
        throw new Error("header component size too large, possible corruption");
    }

    const HEADER_SIZE = METADATA_LEN + MLKEM_CT_LEN_ACTUAL + FALCON_SIG_LEN_ACTUAL;
    if (file.size < HEADER_SIZE) {
        throw new Error("file is too small to contain header components");
    }

    // 3. Read header components (CT and Signature)
    const headerBuffer = await new Response(file.slice(METADATA_LEN, HEADER_SIZE)).arrayBuffer();
    const ctMLKem = new Uint8Array(headerBuffer, 0, MLKEM_CT_LEN_ACTUAL);
    const signatureBytes = new Uint8Array(headerBuffer, MLKEM_CT_LEN_ACTUAL, FALCON_SIG_LEN_ACTUAL);
    
    // 4. Key Decapsulation (ML-KEM)
    const kem = new MlKem768();
    const shared = await kem.decap(ctMLKem, sK);

    // 5. Derive AES key using HKDF-SHA256, with CT as salt
    const aesKey = await deriveKey(shared, ctMLKem, "AES_GCM_ENCRYPT_FILE");

    // 6. Prepare AAD bytes (same as used for encryption)
    const aadBytes = new Uint8Array(METADATA_LEN + MLKEM_CT_LEN_ACTUAL);
    aadBytes.set(new Uint8Array(metadataBuffer), 0);
    aadBytes.set(ctMLKem, METADATA_LEN);

    // 7. Stream Decryption
    const DECRYPTED_CHUNKS = [];
    const CHUNK_IV_PLUS_TAG_SIZE = AES_IV_LEN + AES_TAG_LEN; // 12 + 16 = 28 bytes minimum overhead per chunk

    let bytesDecrypted = 0;
    const fileSize = file.size;

    for (let offset = HEADER_SIZE; offset < fileSize; ) {
        // Calculate the maximum chunk size to read (Chunk Data + IV + Tag)
        const chunkEnd = Math.min(offset + FILE_CHUNK_SIZE + CHUNK_IV_PLUS_TAG_SIZE, fileSize);
        
        // Read the encrypted chunk data (IV + Ciphertext + Tag)
        const encryptedChunkSlice = file.slice(offset, chunkEnd);
        const encryptedChunkBuffer = await new Response(encryptedChunkSlice).arrayBuffer();
        const encryptedChunk = new Uint8Array(encryptedChunkBuffer);

        if (encryptedChunk.length < CHUNK_IV_PLUS_TAG_SIZE) {
            throw new Error("encrypted chunk too short or file truncated");
        }

        // Extract IV and Ciphertext
        const aesIv = encryptedChunk.slice(0, AES_IV_LEN);
        const aesCiphertext = encryptedChunk.slice(AES_IV_LEN);
        
        // Decrypt the chunk
        try {
            const decryptedChunk = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: aesIv, additionalData: aadBytes },
                aesKey,
                aesCiphertext
            ));
            DECRYPTED_CHUNKS.push(decryptedChunk);
            bytesDecrypted += decryptedChunk.length;
        } catch (e) {
            if (e.message?.includes('operation failed')) {
                throw new Error("decryption failed (file corrupted, keys are wrong, or AAD mismatch)");
            }
            throw e;
        }

        offset = chunkEnd;
    }
    
    // 8. Calculate hash of the decrypted content
    // We must concatenate all chunks to calculate the hash, which may be memory-intensive.
    const fullDecryptedBytes = new Uint8Array(bytesDecrypted);
    let currentOffset = 0;
    for (const chunk of DECRYPTED_CHUNKS) {
        fullDecryptedBytes.set(chunk, currentOffset);
        currentOffset += chunk.length;
    }

    const decryptedHashBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', fullDecryptedBytes));

    // 9. Signature Verification (using the file hash)
    // Prepare canonical data to verify (Hash with domain separation)
    const dataToVerify = prepareDataToSignFile(decryptedHashBytes);
    
    const falcon = await pqcSignFalcon512();
    const validSignature = await falcon.verify(signatureBytes, dataToVerify, pF);

    // 10. Prepare result
    const decryptedBlob = new Blob(DECRYPTED_CHUNKS);
    
    const originalFileName = file.name.endsWith('.flame') ? file.name.slice(0, -6) : "decrypted_file.dat";

    return { 
        decryptedBlob: decryptedBlob, 
        validSignature: validSignature,
        originalFileName: originalFileName
    };
  }


  /**
   * Decrypts and verifies text data (TEXT MODE ONLY)
   * NEW FORMAT: CT_KEM|IV|CT_AES|SIG_FALCON (no compression/JSON)
   * @param {string} input - The encrypted message.
   * @param {string} senderPublicKey - Sender's public key (custom-encoded).
   */
  async function decryptVerifyText(input, senderPublicKey) {
    if (!_privateKeyPair.mlkemKey) throw new Error("your decryption key is missing or invalid");
    const sK = _privateKeyPair.mlkemKey; // ML-KEM Private Key (Uint8Array)
    
    const [____, pubFACustom] = senderPublicKey.split("|");
    const pF = fromBase64(decodeCustomToBase64(pubFACustom)); // Falcon Public Key

    if (!sK || !pF) throw new Error("invalid or missing decryption/verification keys");

    // Text mode uses custom encoding/standard base64
    const [ctKStr, ivStrCustom, ctStrCustom, sigStrCustom] = input.split("|"); // NEW: Added sigStrCustom
    const ctK = fromBase64(decodeCustomToBase64(ctKStr));
    const aesIv = fromBase64(decodeCustomToBase64(ivStrCustom));
    const aesCiphertext = fromBase64(decodeCustomToBase64(ctStrCustom));
    const signatureBytes = fromBase64(decodeCustomToBase64(sigStrCustom)); // NEW: Signature bytes

    if (!ctK || !aesIv || !aesCiphertext || !signatureBytes) throw new Error("invalid encoded text data");

    // a. key decapsulation (ml-kem)
    const kem = new MlKem768();
    const shared = await kem.decap(ctK, sK); // sK must be raw Uint8Array

    // b. derive AES key using HKDF-SHA256, with CT as salt
    const aesKey = await deriveKey(shared, ctK, "AES_GCM_ENCRYPT_TEXT");

    // c. decrypt data (aes-gcm) - AAD is the KEM CT
    let decryptedBytes;
    try {
      decryptedBytes = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: aesIv, additionalData: ctK }, // AAD included
        aesKey,
        aesCiphertext
      ));
    } catch (e) {
      if (e.message?.includes('operation failed')) {
        throw new Error("decryption failed (ciphertext is corrupted, keys are wrong, or AAD mismatch)");
      }
      throw e;
    }
    
    // d. verify signature (falcon)
    // decrypted bytes contain the raw message string
    const decryptedMessage = new TextDecoder().decode(decryptedBytes);
    
    // Prepare canonical data to verify
    const dataToVerify = prepareDataToSignText(decryptedMessage);

    const falcon = await pqcSignFalcon512();
    const valid = await falcon.verify(signatureBytes, dataToVerify, pF);

    return { 
        decryptedData: decryptedMessage, 
        validSignature: valid, 
    };
  }

  // --- EVENT HANDLERS ---
  
  // GENERATE KEYS BUTTON
  genKeysBtn.addEventListener('click', async () => {
    genKeysBtn.disabled = true;
    genKeysBtn.textContent = "generating...";
    
    try {
      const kem = new MlKem768();
      const [mlkemPub, mlkemPrivRaw] = await kem.generateKeyPair();
      const falcon = await pqcSignFalcon512();
      const fk = await falcon.keypair();

      // Store public keys
      const mlkemPubCustom = encodeBase64ToCustom(toBase64(mlkemPub));
      const faPubCustom = encodeBase64ToCustom(toBase64(fk.publicKey));

      // Store private keys for export
      _privateKeyPair.mlkem = encodeBase64ToCustom(toBase64(mlkemPrivRaw));
      _privateKeyPair.falcon = encodeBase64ToCustom(toBase64(fk.privateKey));

      // Store private keys securely in memory (as Uint8Array, as required by the libraries)
      _privateKeyPair.mlkemKey = mlkemPrivRaw; // ML-KEM private key (Uint8Array)
      _privateKeyPair.falconKey = fk.privateKey;
      
      // Copy public keys to clipboard
      await navigator.clipboard.writeText(`${mlkemPubCustom}|${faPubCustom}`);
      alert('your public keys were copied to the clipboard, please save them somewhere safe');

      showAlert("keys generated successfully");
    } catch (e) {
      showAlert("key generation failed", true, e);
    } finally {
      genKeysBtn.disabled = false;
      genKeysBtn.textContent = "generate new keys";
      clearOutput();
      clearFileOutput();
    }
  });

  // Export button
  exportBtn.addEventListener('click', async () => {
    if (!_privateKeyPair.mlkem || !_privateKeyPair.falcon) {
      return showAlert("generate or import keys first", true);
    }
    impExp.value = ""; // Clear export field
  
    try {
      const mlkemPrivBase64 = decodeCustomToBase64(_privateKeyPair.mlkem);
      const faPrivBase64    = decodeCustomToBase64(_privateKeyPair.falcon);
  
      const rawKeys = JSON.stringify({
        mlkemPriv: mlkemPrivBase64,
        faPriv: faPrivBase64,
      });
  
      const password = keyPassword.value.trim();
      let outputData;
  
      if (password) {
        // Password encryption
        outputData = await encryptWithPassword(new TextEncoder().encode(rawKeys), password);
        showAlert("private keys exported (password encrypted)");
      } else {
        // Compression only (unsafe)
        outputData = await compressString(rawKeys);
        showAlert("private keys exported (compressed, NO password protection)");
      }
  
      impExp.value = outputData;
  
    } catch (e) {
      showAlert("export failed", true, e);
    }
  });

  importBtn.addEventListener('click', async () => {
    const data = impExp.value.trim();
    if (!data) return showAlert("paste key data into the field first", true);
  
    try {
      let rawKeysJson;
      const password = keyPassword.value.trim();
  
      if (data.startsWith(PENC_HEADER)) {
        // Password decryption
        if (!password) throw new Error("password required to decrypt key data");
        const decryptedBytes = await decryptWithPassword(data, password);
        rawKeysJson = new TextDecoder().decode(decryptedBytes);
      } else {
        // Decompression only (old behavior)
        rawKeysJson = await decompressString(data);
      }
  
      if (!rawKeysJson) return showAlert("data parsing failed", true);
  
      const keys = JSON.parse(rawKeysJson);
  
      // Private keys are mandatory
      if (!keys.mlkemPriv || !keys.faPriv) {
        return showAlert("private keys missing", true);
      }
  
      // Encode private keys
      _privateKeyPair.mlkem = encodeBase64ToCustom(keys.mlkemPriv);
      _privateKeyPair.falcon = encodeBase64ToCustom(keys.faPriv);
  
      // Store raw private keys securely in memory
      _privateKeyPair.mlkemKey = fromBase64(keys.mlkemPriv);
      _privateKeyPair.falconKey = fromBase64(keys.faPriv);
  
      // Public keys are optional (legacy format)
      if (keys.mlkemPub && keys.faPub) {
        const mlkemPubCustom = encodeBase64ToCustom(keys.mlkemPub);
        const faPubCustom = encodeBase64ToCustom(keys.faPub);
        await navigator.clipboard.writeText(`${mlkemPubCustom}|${faPubCustom}`);
        alert("your public keys were copied to clipboard, save them safely as we no longer export them");
      }
  
      showAlert("keys imported successfully");
      impExp.value = '';
      clearOutput();
      clearFileOutput();
  
    } catch (e) {
      showAlert("import failed", true, e);
    }
  });

  // Encrypt & Sign (Text)
  encBtn.addEventListener('click', async () => {
    clearOutput();
    const msg = inp.value.trim();
    const rec = recPub.value.trim();
    
    if (!hasPrivateKey()) return showAlert("generate or import your private key first", true);
    if (!msg || !rec) return showAlert("message and recipient key required", true);
    
    encBtn.disabled = true;
    encBtn.textContent = "encrypting...";

    try {
      // Setup performs KEM, HKDF, and Signing
      const textSetup = await setupEncryptionText(msg, rec);
      
      // 1. Encrypt Payload (Raw message string converted to bytes)
      const messageBytes = new TextEncoder().encode(msg);
      
      const aesKey = textSetup.aesKey;
      const aesIv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
      
      // Encrypt with AAD: KEM CT
      const aesCiphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: aesIv, additionalData: textSetup.ctMLKem }, // AAD included
        aesKey,
        messageBytes
      ));
      
      // 2. Encode to custom format, *including* signature as a separate component
      const encoded = [
        encodeBase64ToCustom(toBase64(textSetup.ctMLKem)),
        encodeBase64ToCustom(toBase64(aesIv)),
        encodeBase64ToCustom(toBase64(aesCiphertext)),
        encodeBase64ToCustom(toBase64(textSetup.signatureBytes)) // NEW: Signature component
      ].join("|");

      out.value = encoded;
      showAlert("encryption & signing complete");
    } catch (e) {
      showAlert("encryption failed", true, e);
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

    if (!hasPrivateKey()) return showAlert("generate or import your private key first", true);
    if (!val || !sender) return showAlert("encrypted input and sender's public key required", true);

    decBtn.disabled = true;
    decBtn.textContent = "decrypting...";

    try {
      const result = await decryptVerifyText(val, sender);
      
      out.value = result.decryptedData;
      res.textContent = result.validSignature ? "valid signature" : "the sender could not be verified! (check the recipient public key)";
      res.style.color = result.validSignature ? "#50fa7b" : "#ff5555";

      showAlert("decryption & verification complete");
    } catch (e) {
      showAlert("decryption or verification failed", true, e)
    } finally {
      decBtn.disabled = false;
      decBtn.textContent = "decrypt & verify";
    }
  });

  // ======= FILE SELECTION =======
  fakeFileBtn.addEventListener('click', () => realFileInput.click());
  
  realFileInput.addEventListener('change', () => {
    const file = realFileInput.files[0];
    chosenFileName.textContent = file ? file.name : "no file chosen";
  });
  
  // ======= ENCRYPT FILE =======
  encryptFileBtn.addEventListener('click', async () => {
    encryptFileBtn.disabled = true;
    encryptFileBtn.textContent = "encrypting...";
    fileVerifyResult.textContent = "";
  
    const file = realFileInput.files[0];
    const rec = recPub.value.trim();
  
    if (!file) return showAlert("please select a file first", true);
    if (!hasPrivateKey()) return showAlert("generate or import your private key first", true);
    if (!rec) return showAlert("recipient public key required", true);
  
    try {
      const setupResult = await setupEncryptionFile(file, rec);
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      const ctMLKem = setupResult.ctMLKem;
      const signatureBytes = setupResult.signatureBytes;
  
      const MLKEM_CT_LEN_ACTUAL = ctMLKem.length;
      const FALCON_SIG_LEN_ACTUAL = signatureBytes.length;
      const METADATA_LEN = 2 * SIZE_FIELD_LEN;
  
      const metadata = new Uint8Array(METADATA_LEN);
      const metadataView = new DataView(metadata.buffer);
      metadataView.setUint32(0, MLKEM_CT_LEN_ACTUAL, false);
      metadataView.setUint32(SIZE_FIELD_LEN, FALCON_SIG_LEN_ACTUAL, false);
  
      const HEADER_LENGTH = METADATA_LEN + MLKEM_CT_LEN_ACTUAL + AES_IV_LEN + FALCON_SIG_LEN_ACTUAL;
      const aadBytes = new Uint8Array(METADATA_LEN + MLKEM_CT_LEN_ACTUAL);
      aadBytes.set(metadata, 0);
      aadBytes.set(ctMLKem, METADATA_LEN);
  
      const aesIv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
      const aesKey = setupResult.aesKey;
  
      const aesCiphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: aesIv, additionalData: aadBytes },
        aesKey,
        fileBytes
      ));
  
      const totalLength = HEADER_LENGTH + aesCiphertext.length;
      const combined = new Uint8Array(totalLength);
      let offset = 0;
      combined.set(metadata, offset); offset += METADATA_LEN;
      combined.set(ctMLKem, offset); offset += MLKEM_CT_LEN_ACTUAL;
      combined.set(aesIv, offset); offset += AES_IV_LEN;
      combined.set(signatureBytes, offset); offset += FALCON_SIG_LEN_ACTUAL;
      combined.set(aesCiphertext, offset);
  
      const blob = new Blob([combined]);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = file.name + ".flame";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
  
      showAlert(`encryption complete. file downloaded as '${file.name}.flame'`);
    } catch (e) {
      showAlert("file encryption failed", true, e);
    } finally {
      encryptFileBtn.disabled = false;
      encryptFileBtn.textContent = "encrypt file";
    }
  });
  
  // ======= DECRYPT FILE =======
  decryptFileBtn.addEventListener('click', async () => {
    decryptFileBtn.disabled = true;
    decryptFileBtn.textContent = "decrypting...";
    fileVerifyResult.textContent = "";
  
    const file = realFileInput.files[0];
    const senderPub = recPub.value.trim();
  
    if (!file) return showAlert("please select a file first", true);
    if (!hasPrivateKey()) return showAlert("generate or import your private key first", true);
    if (!senderPub) return showAlert("sender public key required", true);
    if (!_privateKeyPair.mlkemKey) return showAlert("your ML-KEM decryption key is not loaded.", true);
  
    const sK = _privateKeyPair.mlkemKey;
    const [__, pubFACustom] = senderPub.split("|");
    const pF = fromBase64(decodeCustomToBase64(pubFACustom));
    if (!sK || !pF) return showAlert("invalid or missing decryption/verification keys", true);
  
    try {
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      const METADATA_LEN = 2 * SIZE_FIELD_LEN;
  
      let offset = 0;
      const metadata = fileBytes.slice(offset, METADATA_LEN);
      const metadataView = new DataView(metadata.buffer);
      const MLKEM_CT_LEN_READ = metadataView.getUint32(0, false);
      const FALCON_SIG_LEN_READ = metadataView.getUint32(SIZE_FIELD_LEN, false);
  
      offset += METADATA_LEN;
  
      const ctMLKem = fileBytes.slice(offset, offset + MLKEM_CT_LEN_READ); offset += MLKEM_CT_LEN_READ;
      const aesIv = fileBytes.slice(offset, offset + AES_IV_LEN); offset += AES_IV_LEN;
      const signatureBytes = fileBytes.slice(offset, offset + FALCON_SIG_LEN_READ); offset += FALCON_SIG_LEN_READ;
      const aesCiphertext = fileBytes.slice(offset); // remaining bytes (can be zero)
  
      const kem = new MlKem768();
      const shared = await kem.decap(ctMLKem, sK);
      const aesKey = await deriveKey(shared, ctMLKem, "AES_GCM_ENCRYPT_FILE");
  
      const aadBytes = new Uint8Array(METADATA_LEN + MLKEM_CT_LEN_READ);
      aadBytes.set(metadata, 0);
      aadBytes.set(ctMLKem, METADATA_LEN);
  
      const decryptedBytes = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: aesIv, additionalData: aadBytes },
        aesKey,
        aesCiphertext
      ));
  
      const fileHash = new Uint8Array(await crypto.subtle.digest('SHA-256', decryptedBytes));
      const dataToVerify = prepareDataToSignFile(fileHash);
  
      const falcon = await pqcSignFalcon512();
      const valid = await falcon.verify(signatureBytes, dataToVerify, pF);
  
      fileVerifyResult.textContent = valid ? "signature valid" : "signature verification failed";
      fileVerifyResult.style.color = valid ? "#50fa7b" : "#ff5555";
      if (!valid) throw new Error("signature verification failed");
  
      const originalFileName = file.name.endsWith('.flame') ? file.name.slice(0, -6) : "decrypted_file.dat";
  
      const blob = new Blob([decryptedBytes]);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = originalFileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
  
      showAlert("file decryption & verification complete");
    } catch (e) {
      showAlert("file decryption or verification failed", true, e);
    } finally {
      decryptFileBtn.disabled = false;
      decryptFileBtn.textContent = "decrypt file";
    }
  });
  
  // FIX: The tabs logic is updated here to toggle the 'hidden' class based on the HTML structure
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      // 1. Update button states
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      // 2. Get the target section ID
      const tgt = btn.getAttribute('data-tab');
      
      // 3. Update content visibility
      document.querySelectorAll('.tab-content').forEach(c => {
        if (c.id === tgt) {
          c.classList.add('active');
          c.classList.remove('hidden'); // Show the correct tab content
        } else {
          c.classList.remove('active');
          c.classList.add('hidden'); // Hide all other tab content
        }
      });
      
      // Also clear output/verification result when switching tabs
      clearOutput();
      clearFileOutput();
    });
  });
});