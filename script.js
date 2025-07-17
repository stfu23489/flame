import { MlKem768 } from "https://esm.sh/mlkem";
import pqcSignFalcon512 from "https://cdn.jsdelivr.net/npm/@dashlane/pqc-sign-falcon-512-browser@1.0.0/dist/pqc-sign-falcon-512.min.js";

let encoderAlphabet = '';

fetch('encoderalphabet.txt')
  .then(response => response.text())
  .then(data => {
    encoderAlphabet = data;
  })
  .catch(error => showAlert("error loading encoder alphabet: " + (error?.message || error), true));

const _standardBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const _standardCharToInt = (() => {
  const map = {};
  for (let i = 0; i < _standardBase64Chars.length; i++) {
    map[_standardBase64Chars[i]] = i;
  }
  return map;
})();

function encodeBase64ToCustom(base64String) {
  if (encoderAlphabet.length !== 4096) {
    console.warn(`warning: encoderAlphabet length is ${encoderAlphabet.length}, expected 4096`);
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
    console.warn(`warning: encoderAlphabet length is ${encoderAlphabet.length}, expected 4096`);
  }

  const customCharToInt = {};
  for (let i = 0; i < encoderAlphabet.length; i++) {
    customCharToInt[encoderAlphabet[i]] = i;
  }

  const decoded = [];

  for (const char of mappedString) {
    const val = customCharToInt[char];
    if (val === undefined) {
      if (_standardCharToInt[char] !== undefined) decoded.push(char);
      continue;
    }
    const v1 = (val >> 6) & 0x3F;
    const v2 = val & 0x3F;
    decoded.push(_standardBase64Chars[v1], _standardBase64Chars[v2]);
  }

  while (decoded.length % 4 !== 0) decoded.push('=');
  return decoded.join('');
}

const toBase64 = u8 => btoa(String.fromCharCode(...u8));
const fromBase64 = s => { try { return new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0))); } catch { return null; } };

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

// DOM Elements
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

var alertTimeout;
function showAlert(message, isError = false) {
  alertMessage.textContent = message.toLowerCase();
  alertPopup.classList.remove('alert-success', 'alert-error');
  alertPopup.classList.add(isError ? 'alert-error' : 'alert-success');
  alertPopup.classList.add('show');

  alertProgressBar.style.animation = 'none';
  void alertProgressBar.offsetWidth;
  alertProgressBar.style.animation = null;

  clearTimeout(alertTimeout);
  alertTimeout = setTimeout(() => alertPopup.classList.remove('show'), 3000);
}

function clearOutput() {
  out.value = "";
  res.textContent = "";
}

// Generate Keypairs
genKeysBtn.addEventListener('click', async () => {
  genKeysBtn.disabled = true;
  genKeysBtn.textContent = "generating...";
  try {
    const kem = new MlKem768();
    const [mlkemPub, mlkemPriv] = await kem.generateKeyPair();
    const falcon = await pqcSignFalcon512();
    const fk = await falcon.keypair();

    const mlkemPubCustom = encodeBase64ToCustom(toBase64(mlkemPub));
    const mlkemPrivCustom = encodeBase64ToCustom(toBase64(mlkemPriv));
    const faPubCustom = encodeBase64ToCustom(toBase64(fk.publicKey));
    const faPrivCustom = encodeBase64ToCustom(toBase64(fk.privateKey));

    yourPub.value = `${mlkemPubCustom}|${faPubCustom}`;
    yourPriv.value = `${mlkemPrivCustom}|${faPrivCustom}`;

    showAlert("keypairs generated successfully");
  } catch (e) {
    showAlert("key generation failed: " + (e?.message || e), true);
  } finally {
    genKeysBtn.disabled = false;
    genKeysBtn.textContent = "generate your keypairs";
    clearOutput();
  }
});

// Export Keys
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

// Import Keys
importBtn.addEventListener('click', async () => {
  const compressedData = impExp.value.trim();
  if (!compressedData) return showAlert("paste key data first", true);
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
  } catch (e) {
    showAlert("import failed: " + (e?.message || e), true);
  }
});

// Encrypt & Sign
encBtn.addEventListener('click', async () => {
  clearOutput();
  const msg = inp.value.trim();
  const rec = recPub.value.trim();
  if (!msg || !rec) return showAlert("message and recipient key required", true);

  try {
    const [rkpStrCustom, rfpStrCustom] = rec.split("|");
    const rkp = fromBase64(decodeCustomToBase64(rkpStrCustom));
    const rfp = fromBase64(decodeCustomToBase64(rfpStrCustom));
    if (!rkp || !rfp) return showAlert("invalid recipient keys", true);

    const kem = new MlKem768();
    const [ctMLKem, shared] = await kem.encap(rkp);

    const falcon = await pqcSignFalcon512();
    const faPriv = fromBase64(decodeCustomToBase64(yourPriv.value.split("|")[1]));
    const signature = (await falcon.sign(new TextEncoder().encode(msg), faPriv)).signature;

    const payload = JSON.stringify({ m: msg, s: toBase64(signature) });
    const compressed = await compressString(payload);
    const compressedBytes = fromBase64(compressed);

    const aesKey = await crypto.subtle.importKey("raw", shared, "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, compressedBytes));

    const encoded = [
      encodeBase64ToCustom(toBase64(ctMLKem)),
      encodeBase64ToCustom(toBase64(iv)),
      encodeBase64ToCustom(toBase64(ciphertext))
    ].join("|");

    out.value = encoded;
    showAlert("encryption & signing complete");
  } catch (e) {
    showAlert("encryption failed: " + (e?.message || e), true);
  }
});

// Decrypt & Verify
decBtn.addEventListener('click', async () => {
  clearOutput();
  const val = inp.value.trim();
  if (!val) return showAlert("enter encrypted input", true);

  try {
    const [privMLCustom, privFACustom] = yourPriv.value.trim().split("|");
    const [pubMLCustom, pubFACustom] = recPub.value.trim().split("|");

    const sK = fromBase64(decodeCustomToBase64(privMLCustom));
    const sF = fromBase64(decodeCustomToBase64(privFACustom));
    const pF = fromBase64(decodeCustomToBase64(pubFACustom));

    if (!sK || !sF || !pF) return showAlert("invalid or missing keys", true);

    const [ctK, ivStr, ctStr] = val.split("|").map(p => fromBase64(decodeCustomToBase64(p)));
    if (!ctK || !ivStr || !ctStr) return showAlert("invalid encoded data", true);

    const kem = new MlKem768();
    const shared = await kem.decap(ctK, sK);
    const aesKey = await crypto.subtle.importKey("raw", shared, "AES-GCM", false, ["decrypt"]);

    const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivStr }, aesKey, ctStr));
    const decompressed = await decompressString(toBase64(decrypted));
    const { m, s } = JSON.parse(decompressed);

    if (!m || !s) return showAlert("missing message or signature", true);

    const falcon = await pqcSignFalcon512();
    const valid = await falcon.verify(fromBase64(s), new TextEncoder().encode(m), pF);

    out.value = m;
    res.textContent = valid ? "✅ signature is valid" : "❌ signature is invalid";
    res.style.color = valid ? "#90ee90" : "#f08080";

    showAlert("decryption & verification complete");
  } catch (e) {
    showAlert("decryption or verification failed: " + (e?.message || e), true);
  }
});

// Tabs
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
