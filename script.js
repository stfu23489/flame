import { MlKem768 } from "https://esm.sh/mlkem";
import pqcSignFalcon512 from "https://cdn.jsdelivr.net/npm/@dashlane/pqc-sign-falcon-512-browser@1.0.0/dist/pqc-sign-falcon-512.min.js";

// Helpers
const toBase64 = u8 => btoa(String.fromCharCode(...u8));
const fromBase64 = s => { try { return new Uint8Array(atob(s).split('').map(c=>c.charCodeAt(0))); } catch { return null; } };

// Elements
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

// State
let kem, falcon, kyPub, kyPriv, faPub, faPriv;

// Show custom alert
function showAlert(message, isError = false) {
  alertMessage.textContent = message;
  alertPopup.classList.remove('alert-success', 'alert-error');
  alertPopup.classList.add(isError ? 'alert-error' : 'alert-success');
  alertPopup.classList.add('show');

  // Reset and restart the animation
  alertProgressBar.style.animation = 'none';
  void alertProgressBar.offsetWidth; // Trigger reflow
  alertProgressBar.style.animation = null;

  setTimeout(() => {
    alertPopup.classList.remove('show');
  }, 3000);
}

// Generate Keys
genKeysBtn.addEventListener('click', async () => {
  genKeysBtn.disabled = true;
  genKeysBtn.textContent = "Generating...";
  try {
    kem = new MlKem768();
    [kyPub, kyPriv] = await kem.generateKeyPair();
    falcon = await pqcSignFalcon512();
    const fk = await falcon.keypair();
    faPub = fk.publicKey; faPriv = fk.privateKey;
    yourPub.value = toBase64(kyPub) + "||" + toBase64(faPub);
    yourPriv.value = toBase64(kyPriv) + "||" + toBase64(faPriv);
    showAlert("Keypairs generated successfully!");
  } catch (e) {
    showAlert("Failed to generate keys.", true);
    console.error(e);
  } finally {
    genKeysBtn.disabled = false;
    genKeysBtn.textContent = "Generate Your Keypairs (Kyber + Falcon)";
    clearOutput();
  }
});

// Export Raw Keys
exportBtn.addEventListener('click', () => {
  if (!kyPub || !faPub || !kyPriv || !faPriv) return showAlert("Generate or import keys first.", true);
  impExp.value = [toBase64(kyPub), toBase64(faPub), toBase64(kyPriv), toBase64(faPriv)].join("||");
  showAlert("Keys exported to the text box.");
});

// Import Raw Keys
importBtn.addEventListener('click', () => {
  const parts = impExp.value.trim().split("||");
  if (parts.length !== 4) return showAlert("Import format: KyberPub||FalconPub||KyberPriv||FalconPriv", true);
  const [kp, fp, ks, fs] = parts.map(fromBase64);
  if (!kp || !fp || !ks || !fs) return showAlert("Invalid base64 in keys.", true);
  kyPub = kp; faPub = fp; kyPriv = ks; faPriv = fs;
  yourPub.value = parts[0] + "||" + parts[1];
  yourPriv.value = parts[2] + "||" + parts[3];
  showAlert("Keys imported successfully.");
  clearOutput();
});

// Encrypt & Sign Logic
encBtn.addEventListener('click', async () => {
  clearOutput();
  const msg = inp.value.trim();
  const rec = recPub.value.trim();
  if (!msg) return showAlert("Enter a message to encrypt.", true);
  if (!rec) return showAlert("Recipient public key needed.", true);
  
  const pr = rec.split("||");
  if (pr.length !== 2) return showAlert("Recipient key format: KyberPub||FalconPub", true);
  
  const rkp = fromBase64(pr[0]), rfp = fromBase64(pr[1]);
  if (!rkp || !rfp) return showAlert("Invalid base64 in recipient pub keys.", true);
  
  try {
    if (!kem) kem = new MlKem768();
    const [ctKEM, shared] = await kem.encap(rkp);
    const aesKey = await crypto.subtle.importKey("raw", shared, "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(msg));
    const ct = new Uint8Array(enc);
    if (!falcon) falcon = await pqcSignFalcon512();
    const { signature } = await falcon.sign(new TextEncoder().encode(msg), faPriv);
    out.value = [toBase64(ctKEM), toBase64(iv), toBase64(ct), toBase64(signature)].join("|");
    showAlert("Encryption & signing complete!");
  } catch (e) {
    showAlert("Encryption failed. Make sure your private keys are loaded.", true);
    console.error(e);
  }
});

// Decrypt & Verify Logic
decBtn.addEventListener('click', async () => {
  clearOutput();
  const val = inp.value.trim();
  if (!val) return showAlert("Enter encrypted input.", true);
  
  const priv = yourPriv.value.trim(), pub = yourPub.value.trim();
  if (!priv || !pub) return showAlert("Your keys needed.", true);
  
  const pp = priv.split("||"), pu = pub.split("||");
  if (pp.length !==2 || pu.length!==2) return showAlert("Your keys must be Kyber||Falcon", true);
  
  const sK = fromBase64(pp[0]), sF = fromBase64(pp[1]), pK = fromBase64(pu[0]), pF = fromBase64(pu[1]);
  if (!sK||!sF||!pK||!pF) return showAlert("Invalid base64 in your keys.", true);
  
  const parts = val.split("|");
  if (parts.length !== 4) return showAlert("Encrypted format: ctKEM|iv|ciphertext|signature", true);
  
  const [ctK, iv, ct, sig] = parts.map(fromBase64);
  if (!ctK||!iv||!ct||!sig) return showAlert("Invalid base64 in encrypted data.", true);
  
  try {
    if (!kem) kem = new MlKem768();
    const shared = await kem.decap(ctK, sK);
    const aesKey = await crypto.subtle.importKey("raw", shared, "AES-GCM", false, ["decrypt"]);
    
    let plainBytes;
    try { plainBytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct); }
    catch { return res.textContent = "❌ Decryption failed."; }
    
    if (!falcon) falcon = await pqcSignFalcon512();
    const valid = await falcon.verify(sig, new Uint8Array(plainBytes), pF);
    
    out.value = new TextDecoder().decode(plainBytes);
    res.textContent = valid ? "✅ Signature is valid." : "❌ Signature is invalid.";
    
    showAlert("Decryption & verification complete!");
  } catch (e) {
    showAlert("Decryption failed. Check your input and keys.", true);
    console.error(e);
  }
});

// Clear output helper
function clearOutput() { out.value = ""; res.textContent = ""; }

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const tgt = btn.getAttribute('data-tab');
    document.querySelectorAll('.tab-content').forEach(sec => {
      sec.id === tgt ? sec.classList.remove('hidden') : sec.classList.add('hidden');
    });
  });
});
