// === UI helpers with XSS check ==========================================
function isXSSAttempt(message) {
  const pattern = /<[^>]+>|(on\w+=)|javascript:/gi;
  return pattern.test(message);
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".icon-button, .confirm-on-submit button, .confirm-stop-sharing, [data-confirm]");
  if (!btn) return;
  const msg = btn.getAttribute("data-confirm") || "Are you sure?";
  if (isXSSAttempt(msg)) {
    e.preventDefault();
    alert("Malicious code attempt denied.");
    return;
  }
  if (!confirm(msg)) {
    e.preventDefault();
  }
});

// Flash notifications: auto-hide + close button
window.addEventListener("load", () => {
  const flashes = document.querySelectorAll(".flash-notification");
  flashes.forEach((el) => {
    const closeBtn = el.querySelector(".close-btn");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => el.remove());
    }
    // auto-hide after 5s
    setTimeout(() => { el.style.display = "none"; }, 5000);
  });
});

// 429 retry countdown
(function () {
  const el = document.getElementById("count");
  if (!el) return;
  let s = parseInt(el.dataset.seconds || "0", 10);
  const target = el.dataset.redirect;
  const tick = () => {
    el.textContent = String(s);
    if (s <= 0) {
      if (target) window.location.href = target;
      return;
    }
    s -= 1;
    setTimeout(tick, 1000);
  };
  tick();
})();

// === Session timeout modal ===============================================
document.addEventListener("DOMContentLoaded", function () {
  const holder = document.getElementById("session-timeouts");
  if (!holder) return;

  const inactivityLimit = parseInt(holder.dataset.inactive, 10);
  const absoluteLimit = parseInt(holder.dataset.absolute, 10);
  if (!Number.isFinite(inactivityLimit) || !Number.isFinite(absoluteLimit)) return;

  const warningDuration = 30; // seconds
  const logoutUrl = "/logout";

  let inactivityTimer = null;
  let absoluteTimer = null;
  let warningOpen = false;

  function showWarning(message, onStay) {
    if (warningOpen) return;
    warningOpen = true;

    const overlay = document.createElement("div");
    overlay.style.cssText = `
      position: fixed; inset: 0; background: rgba(0,0,0,.5);
      display: flex; align-items: center; justify-content: center; z-index: 9999;
    `;
    const box = document.createElement("div");
    box.style.cssText = `
      background: #2c2b34; color: #fff; padding: 18px 20px; border-radius: 10px;
      width: 420px; box-shadow: 0 10px 25px rgba(0,0,0,.3); font-family: system-ui, Arial;
    `;
    box.innerHTML = `
      <h3 style="margin:0 0 10px; font-size:18px; color:#00aaff;">Your session will expire soon.</h3>
      <p style="margin:0 0 6px;">${message}</p>
      <p style="margin:0 0 14px;">You will be logged out in <b id="sess-count">${warningDuration}</b> seconds.</p>
      <div style="display:flex; gap:12px; justify-content:center; margin-top:15px;">
        <button id="stay-btn" style="padding:8px 16px;border:0;border-radius:6px;background:#555;color:#fff;cursor:pointer;">Stay Logged In</button>
        <button id="logout-btn" style="padding:8px 16px;border:0;border-radius:6px;background:#00d5ff;color:#000;font-weight:bold;cursor:pointer;">Log Out Now</button>
      </div>
    `;
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    const countEl = box.querySelector("#sess-count");
    const stayBtn = box.querySelector("#stay-btn");
    const logoutBtn = box.querySelector("#logout-btn");

    let secondsLeft = warningDuration;
    const interval = setInterval(() => {
      secondsLeft -= 1;
      if (secondsLeft <= 0) {
        clearInterval(interval);
        window.location.href = logoutUrl;
      } else {
        countEl.textContent = secondsLeft;
      }
    }, 1000);

    function cleanup() {
      clearInterval(interval);
      overlay.remove();
      warningOpen = false;
    }

    stayBtn.addEventListener("click", () => {
      cleanup();
      if (typeof onStay === "function") onStay();
    });

    logoutBtn.addEventListener("click", () => {
      cleanup();
      window.location.href = logoutUrl;
    });
  }

  function scheduleInactivityWarning() {
    clearTimeout(inactivityTimer);
    const delay = Math.max(0, (inactivityLimit - warningDuration));
    inactivityTimer = setTimeout(() => {
      showWarning("You have been inactive.", resetInactivityTimer);
    }, delay * 1000);
  }

  function scheduleAbsoluteWarning() {
    clearTimeout(absoluteTimer);
    const delay = Math.max(0, (absoluteLimit - warningDuration));
    absoluteTimer = setTimeout(() => {
      showWarning("Your session has reached the maximum duration.");
    }, delay * 1000);
  }

  function resetInactivityTimer() {
    scheduleInactivityWarning();
  }

  scheduleInactivityWarning();
  scheduleAbsoluteWarning();

  ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach(evt => {
    document.addEventListener(evt, resetInactivityTimer, { passive: true });
  });
});

// === WebCrypto helpers ===================================================
async function deriveArgon2Key(password, salt, { time = 3, mem = 1 << 16, parallelism = 1 } = {}) {
  const hash = await argon2.hash({
    pass: password,
    salt: salt,
    time: time,
    mem: mem,
    parallelism: parallelism,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    raw: true
  });

  return crypto.subtle.importKey(
    "raw",
    hash.hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

function randomBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

async function encryptArrayBuffer(ab, password, opts = { time: 3, mem: 1 << 16, parallelism: 1 }) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveArgon2Key(password, salt, opts);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ab);
  return { ciphertext: new Uint8Array(ct), salt, iv, opts };
}

async function decryptArrayBuffer(cipherBytes, password, saltBytes, ivBytes, opts) {
  const key = await deriveArgon2Key(password, saltBytes, opts);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, cipherBytes);
}

function b64encode(bytes) {
  let bin = "";
  bytes.forEach((x) => (bin += String.fromCharCode(x)));
  return btoa(bin);
}

function downloadBlob(buf, filename) {
  const blob = new Blob([buf]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// === Upload (client-side encryption) =====================================
(async function () {
  const form = document.getElementById("client-encrypted-upload");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const fileInput = form.querySelector('input[type="file"]');
    const dirSelect = form.querySelector('select[name="directory"]');
    const pass1 = document.getElementById("enc-pass");
    const pass2 = document.getElementById("enc-pass2");
    const csrf = form.querySelector('input[name="csrf_token"]');

    if (!fileInput?.files?.length) { alert("Please choose a file."); return; }
    if (!dirSelect?.value) { alert("Please choose a target directory."); return; }
    const password = pass1?.value || "";
    const confirmPassword = pass2?.value || "";

    // Non-empty & match
    if (!password || password !== confirmPassword) {
        alert("Passwords are empty or do not match.");
        return;
    }

    // Strength policy: ≥8 chars, 1 uppercase, 1 digit
    const regex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!regex.test(password)) {
        alert("Password must be at least 8 characters, include 1 uppercase letter and 1 digit.");
        return;
    }

    const file = fileInput.files[0];
    const ab = await file.arrayBuffer();

    try {
      const argonOpts = { time: 3, mem: 1 << 16, parallelism: 1 };
      const { ciphertext, salt, iv } = await encryptArrayBuffer(ab, pass1.value, argonOpts);

      const fd = new FormData();
      if (csrf?.value) fd.append("csrf_token", csrf.value);
      fd.append(fileInput.name || "file", new Blob([ciphertext]), file.name);
      fd.append(dirSelect.name || "directory", dirSelect.value);
      fd.append("iv", b64encode(iv));
      fd.append("salt", b64encode(salt));
      fd.append("argon_time", argonOpts.time);
      fd.append("argon_mem", argonOpts.mem);
      fd.append("argon_parallelism", argonOpts.parallelism);

      const resp = await fetch(window.location.pathname, {
        method: "POST",
        body: fd,
        credentials: "same-origin",
      });

      if (!resp.ok) {
        console.error("Upload failed:", await resp.text());
        alert("Upload failed.");
        return;
      }

      window.location.reload();
    } catch (err) {
      console.error(err);
      alert("Encryption failed. Aborting upload.");
    }
  });
})();

// === Download & Decrypt ==================================================
(function () {
  async function handleDecryptDownload(btn) {
    const fileId = btn.dataset.fileId;
    const directoryId = btn.dataset.directoryId;
    const filenameEnc = btn.dataset.filenameEnc;
    const originalName = btn.dataset.originalFilename || "decrypted";

    if (!fileId || !directoryId || !filenameEnc) { alert("Missing file metadata."); return; }

    const password = await askPassword({ title: "Enter decryption password" });
    if (!password) return;

    try {
      const metaResp = await fetch(`/api/files/${fileId}/metadata`, { credentials: "same-origin" });
      if (!metaResp.ok) { alert("Unable to fetch file metadata."); return; }
      const meta = await metaResp.json();
      const time = meta.argon_time;
      const mem = meta.argon_mem;
      const parallelism = meta.argon_parallelism;
      const salt = Uint8Array.from(atob(meta.salt), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(meta.iv), c => c.charCodeAt(0));

      const ctResp = await fetch(`/files/${directoryId}/${encodeURIComponent(filenameEnc)}`, { credentials: "same-origin" });
      if (!ctResp.ok) { alert("Unable to download encrypted file."); return; }
      const ctBuf = new Uint8Array(await ctResp.arrayBuffer());

      let plainAB;
      try {
        plainAB = await decryptArrayBuffer(ctBuf, password, salt, iv, {
          time,
          mem,
          parallelism
        });
      } catch (e) {
        console.error(e);
        alert("Decryption failed. Wrong password or corrupted file.");
        return;
      }

      downloadBlob(plainAB, originalName);
    } catch (err) {
      console.error(err);
      alert("Download/decrypt error.");
    }
  }

  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".decrypt-download");
    if (!btn) return;
    e.preventDefault();
    handleDecryptDownload(btn);
  });
})();

// Reusable password prompt that returns a Promise<string|null>
function askPassword({title = "Enter decryption password", confirmText = "Decrypt"} = {}) {
  return new Promise((resolve) => {
    // Build <dialog>
    const dlg = document.createElement("dialog");
    dlg.className = "pw-dialog"; // styling via CSS file (see below)
    dlg.innerHTML = `
      <form method="dialog" class="pw-dialog__box" autocomplete="off">
        <h3 class="pw-dialog__title">${title}</h3>
        <label class="pw-dialog__label" for="pw-input">Password</label>
        <div class="pw-dialog__row">
          <input id="pw-input" class="pw-dialog__input" type="password" required
                 autocomplete="new-password" autocapitalize="off" spellcheck="false" />
          <button type="button" class="pw-dialog__toggle" aria-label="Show/Hide password">👁️</button>
        </div>
        <div class="pw-dialog__actions">
          <button value="cancel" class="pw-dialog__btn pw-dialog__btn--ghost">Cancel</button>
          <button value="ok" class="pw-dialog__btn pw-dialog__btn--primary">${confirmText}</button>
        </div>
      </form>
    `;

    // Wire up show/hide
    const input = dlg.querySelector("#pw-input");
    const toggle = dlg.querySelector(".pw-dialog__toggle");
    toggle.addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
      input.focus();
    });

    // Close handlers
    dlg.addEventListener("close", () => {
      const val = (dlg.returnValue === "ok" && input.value) ? input.value : null;
      dlg.remove();
      resolve(val);
    });

    document.body.appendChild(dlg);
    try { dlg.showModal(); } catch { dlg.show(); } // fallback if <dialog> not supported
    input.focus();
  });
}
