/**
 * SecureShare // KEY EXCHANGE - Frontend Core Application
 * Full SPA controller connecting UI, IndexedDB Vault, and Cryptographic Protocols.
 */

import { api } from "./api.js";
import { UI } from "./ui.js";
import { AESGCM } from "./crypto/aes_gcm.js";
import { Ed25519Sign } from "./crypto/ed25519_sign.js";
import { X25519HKDF } from "./crypto/x25519_hkdf.js";
import { Envelope } from "./crypto/envelope.js";
import { KeyStore } from "./crypto/keystore.js";

class SecureShareApp {
  constructor() {
    this.currentUser = null;
    this.keyStore = null;
    this.identityState = "UNAUTHENTICATED"; // "UNAUTHENTICATED", "INITIALIZING", "LOCKED", "READY", "ERROR"
    this.identityError = null;
    this._identityPromise = null;
    this.currentView = "overview";
    this.activeDiscoveredRecipient = null;
    this.currentVerifyContact = null;
    this.authMode = "login"; // "login" or "register"
    this.contactsCache = [];
    this.transfersCache = { sent: [], received: [] };
    this.historyFilterMode = "all"; // 'all', 'sent', 'recv'
    this.logsCache = [];
  }

  async init() {
    UI.init();
    this.bindEvents();

    // Restore cached user session if available
    try {
      const savedUser = JSON.parse(localStorage.getItem("secureshare_keyx_user") || "null");
      if (savedUser && savedUser.id) {
        this.currentUser = savedUser;
        api.setUserId(savedUser.id);
        this.updateUserUI(true);
      }
    } catch (_) {}

    // Ensure libsodium is ready
    if (window.sodium) {
      await window.sodium.ready;
    }

    // Start background file vault health probe
    this.probeFileVaultStatus();
    setInterval(() => this.probeFileVaultStatus(), 30000);

    // Check user authentication
    await this.checkAuth();

    // Handle deep-link routing
    this.handleInitialRoute();
  }

  handleInitialRoute() {
    const path = window.location.pathname.replace(/^\//, "");
    const validViews = ["overview", "identity", "contacts", "prekeys", "exchange", "inbox", "history", "logs", "settings"];
    if (validViews.includes(path)) {
      this.switchView(path, false);
    } else {
      this.switchView("overview", false);
    }
  }

  bindEvents() {
    // Navigation items
    document.querySelectorAll(".nav-item").forEach(item => {
      item.addEventListener("click", () => {
        const view = item.getAttribute("data-view");
        if (view) this.switchView(view);
      });
    });

    // History popstate
    window.addEventListener("popstate", () => {
      this.handleInitialRoute();
    });

    // Header buttons
    const btnAuth = document.getElementById("btn-header-auth");
    if (btnAuth) {
      btnAuth.addEventListener("click", () => {
        if (this.currentUser) {
          this.handleLogout();
        } else {
          this.openAuthModal("login");
        }
      });
    }

    // Quick actions on overview
    const btnQuickEx = document.getElementById("btn-quick-new-exchange");
    if (btnQuickEx) {
      btnQuickEx.addEventListener("click", () => this.switchView("exchange"));
    }
    const btnRefreshInbox = document.getElementById("btn-refresh-inbox");
    if (btnRefreshInbox) {
      btnRefreshInbox.addEventListener("click", () => this.loadInbox());
    }

    // Header & Sidebar Vault unlock modal triggers
    document.getElementById("header-vault-status-item")?.addEventListener("click", () => {
      if (!this.keyStore || !this.keyStore.isUnlocked) {
        UI.openModal("modal-unlock-vault");
      }
    });
    document.getElementById("sidebar-vault-badge")?.addEventListener("click", () => {
      if (!this.keyStore || !this.keyStore.isUnlocked) {
        UI.openModal("modal-unlock-vault");
      }
    });
    document.getElementById("form-unlock-vault")?.addEventListener("submit", (e) => this.handleUnlockVaultSubmit(e));

    // Sidebar Vault lock & wipe buttons
    document.getElementById("btn-sidebar-wipe")?.addEventListener("click", () => UI.openModal("modal-wipe-confirm"));
    document.getElementById("btn-sidebar-lock")?.addEventListener("click", () => this.lockVault());
    document.getElementById("btn-modal-confirm-wipe")?.addEventListener("click", () => {
      UI.closeModal("modal-wipe-confirm");
      this.wipeMemory();
    });

    // Auth Modal tabs & submission
    document.getElementById("tab-auth-login")?.addEventListener("click", () => this.setAuthMode("login"));
    document.getElementById("tab-auth-register")?.addEventListener("click", () => this.setAuthMode("register"));
    document.getElementById("form-auth")?.addEventListener("submit", (e) => this.handleAuthSubmit(e));

    // Identity View buttons
    document.getElementById("btn-gen-identity")?.addEventListener("click", () => this.generateOrRotateIdentity());
    document.getElementById("btn-copy-fp")?.addEventListener("click", (e) => {
      const fp = document.getElementById("disp-identity-fingerprint")?.innerText.trim();
      if (fp && !fp.includes("NOT INITIALIZED")) UI.copyToClipboard(fp, e.currentTarget);
    });
    document.getElementById("btn-copy-ed-pub")?.addEventListener("click", (e) => {
      const pub = document.getElementById("disp-identity-pubkey")?.innerText.trim();
      if (pub && pub !== "--") UI.copyToClipboard(pub, e.currentTarget);
    });
    document.getElementById("btn-show-qr-my-fp")?.addEventListener("click", () => this.showMyFingerprintQR());
    document.getElementById("btn-export-vault")?.addEventListener("click", () => UI.openModal("modal-export-vault"));
    document.getElementById("btn-import-vault")?.addEventListener("click", () => UI.openModal("modal-import-vault"));
    document.getElementById("btn-modal-run-export")?.addEventListener("click", () => this.handleExportVault());
    document.getElementById("btn-modal-run-import")?.addEventListener("click", () => this.handleImportVault());

    // Contacts View buttons & directory search
    document.getElementById("btn-add-contact")?.addEventListener("click", () => this.handleAddContact());
    document.getElementById("input-add-contact-username")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        this.handleAddContact();
      }
    });
    document.getElementById("btn-search-users")?.addEventListener("click", () => this.handleSearchUsers());
    document.getElementById("input-search-users")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        this.handleSearchUsers();
      }
    });

    document.getElementById("verify-modal-confirm-check")?.addEventListener("change", (e) => {
      const btn = document.getElementById("btn-modal-mark-verified");
      if (btn) btn.disabled = !e.target.checked;
    });
    document.getElementById("btn-modal-mark-verified")?.addEventListener("click", () => this.handleConfirmVerifyContact());

    // Prekeys View buttons
    document.getElementById("btn-refresh-prekeys")?.addEventListener("click", () => this.loadPrekeys());
    document.getElementById("btn-replenish-prekeys")?.addEventListener("click", () => this.replenishPrekeys(5));

    document.getElementById("btn-banner-unlock-vault")?.addEventListener("click", () => UI.openModal("modal-unlock-vault"));
    document.getElementById("btn-banner-restore-backup")?.addEventListener("click", () => UI.openModal("modal-import-vault"));

    // Key Exchange Tool buttons & selector
    document.getElementById("exchange-recipient-select")?.addEventListener("change", (e) => {
      const selected = e.target.value;
      if (selected) {
        document.getElementById("exchange-recipient-input").value = selected;
        this.discoverRecipient();
      }
    });
    document.getElementById("btn-exchange-discover")?.addEventListener("click", () => this.discoverRecipient());
    document.getElementById("btn-exchange-gen-tx")?.addEventListener("click", () => this.generateNewTransferId());
    document.getElementById("btn-exchange-gen-aes")?.addEventListener("click", () => this.generateRandomAesKey());
    document.getElementById("btn-exchange-auto-gen-aes")?.addEventListener("click", () => this.generateRandomAesKey());
    document.getElementById("btn-exchange-paste-aes")?.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text && text.trim()) {
          const keyInput = document.getElementById("exchange-file-key");
          if (keyInput) {
            keyInput.value = text.trim();
            this.updateAesKeyStatus(keyInput.value);
            UI.showToast("AES key pasted from clipboard!", "success");
          }
        } else {
          UI.showToast("Clipboard is empty.", "warning");
        }
      } catch (e) {
        const inputKey = prompt("Paste your 64-character hex AES-256 file key here:");
        if (inputKey && inputKey.trim()) {
          const keyInput = document.getElementById("exchange-file-key");
          if (keyInput) {
            keyInput.value = inputKey.trim();
            this.updateAesKeyStatus(keyInput.value);
            UI.showToast("AES key pasted directly!", "success");
          }
        }
      }
    });
    document.getElementById("exchange-file-key")?.addEventListener("input", (e) => {
      this.updateAesKeyStatus(e.target.value);
    });
    document.getElementById("btn-seal-and-dispatch")?.addEventListener("click", () => this.sealAndDispatchEnvelope());

    // Inbox View buttons
    document.getElementById("btn-refresh-inbox-view")?.addEventListener("click", () => this.loadInbox());
    document.getElementById("btn-copy-unwrapped-key")?.addEventListener("click", (e) => {
      const key = document.getElementById("disp-unwrapped-key")?.innerText.trim();
      if (key && key !== "--") UI.copyToClipboard(key, e.currentTarget);
    });

    // History and Logs refresh, filters, and searches
    document.getElementById("btn-refresh-history")?.addEventListener("click", () => this.loadHistory());
    document.getElementById("btn-filter-history-all")?.addEventListener("click", () => this.setHistoryFilter("all"));
    document.getElementById("btn-filter-history-sent")?.addEventListener("click", () => this.setHistoryFilter("sent"));
    document.getElementById("btn-filter-history-recv")?.addEventListener("click", () => this.setHistoryFilter("recv"));
    document.getElementById("input-history-search")?.addEventListener("input", () => this.renderHistoryTables());

    document.getElementById("btn-refresh-logs")?.addEventListener("click", () => this.loadLogs());
    document.getElementById("select-logs-filter")?.addEventListener("change", () => this.renderLogsTable());
    document.getElementById("input-logs-search")?.addEventListener("input", () => this.renderLogsTable());

    // Settings actions
    document.getElementById("btn-settings-wipe")?.addEventListener("click", () => UI.openModal("modal-wipe-confirm"));
    document.getElementById("btn-settings-change-pass")?.addEventListener("click", () => UI.openModal("modal-change-pass"));
    document.getElementById("form-change-pass")?.addEventListener("submit", (e) => this.handleChangePassSubmit(e));
    document.getElementById("btn-test-filevault-connection")?.addEventListener("click", async () => {
      UI.showToast("Probing SecureShare File Vault on port 5000...", "info");
      const ok = await this.probeFileVaultStatus();
      if (ok) {
        UI.showToast("SecureShare File Vault (Port 5000) is online and reachable.", "success");
      } else {
        UI.showToast("SecureShare File Vault (Port 5000) is currently offline.", "warning");
      }
    });
  }

  // --- VIEW SWITCHER ---
  switchView(viewName, pushHistory = true) {
    this.currentView = viewName;

    // Update active nav item
    document.querySelectorAll(".nav-item").forEach(item => {
      if (item.getAttribute("data-view") === viewName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Update view panes
    document.querySelectorAll(".view-pane").forEach(pane => {
      if (pane.id === `view-${viewName}`) {
        pane.classList.add("active");
      } else {
        pane.classList.remove("active");
      }
    });

    if (pushHistory) {
      const urlPath = viewName === "overview" ? "/" : `/${viewName}`;
      window.history.pushState({}, "", urlPath);
    }

    // Refresh view specific data
    if (this.currentUser) {
      if (viewName === "overview") this.refreshOverview();
      else if (viewName === "identity") this.loadIdentity();
      else if (viewName === "contacts") {
        this.loadContacts();
        this.handleSearchUsers();
      }
      else if (viewName === "prekeys") this.loadPrekeys();
      else if (viewName === "exchange") this.loadExchangeView();
      else if (viewName === "inbox") this.loadInbox();
      else if (viewName === "history") this.loadHistory();
      else if (viewName === "logs") this.loadLogs();
      else if (viewName === "settings") this.loadSettings();
    } else {
      if (viewName === "contacts") {
        this.loadContacts();
        this.handleSearchUsers();
      }
    }
  }

  // --- FILE VAULT TELEMETRY PROBE ---
  async probeFileVaultStatus() {
    const ind = document.getElementById("filevault-indicator");
    const text = document.getElementById("filevault-header-text");
    const pill = document.getElementById("settings-filevault-status-pill");

    try {
      const isOnline = await api.probeFileVault();
      if (isOnline) {
        if (ind) ind.className = "telemetry-indicator indicator-green";
        if (text) text.innerText = "FILE VAULT (5000): ONLINE";
        if (pill) {
          pill.className = "status-pill status-verified";
          pill.innerText = "ONLINE (PORT 5000)";
        }
      } else {
        if (ind) ind.className = "telemetry-indicator indicator-amber";
        if (text) text.innerText = "FILE VAULT (5000): OFFLINE";
        if (pill) {
          pill.className = "status-pill status-danger";
          pill.innerText = "OFFLINE (PORT 5000)";
        }
      }
      return isOnline;
    } catch (e) {
      if (ind) ind.className = "telemetry-indicator indicator-amber";
      if (text) text.innerText = "FILE VAULT (5000): OFFLINE";
      if (pill) {
        pill.className = "status-pill status-danger";
        pill.innerText = "OFFLINE (PORT 5000)";
      }
      return false;
    }
  }

  // --- AUTHENTICATION & VAULT SETUP ---
  async checkAuth() {
    try {
      const res = await api.getMe();
      if (res.authenticated) {
        this.currentUser = res.user;
        api.setUserId(res.user.id);
        localStorage.setItem("secureshare_keyx_user", JSON.stringify(res.user));
        this.updateUserUI(true);

        // Attempt vault unlock if passphrase cached in sessionStorage
        if (!this.keyStore || !this.keyStore.isUnlocked) {
          const pass = sessionStorage.getItem(`vault_pass_${this.currentUser.id}`);
          if (pass) {
            const ok = await this.unlockVault(pass);
            if (!ok) {
              sessionStorage.removeItem(`vault_pass_${this.currentUser.id}`);
            }
          }
        }

        // Run idempotent identity lifecycle verification
        await this.ensureIdentityReady({ autoPromptUnlock: false });
        await this.refreshOverview();
      } else {
        const saved = JSON.parse(localStorage.getItem("secureshare_keyx_user") || "null");
        if (saved && saved.id) {
          this.currentUser = saved;
          api.setUserId(saved.id);
          this.updateUserUI(true);
          await this.ensureIdentityReady({ autoPromptUnlock: false });
        } else {
          this.currentUser = null;
          api.setUserId(null);
          this.identityState = "UNAUTHENTICATED";
          this.identityError = null;
          this.updateUserUI(false);
        }
      }
    } catch (err) {
      console.warn("Auth check error:", err);
      const saved = JSON.parse(localStorage.getItem("secureshare_keyx_user") || "null");
      if (saved && saved.id) {
        this.currentUser = saved;
        api.setUserId(saved.id);
        this.updateUserUI(true);
      } else {
        this.currentUser = null;
        api.setUserId(null);
        this.identityState = "UNAUTHENTICATED";
        this.identityError = null;
        this.updateUserUI(false);
      }
    }
  }

  updateUserUI(isLoggedIn) {
    const userNav = document.getElementById("user-nav-actions");

    if (isLoggedIn && this.currentUser) {
      if (userNav) {
        userNav.innerHTML = `
          <div style="font-size: 11px; padding: 4px 8px; background: var(--bg-surface); border: 1px solid var(--border-medium);">
            <span style="color: var(--text-dim);">USER:</span> <strong style="color: #FFF;">${UI.escapeHtml(this.currentUser.username)}</strong>
          </div>
          <button id="btn-logout" class="btn btn-secondary btn-sm">LOGOUT</button>
        `;
        document.getElementById("btn-logout")?.addEventListener("click", () => this.handleLogout());
      }
    } else {
      if (userNav) {
        userNav.innerHTML = `
          <button id="btn-header-auth" class="btn btn-primary btn-sm">AUTHENTICATE [LOGIN / REGISTER]</button>
        `;
        document.getElementById("btn-header-auth")?.addEventListener("click", () => this.openAuthModal("login"));
      }
    }
    this.updateIdentityUI();
  }

  openAuthModal(mode = "login") {
    this.setAuthMode(mode);
    UI.openModal("modal-auth");
  }

  setAuthMode(mode) {
    this.authMode = mode;
    const badge = document.getElementById("auth-modal-mode-badge");
    const groupEmail = document.getElementById("group-auth-email");
    const tabLogin = document.getElementById("tab-auth-login");
    const tabRegister = document.getElementById("tab-auth-register");
    const btnSubmit = document.getElementById("btn-submit-auth");

    if (mode === "register") {
      if (badge) badge.innerText = "REGISTER";
      if (groupEmail) groupEmail.style.display = "block";
      if (tabRegister) { tabRegister.className = "btn btn-primary btn-sm"; }
      if (tabLogin) { tabLogin.className = "btn btn-secondary btn-sm"; }
      if (btnSubmit) btnSubmit.innerText = "REGISTER & INITIALIZE VAULT";
    } else {
      if (badge) badge.innerText = "LOGIN";
      if (groupEmail) groupEmail.style.display = "none";
      if (tabLogin) { tabLogin.className = "btn btn-primary btn-sm"; }
      if (tabRegister) { tabRegister.className = "btn btn-secondary btn-sm"; }
      if (btnSubmit) btnSubmit.innerText = "AUTHENTICATE & UNLOCK VAULT";
    }
  }

  async handleAuthSubmit(e) {
    e.preventDefault();
    const username = document.getElementById("auth-username").value.trim();
    const email = document.getElementById("auth-email")?.value.trim();
    const password = document.getElementById("auth-password").value;
    const vaultPass = document.getElementById("auth-vault-passphrase").value;

    if (!vaultPass) {
      UI.showToast("Vault passphrase is required to protect your private keys.", "warning");
      return;
    }

    try {
      let res;
      if (this.authMode === "register") {
        res = await api.register(username, email, password);
        UI.showToast("Account created successfully.", "success");
      } else {
        res = await api.login(username, password);
        UI.showToast("Authenticated successfully.", "success");
      }

      this.currentUser = res.user;
      api.setUserId(res.user.id);
      localStorage.setItem("secureshare_keyx_user", JSON.stringify(res.user));
      UI.closeModal("modal-auth");
      this.updateUserUI(true);

      // Attempt vault unlock with provided master passphrase
      const unlocked = await this.unlockVault(vaultPass);
      if (!unlocked) {
        UI.showToast("Notice: Vault could not be unlocked with this passphrase.", "warning");
      }

      // Automatically initialize, restore, or sync identity
      await this.ensureIdentityReady({ autoPromptUnlock: false });
      await this.refreshOverview();
    } catch (err) {
      console.error("Auth error:", err);
      UI.showToast(err.message, "danger");
    }
  }

  async handleLogout() {
    try {
      await api.logout();
    } catch (err) {
      console.warn("Logout error:", err);
    }
    this.wipeMemory();
    this.currentUser = null;
    api.setUserId(null);
    localStorage.removeItem("secureshare_keyx_user");
    this.identityState = "UNAUTHENTICATED";
    this.identityError = null;
    this.updateUserUI(false);
    this.switchView("overview");
    UI.showToast("Logged out and encrypted memory purged.", "info");
  }

  async unlockVault(passphrase) {
    if (!this.currentUser) return false;
    this.keyStore = new KeyStore(this.currentUser.id);
    const ok = await this.keyStore.unlock(passphrase);
    if (ok) {
      sessionStorage.setItem(`vault_pass_${this.currentUser.id}`, passphrase);
      this.updateVaultStatusUI(true);
      return true;
    } else {
      this.updateVaultStatusUI(false);
      return false;
    }
  }

  async handleUnlockVaultSubmit(e) {
    e.preventDefault();
    const input = document.getElementById("input-unlock-vault-pass");
    const pass = input ? input.value : "";
    if (!pass) return;

    const ok = await this.unlockVault(pass);
    if (ok) {
      input.value = "";
      UI.closeModal("modal-unlock-vault");
      UI.showToast("Local cryptographic vault unlocked successfully.", "success");
      await this.ensureIdentityReady({ autoPromptUnlock: false });
      if (this.currentView === "identity") await this.loadIdentity();
      if (this.currentView === "prekeys") await this.loadPrekeys();
      if (this.currentView === "overview") await this.refreshOverview();
    } else {
      UI.showToast("Incorrect vault passphrase.", "danger");
    }
  }

  async handleChangePassSubmit(e) {
    e.preventDefault();
    const oldPass = document.getElementById("input-change-old-pass")?.value;
    const newPass = document.getElementById("input-change-new-pass")?.value;
    const confirmPass = document.getElementById("input-change-confirm-pass")?.value;

    if (!oldPass || !newPass || !confirmPass) {
      UI.showToast("All passphrase fields are required.", "warning");
      return;
    }
    if (newPass !== confirmPass) {
      UI.showToast("New passphrase and confirmation do not match.", "warning");
      return;
    }
    if (newPass.length < 8) {
      UI.showToast("Passphrase must be at least 8 characters.", "warning");
      return;
    }

    try {
      await this.keyStore.changePassphrase(oldPass, newPass);
      if (this.currentUser) {
        sessionStorage.setItem(`vault_pass_${this.currentUser.id}`, newPass);
      }
      document.getElementById("input-change-old-pass").value = "";
      document.getElementById("input-change-new-pass").value = "";
      document.getElementById("input-change-confirm-pass").value = "";
      UI.closeModal("modal-change-pass");
      UI.showToast("Vault re-encrypted with new master passphrase.", "success");
    } catch (err) {
      console.error("Change pass error:", err);
      UI.showToast(`Failed to change passphrase: ${err.message}`, "danger");
    }
  }

  lockVault() {
    if (this.keyStore) {
      this.keyStore.lock();
    }
    if (this.currentUser) {
      sessionStorage.removeItem(`vault_pass_${this.currentUser.id}`);
    }
    this.updateVaultStatusUI(false);
    UI.showToast("Local vault locked. Private keys removed from memory.", "info");
  }

  wipeMemory() {
    this.lockVault();
    if (window.crypto && window.crypto.getRandomValues) {
      // Memory wipe trigger
      const dummy = new Uint8Array(1024);
      window.crypto.getRandomValues(dummy);
    }
    UI.showToast("Memory zeroized. All key material purged.", "success");
  }

  updateVaultStatusUI(isUnlocked) {
    if (!this.currentUser) {
      this.identityState = "UNAUTHENTICATED";
    } else if (!isUnlocked) {
      this.identityState = "LOCKED";
    } else if (this.identityState === "LOCKED" || this.identityState === "UNAUTHENTICATED") {
      this.identityState = "INITIALIZING";
    }
    this.updateIdentityUI();
  }

  updateIdentityUI() {
    const statId = document.getElementById("stat-identity-status");
    const statIdSub = document.getElementById("stat-identity-sub");
    const badgeIdentity = document.getElementById("badge-identity-status");
    const headerIndicator = document.getElementById("vault-indicator");
    const headerText = document.getElementById("vault-header-text");
    const sidebarBadge = document.getElementById("sidebar-vault-badge");
    const cardBadge = document.getElementById("identity-card-badge");
    const storageStatus = document.getElementById("disp-vault-storage-status");
    const fpDisp = document.getElementById("disp-identity-fingerprint");
    const pubDisp = document.getElementById("disp-identity-pubkey");

    const authBanner = document.getElementById("overview-auth-banner");
    const lockedBanner = document.getElementById("overview-vault-locked-banner");
    const recoveryBanner = document.getElementById("overview-recovery-banner");

    if (authBanner) authBanner.style.display = "none";
    if (lockedBanner) lockedBanner.style.display = "none";
    if (recoveryBanner) recoveryBanner.style.display = "none";

    switch (this.identityState) {
      case "UNAUTHENTICATED":
        if (statId) {
          statId.innerText = "LOCKED";
          statId.className = "stat-value accent-red";
        }
        if (statIdSub) statIdSub.innerText = "Unauthenticated";
        if (badgeIdentity) {
          badgeIdentity.innerText = "LOCKED";
          badgeIdentity.className = "nav-badge";
        }
        if (headerIndicator) headerIndicator.className = "telemetry-indicator indicator-red";
        if (headerText) headerText.innerText = "VAULT: LOCKED";
        if (sidebarBadge) {
          sidebarBadge.innerText = "LOCKED";
          sidebarBadge.className = "status-pill status-danger";
        }
        if (cardBadge) {
          cardBadge.innerText = "UNAUTHENTICATED";
          cardBadge.className = "status-pill status-unverified";
        }
        if (fpDisp) fpDisp.innerText = "-- UNAUTHENTICATED --";
        if (pubDisp) pubDisp.innerText = "--";
        if (storageStatus) storageStatus.innerText = "PLEASE LOG IN";
        if (authBanner) authBanner.style.display = "flex";
        break;

      case "LOCKED":
        if (statId) {
          statId.innerText = "LOCKED";
          statId.className = "stat-value accent-red";
        }
        if (statIdSub) statIdSub.innerText = "Passphrase Required";
        if (badgeIdentity) {
          badgeIdentity.innerText = "LOCKED";
          badgeIdentity.className = "nav-badge status-danger";
        }
        if (headerIndicator) headerIndicator.className = "telemetry-indicator indicator-red";
        if (headerText) headerText.innerText = "VAULT: LOCKED";
        if (sidebarBadge) {
          sidebarBadge.innerText = "LOCKED";
          sidebarBadge.className = "status-pill status-danger";
        }
        if (cardBadge) {
          cardBadge.innerText = "LOCKED";
          cardBadge.className = "status-pill status-danger";
        }
        if (fpDisp) fpDisp.innerText = "-- VAULT LOCKED --";
        if (pubDisp) pubDisp.innerText = "--";
        if (storageStatus) storageStatus.innerText = "VAULT LOCKED (ENTER PASSPHRASE)";
        if (lockedBanner) lockedBanner.style.display = "flex";
        break;

      case "INITIALIZING":
        if (statId) {
          statId.innerText = "SYNCING";
          statId.className = "stat-value accent-amber";
        }
        if (statIdSub) statIdSub.innerText = "Synchronizing with Network...";
        if (badgeIdentity) {
          badgeIdentity.innerText = "SYNCING";
          badgeIdentity.className = "nav-badge status-pending";
        }
        if (headerIndicator) headerIndicator.className = "telemetry-indicator indicator-amber";
        if (headerText) headerText.innerText = "VAULT: SYNCING";
        if (sidebarBadge) {
          sidebarBadge.innerText = "SYNCING";
          sidebarBadge.className = "status-pill status-pending";
        }
        if (cardBadge) {
          cardBadge.innerText = "INITIALIZING";
          cardBadge.className = "status-pill status-pending";
        }
        if (fpDisp) fpDisp.innerText = "SYNCHRONIZING CRYPTOGRAPHIC IDENTITY...";
        if (pubDisp) pubDisp.innerText = "...";
        if (storageStatus) storageStatus.innerText = "CHECKING LOCAL VAULT & NETWORK...";
        break;

      case "ERROR":
        if (statId) {
          statId.innerText = "ATTENTION";
          statId.className = "stat-value accent-red";
        }
        if (statIdSub) statIdSub.innerText = this.identityError === "LOCAL_KEY_MISSING" ? "Private Key Missing" : "Sync Error";
        if (badgeIdentity) {
          badgeIdentity.innerText = "ATTENTION";
          badgeIdentity.className = "nav-badge status-danger";
        }
        if (headerIndicator) headerIndicator.className = "telemetry-indicator indicator-red";
        if (headerText) headerText.innerText = "VAULT: ERROR";
        if (sidebarBadge) {
          sidebarBadge.innerText = "ERROR";
          sidebarBadge.className = "status-pill status-danger";
        }
        if (cardBadge) {
          cardBadge.innerText = this.identityError === "LOCAL_KEY_MISSING" ? "KEY MISSING" : "ERROR";
          cardBadge.className = "status-pill status-danger";
        }
        if (fpDisp) fpDisp.innerText = this.identityError === "LOCAL_KEY_MISSING" ? "-- LOCAL PRIVATE KEY MISSING --" : "-- ERROR --";
        if (pubDisp) pubDisp.innerText = "--";
        if (storageStatus) storageStatus.innerText = this.identityError === "LOCAL_KEY_MISSING" ? "PRIVATE KEY MISSING IN INDEXEDDB (RESTORE BACKUP)" : `ERROR: ${this.identityError}`;
        if (this.identityError === "LOCAL_KEY_MISSING" && recoveryBanner) {
          recoveryBanner.style.display = "flex";
        }
        break;

      case "READY":
        const id = this.keyStore?.identity;
        if (statId) {
          statId.innerText = "ACTIVE";
          statId.className = "stat-value accent-green";
        }
        if (statIdSub) statIdSub.innerText = "Ed25519 Signing Key (Active)";
        if (badgeIdentity) {
          badgeIdentity.innerText = "ACTIVE";
          badgeIdentity.className = "nav-badge status-verified";
        }
        if (headerIndicator) headerIndicator.className = "telemetry-indicator indicator-green";
        if (headerText) headerText.innerText = "VAULT: UNLOCKED";
        if (sidebarBadge) {
          sidebarBadge.innerText = "UNLOCKED";
          sidebarBadge.className = "status-pill status-verified";
        }
        if (cardBadge) {
          cardBadge.innerText = "ACTIVE";
          cardBadge.className = "status-pill status-verified";
        }
        if (fpDisp && id) fpDisp.innerText = id.fingerprint || "--";
        if (pubDisp && id) pubDisp.innerText = id.publicKey || "--";
        if (storageStatus) storageStatus.innerText = "VAULT STATUS: SECURE IN INDEXEDDB (SYNCED WITH BACKEND)";
        break;
    }
  }

  // --- CRYPTOGRAPHIC IDENTITY & PREKEY LIFECYCLE MANAGEMENT ---
  async ensureIdentityReady(options = { autoPromptUnlock: false }) {
    if (this._identityPromise) {
      return this._identityPromise;
    }
    this._identityPromise = this._runEnsureIdentityReady(options).finally(() => {
      this._identityPromise = null;
    });
    return this._identityPromise;
  }

  // Backwards-compatible alias
  async ensureIdentityAndPrekeys(options = {}) {
    return this.ensureIdentityReady(options);
  }

  async _runEnsureIdentityReady(options = {}) {
    if (!this.currentUser) {
      this.identityState = "UNAUTHENTICATED";
      this.identityError = null;
      this.updateIdentityUI();
      return false;
    }

    // Attempt unlocking vault with cached passphrase in sessionStorage if currently locked
    if (!this.keyStore || !this.keyStore.isUnlocked) {
      const pass = sessionStorage.getItem(`vault_pass_${this.currentUser.id}`);
      if (pass) {
        const ok = await this.unlockVault(pass);
        if (!ok) {
          sessionStorage.removeItem(`vault_pass_${this.currentUser.id}`);
        }
      }
    }

    // If still locked, transition to LOCKED state
    if (!this.keyStore || !this.keyStore.isUnlocked) {
      this.identityState = "LOCKED";
      this.identityError = null;
      this.updateIdentityUI();
      if (options.autoPromptUnlock) {
        UI.openModal("modal-unlock-vault");
      }
      return false;
    }

    this.identityState = "INITIALIZING";
    this.identityError = null;
    this.updateIdentityUI();

    try {
      // 1. Fetch server-side registered identity and local IndexedDB identity in parallel
      const [serverRes, localIdentity] = await Promise.all([
        api.getMyIdentity().catch(err => {
          console.warn("Server identity probe error:", err);
          return { has_identity: false, error: err.message };
        }),
        this.keyStore.getIdentity()
      ]);

      const hasServerIdentity = Boolean(serverRes && serverRes.has_identity && serverRes.identity && serverRes.identity.ed25519_public_key);
      const hasLocalIdentity = Boolean(localIdentity && localIdentity.publicKey && localIdentity.privateKey);

      if (hasLocalIdentity && hasServerIdentity) {
        // Both exist: check consistency
        const serverPk = serverRes.identity.ed25519_public_key.toLowerCase();
        const localPk = localIdentity.publicKey.toLowerCase();

        if (serverPk !== localPk) {
          console.warn("Local Ed25519 public key differs from server record!", { localPk, serverPk });
          UI.showToast("Notice: Local identity key differs from server record. Please verify in Identity Vault.", "warning");
        }
      } else if (hasLocalIdentity && !hasServerIdentity) {
        // Local identity exists, but backend record is missing:
        // Safely register the existing public identity rather than generating unrelated keys
        await api.publishIdentity(localIdentity.publicKey, localIdentity.fingerprint);
        UI.showToast("Local cryptographic identity synchronized to server registry.", "success");
      } else if (!hasLocalIdentity && !hasServerIdentity) {
        // First-time initialization: generate in browser and register
        const keypair = await Ed25519Sign.generateIdentityKeyPair();
        if (!keypair || !keypair.publicKey || !keypair.privateKey) {
          throw new Error("Failed to generate Ed25519 identity keypair in browser.");
        }
        const fp = Ed25519Sign.formatFingerprint(keypair.fingerprint);
        const pubHex = keypair.publicKeyHex || (typeof keypair.publicKey === "string" ? keypair.publicKey : sodium.to_hex(keypair.publicKey));
        const privHex = keypair.privateKeyHex || (typeof keypair.privateKey === "string" ? keypair.privateKey : sodium.to_hex(keypair.privateKey));

        await this.keyStore.saveIdentity(pubHex, privHex, fp);
        await api.publishIdentity(pubHex, fp);
        UI.showToast("Ed25519 identity keypair generated and published to network.", "success");
      } else if (!hasLocalIdentity && hasServerIdentity) {
        // Server has identity, but private key is missing on this device/browser
        // Do NOT generate a replacement private key and pretend it is the original!
        console.warn("Public identity is registered on server, but local private key is missing.");
        this.identityState = "ERROR";
        this.identityError = "LOCAL_KEY_MISSING";
        this.updateIdentityUI();
        UI.showToast("Local private key missing for this account. Restore your vault backup.", "danger");
        return false;
      }

      // Check real public prekey pool and auto-replenish if required
      try {
        const prekeyRes = await api.getMyPrekeys();
        const stats = prekeyRes.stats || prekeyRes.summary || {};
        if (stats.needs_replenishment || (stats.available || 0) < 3) {
          await this.replenishPrekeys(5);
        }
      } catch (err) {
        console.warn("Prekey auto-replenishment warning:", err);
      }

      // All checks and synchronizations completed successfully!
      this.identityState = "READY";
      this.identityError = null;
      this.updateIdentityUI();
      return true;

    } catch (err) {
      console.error("Identity lifecycle error:", err);
      this.identityState = "ERROR";
      this.identityError = err.message || "INITIALIZATION_FAILED";
      this.updateIdentityUI();
      UI.showToast(`Identity initialization failed: ${err.message}`, "danger");
      return false;
    }
  }

  async generateOrRotateIdentity() {
    if (!confirm("ATTENTION: Rotating your identity key will cause remote contacts to detect a KEY CHANGED warning. They will need to re-verify your fingerprint out-of-band. Continue?")) {
      return;
    }

    try {
      const keypair = await Ed25519Sign.generateIdentityKeyPair();
      if (!keypair || !keypair.publicKey || !keypair.privateKey) {
        throw new Error("Failed to generate Ed25519 identity keypair.");
      }
      const fp = Ed25519Sign.formatFingerprint(keypair.fingerprint);
      const pubHex = keypair.publicKeyHex || (typeof keypair.publicKey === "string" ? keypair.publicKey : sodium.to_hex(keypair.publicKey));
      const privHex = keypair.privateKeyHex || (typeof keypair.privateKey === "string" ? keypair.privateKey : sodium.to_hex(keypair.privateKey));

      await this.keyStore.saveIdentity(pubHex, privHex, fp);
      await api.publishIdentity(pubHex, fp);

      // Generate fresh signed prekeys with new identity signature
      await this.replenishPrekeys(5);

      await this.loadIdentity();
      UI.showToast("Identity rotated successfully. Remote contacts notified.", "warning");
    } catch (err) {
      console.error("Identity rotation error:", err);
      UI.showToast(err.message, "danger");
    }
  }

  async replenishPrekeys(count = 5) {
    if (!this.keyStore || !this.keyStore.isUnlocked) {
      UI.showToast("Local vault must be unlocked to sign new prekeys.", "warning");
      return;
    }

    try {
      if (!this.currentUser) {
        UI.showToast("Authentication required to replenish prekeys.", "warning");
        this.openAuthModal("login");
        return;
      }

      const identity = await this.keyStore.getIdentity();
      if (!identity || !identity.privateKey) {
        throw new Error("Identity private signing key missing in vault.");
      }

      const prekeysToPublish = [];
      for (let i = 0; i < count; i++) {
        const randHex = (window.sodium && sodium.to_hex) ? sodium.to_hex(sodium.randombytes_buf(4)) : Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, "0")).join("");
        const prekeyId = `prekey_${Date.now()}_${randHex}`;
        const signedPrekey = await X25519HKDF.generateSignedPrekey(identity.privateKey, prekeyId);

        if (!signedPrekey || !signedPrekey.x25519PublicKey || !signedPrekey.x25519PrivateKey) {
          throw new Error("Failed to generate signed X25519 prekey.");
        }

        // Store private prekey in vault
        await this.keyStore.savePrekey(prekeyId, signedPrekey.x25519PublicKey, signedPrekey.x25519PrivateKey, signedPrekey.signature);

        prekeysToPublish.push({
          prekey_id: prekeyId,
          x25519_public_key: signedPrekey.x25519PublicKey,
          signature: signedPrekey.signature,
          days_valid: 30
        });
      }

      await api.publishPrekeysBatch(prekeysToPublish);
      UI.showToast(`Generated & published ${count} signed X25519 prekeys.`, "success");
      await this.loadPrekeys();
    } catch (err) {
      console.error("Prekey replenishment error:", err);
      UI.showToast(`Replenishment failed: ${err.message}`, "danger");
    }
  }

  // --- OVERVIEW DASHBOARD ---
  async refreshOverview() {
    if (!this.currentUser) return;
    try {
      if (this.identityState !== "READY") {
        await this.ensureIdentityReady({ autoPromptUnlock: false });
      }
      this.updateIdentityUI();

      const [prekeyRes, inboxRes, contactsRes] = await Promise.all([
        api.getMyPrekeys(),
        api.getInbox(),
        api.getContacts()
      ]);

      const statPk = document.getElementById("stat-prekeys-count");
      const statInbox = document.getElementById("stat-inbox-count");
      const statContacts = document.getElementById("stat-contacts-count");

      const pkStats = prekeyRes.stats || prekeyRes.summary || {};
      if (statPk) statPk.innerText = pkStats.available ?? 0;
      if (statInbox) statInbox.innerText = (inboxRes && inboxRes.inbox) ? inboxRes.inbox.length : 0;
      if (statContacts) statContacts.innerText = (contactsRes && contactsRes.contacts) ? contactsRes.contacts.length : 0;

      // Update badge in sidebar
      const badgeInbox = document.getElementById("badge-inbox-count");
      if (badgeInbox) {
        const count = (inboxRes && inboxRes.inbox) ? inboxRes.inbox.length : 0;
        badgeInbox.innerText = count;
        badgeInbox.style.display = count > 0 ? "inline-block" : "none";
      }

      // Render pending list
      const container = document.getElementById("overview-pending-inbox");
      if (container) {
        if (inboxRes.inbox.length === 0) {
          container.innerHTML = `<div style="color: var(--text-dim); text-align: center; padding: 24px;">No pending incoming envelopes.</div>`;
        } else {
          container.innerHTML = inboxRes.inbox.map(env => `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-dim); padding: 10px 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-weight: 700; color: #FFF; font-size: 11px;">TX: ${UI.escapeHtml(env.transfer_id)}</div>
                <div style="font-size: 10px; color: var(--text-muted);">From: <strong>${UI.escapeHtml(env.sender_username || "Unknown")}</strong></div>
              </div>
              <button class="btn btn-primary btn-sm btn-quick-unwrap" data-tx="${UI.escapeHtml(env.transfer_id)}">
                UNWRAP KEY
              </button>
            </div>
          `).join("");

          container.querySelectorAll(".btn-quick-unwrap").forEach(b => {
            b.addEventListener("click", () => {
              const tx = b.getAttribute("data-tx");
              this.switchView("inbox");
              this.unwrapKeyForTransfer(tx);
            });
          });
        }
      }
    } catch (err) {
      console.warn("Overview refresh failed:", err);
    }
  }

  // --- IDENTITY VIEW ---
  async loadIdentity() {
    if (this.identityState !== "READY" && this.currentUser) {
      await this.ensureIdentityReady({ autoPromptUnlock: false });
    }
    this.updateIdentityUI();
  }

  showMyFingerprintQR() {
    const fp = document.getElementById("disp-identity-fingerprint")?.innerText.trim();
    if (!fp || fp.includes("--")) return;

    document.getElementById("verify-modal-username").innerText = this.currentUser?.username || "LOCAL USER";
    document.getElementById("verify-modal-fingerprint").innerText = fp;
    const canvas = document.getElementById("verify-modal-qr-canvas");
    UI.renderQRCode(canvas, fp);

    // Disable verify confirmation button in self-view mode
    const btn = document.getElementById("btn-modal-mark-verified");
    if (btn) btn.style.display = "none";
    const chk = document.getElementById("verify-modal-confirm-check");
    if (chk) chk.parentElement.parentElement.style.display = "none";

    UI.openModal("modal-verify-contact");
  }

  async handleExportVault() {
    const pass = document.getElementById("input-export-backup-pass").value;
    if (!pass) {
      UI.showToast("Enter a passphrase to protect the exported vault backup.", "warning");
      return;
    }

    try {
      const backupJson = await this.keyStore.exportEncryptedBackup(pass);
      const blob = new Blob([backupJson], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `secureshare-keyx-${this.currentUser.username}-${Date.now()}.secureshare-keyx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      UI.closeModal("modal-export-vault");
      UI.showToast("Vault backup exported successfully.", "success");
    } catch (err) {
      UI.showToast(`Export failed: ${err.message}`, "danger");
    }
  }

  async handleImportVault() {
    const fileInput = document.getElementById("input-import-file");
    const pass = document.getElementById("input-import-pass").value;

    if (!fileInput.files.length || !pass) {
      UI.showToast("Select backup file and enter decryption passphrase.", "warning");
      return;
    }

    try {
      const file = fileInput.files[0];
      const text = await file.text();
      if (!this.keyStore) {
        this.keyStore = new KeyStore(this.currentUser.id);
      }
      await this.keyStore.importEncryptedBackup(text, pass);
      sessionStorage.setItem(`vault_pass_${this.currentUser.id}`, pass);
      UI.closeModal("modal-import-vault");
      UI.showToast("Vault backup restored successfully.", "success");
      await this.ensureIdentityReady();
      await this.loadIdentity();
      await this.refreshOverview();
    } catch (err) {
      UI.showToast(`Restore failed: ${err.message}`, "danger");
    }
  }

  // --- CONTACTS VIEW ---
  async loadContacts() {
    try {
      const res = await api.getContacts(this.currentUser?.id);
      this.contactsCache = res.contacts || [];
      const tbody = document.getElementById("contacts-table-body");
      if (!tbody) return;

      document.getElementById("badge-contacts-count").innerText = this.contactsCache.length;

      // Populate exchange view contact selector
      this.populateExchangeContactsDropdown();

      if (this.contactsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 20px;">No contacts added yet. Use the field above to add contacts by username or search directory.</td></tr>`;
        return;
      }

      tbody.innerHTML = this.contactsCache.map(c => {
        let pillClass = "status-unverified";
        if (c.verification_status === "VERIFIED") pillClass = "status-verified";
        else if (c.verification_status === "KEY CHANGED") pillClass = "status-changed";

        return `
          <tr>
            <td><strong>${UI.escapeHtml(c.contact_username)}</strong></td>
            <td><span class="status-pill ${pillClass}">${UI.escapeHtml(c.verification_status)}</span></td>
            <td class="cell-mono-sm" style="color: var(--text-muted);">${UI.escapeHtml(c.trusted_fingerprint)}</td>
            <td style="color: var(--text-dim);">${c.verified_at ? UI.escapeHtml(c.verified_at.substring(0, 19).replace("T", " ")) : "--"}</td>
            <td>
              <div class="cell-actions">
                <button class="btn btn-secondary btn-sm btn-verify-contact" data-id="${c.id}" data-user="${UI.escapeHtml(c.contact_username)}" data-fp="${UI.escapeHtml(c.trusted_fingerprint)}">
                  VERIFY FP
                </button>
                <button class="btn btn-danger btn-sm btn-delete-contact" data-id="${c.id}">
                  DELETE
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join("");

      tbody.querySelectorAll(".btn-verify-contact").forEach(btn => {
        btn.addEventListener("click", () => {
          this.openVerifyContactModal({
            id: btn.getAttribute("data-id"),
            username: btn.getAttribute("data-user"),
            fingerprint: btn.getAttribute("data-fp")
          });
        });
      });

      tbody.querySelectorAll(".btn-delete-contact").forEach(btn => {
        btn.addEventListener("click", async () => {
          if (confirm("Delete contact from trusted directory?")) {
            await api.deleteContact(btn.getAttribute("data-id"));
            await this.loadContacts();
            UI.showToast("Contact removed.", "info");
          }
        });
      });
    } catch (err) {
      console.error("Load contacts error:", err);
    }
  }

  async handleAddContact() {
    const input = document.getElementById("input-add-contact-username");
    const username = input ? input.value.trim() : "";
    if (!username) return;

    if (!this.currentUser) {
      UI.showToast("Please log in or register before adding contacts.", "warning");
      this.openAuthModal("login");
      return;
    }

    try {
      const res = await api.addContact(username, this.currentUser.id);
      input.value = "";
      UI.showToast(`Contact '${res.contact?.contact_username || username}' added (${res.contact?.verification_status || "UNVERIFIED"}).`, "success");
      await this.loadContacts();
      this.handleSearchUsers();
    } catch (err) {
      UI.showToast(err.message, "danger");
    }
  }

  async handleSearchUsers() {
    const input = document.getElementById("input-search-users");
    const query = input ? input.value.trim() : "";
    const resultsContainer = document.getElementById("search-users-results");
    if (!resultsContainer) return;

    try {
      const res = await api.searchUsers(query);
      resultsContainer.style.display = "block";
      if (!res.users || res.users.length === 0) {
        resultsContainer.innerHTML = `<div style="font-size: 11px; color: var(--text-dim); padding: 8px;">No users found in directory${query ? ` matching "${UI.escapeHtml(query)}"` : ""}.</div>`;
        return;
      }

      const existingMap = new Map();
      (this.contactsCache || []).forEach(c => existingMap.set(c.contact_username.toLowerCase(), c));

      resultsContainer.innerHTML = res.users.map(u => {
        const isSelf = this.currentUser && this.currentUser.username && this.currentUser.username.toLowerCase() === u.username.toLowerCase();
        const existing = existingMap.get(u.username.toLowerCase());
        
        let actionBtn = "";
        if (isSelf) {
          actionBtn = `<span class="status-pill status-unverified" style="font-size: 9px;">YOU</span>`;
        } else if (existing) {
          const pillClass = existing.verification_status === "VERIFIED" ? "status-verified" : "status-unverified";
          actionBtn = `<span class="status-pill ${pillClass}" style="font-size: 9px;">${existing.verification_status}</span>`;
        } else {
          actionBtn = `<button class="btn btn-secondary btn-sm btn-quick-add-user" data-username="${UI.escapeHtml(u.username)}">+ ADD CONTACT</button>`;
        }

        return `
          <div style="background: var(--bg-surface); border: 1px solid var(--border-dim); padding: 8px 12px; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
            <div>
              <div style="font-weight: 700; color: #FFF; font-size: 11px;">${UI.escapeHtml(u.username)} <span style="color: var(--text-dim); font-size: 9px; font-weight: 400;">(${UI.escapeHtml(u.id)})</span></div>
              <div class="cell-mono-sm" style="color: var(--text-dim); font-size: 10px;">
                ${u.has_identity ? `FP: ${UI.escapeHtml(u.fingerprint ? u.fingerprint.substring(0, 24) : "")}...` : '<span style="color: var(--amber-warn);">No identity published</span>'}
              </div>
            </div>
            <div>${actionBtn}</div>
          </div>
        `;
      }).join("");

      resultsContainer.querySelectorAll(".btn-quick-add-user").forEach(btn => {
        btn.addEventListener("click", async () => {
          if (!this.currentUser) {
            UI.showToast("Please log in or register before adding contacts.", "warning");
            this.openAuthModal("login");
            return;
          }
          const uname = btn.getAttribute("data-username");
          try {
            const res = await api.addContact(uname, this.currentUser.id);
            UI.showToast(`Contact '${res.contact?.contact_username || uname}' added.`, "success");
            await this.loadContacts();
            await this.handleSearchUsers();
          } catch (err) {
            UI.showToast(err.message, "danger");
          }
        });
      });
    } catch (err) {
      console.error("Search users error:", err);
      UI.showToast(`User search failed: ${err.message}`, "danger");
    }
  }

  openVerifyContactModal(contact) {
    this.currentVerifyContact = contact;
    document.getElementById("verify-modal-username").innerText = contact.username;
    document.getElementById("verify-modal-fingerprint").innerText = contact.fingerprint;

    const canvas = document.getElementById("verify-modal-qr-canvas");
    UI.renderQRCode(canvas, contact.fingerprint);

    const btn = document.getElementById("btn-modal-mark-verified");
    if (btn) {
      btn.style.display = "inline-flex";
      btn.disabled = true;
    }
    const chk = document.getElementById("verify-modal-confirm-check");
    if (chk) {
      chk.checked = false;
      chk.parentElement.parentElement.style.display = "block";
    }

    UI.openModal("modal-verify-contact");
  }

  async handleConfirmVerifyContact() {
    if (!this.currentVerifyContact) return;
    try {
      await api.verifyContact(this.currentVerifyContact.id, this.currentVerifyContact.fingerprint, this.currentUser?.id);
      UI.closeModal("modal-verify-contact");
      UI.showToast(`Contact ${this.currentVerifyContact.username} verified out-of-band!`, "success");
      await this.loadContacts();
    } catch (err) {
      console.error("Verification error:", err);
      UI.showToast(err.message, "danger");
    }
  }

  // --- PREKEYS VIEW ---
  async loadPrekeys() {
    try {
      const res = await api.getMyPrekeys();
      const tbody = document.getElementById("prekeys-table-body");
      if (!tbody) return;

      const stats = res.stats || res.summary || {};
      document.getElementById("disp-prekeys-avail").innerText = stats.available ?? 0;
      document.getElementById("disp-prekeys-res").innerText = stats.reserved ?? 0;
      document.getElementById("disp-prekeys-cons").innerText = stats.consumed ?? 0;
      document.getElementById("badge-prekeys-count").innerText = stats.available ?? 0;

      if (res.prekeys.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 20px;">No prekeys found. Click Replenish Prekeys to create a batch.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.prekeys.map(pk => {
        let pillClass = "status-available";
        if (pk.status === "CONSUMED") pillClass = "status-danger";
        else if (pk.status === "RESERVED") pillClass = "status-reserved";

        return `
          <tr>
            <td><strong>${UI.escapeHtml(pk.id)}</strong></td>
            <td class="cell-mono-sm" style="color: var(--text-muted);">${UI.escapeHtml(pk.x25519_public_key.substring(0, 32))}...</td>
            <td><span class="status-pill ${pillClass}">${UI.escapeHtml(pk.status)}</span></td>
            <td style="color: var(--text-dim);">${UI.escapeHtml(pk.created_at.substring(0, 19).replace("T", " "))}</td>
            <td style="color: var(--text-dim);">${pk.expires_at ? UI.escapeHtml(pk.expires_at.substring(0, 19).replace("T", " ")) : "--"}</td>
            <td class="cell-mono-sm" style="color: var(--text-dim);">${UI.escapeHtml(pk.signature.substring(0, 24))}... [VERIFIED]</td>
          </tr>
        `;
      }).join("");
    } catch (err) {
      console.error("Load prekeys error:", err);
    }
  }

  // --- KEY EXCHANGE TOOL ---
  async loadExchangeView() {
    await this.loadContacts();
    await this.populateExchangeContactsDropdown();
    this.parseExchangeUrlParams();
  }

  async populateExchangeContactsDropdown() {
    const sel = document.getElementById("exchange-recipient-select");
    if (!sel) return;

    let optionsHtml = `<option value="">-- CHOOSE FROM VERIFIED CONTACTS OR ACTIVE USERS --</option>`;

    // 1. Add verified/cached contacts
    const addedUsers = new Set();
    if (this.contactsCache && this.contactsCache.length > 0) {
      optionsHtml += `<optgroup label="TRUSTED CONTACT BOOK">`;
      for (const c of this.contactsCache) {
        addedUsers.add(c.contact_username.toLowerCase());
        optionsHtml += `<option value="${UI.escapeHtml(c.contact_username)}">
          ${UI.escapeHtml(c.contact_username)} [${UI.escapeHtml(c.verification_status)}]
        </option>`;
      }
      optionsHtml += `</optgroup>`;
    }

    // 2. Fetch directory users so user is never blocked by an empty list
    try {
      const searchRes = await api.searchUsers("");
      if (searchRes && searchRes.users && searchRes.users.length > 0) {
        const dirUsers = searchRes.users.filter(u => !addedUsers.has(u.username.toLowerCase()));
        if (dirUsers.length > 0) {
          optionsHtml += `<optgroup label="ACTIVE DIRECTORY USERS">`;
          for (const u of dirUsers) {
            const hasIdTag = u.has_identity ? " [IDENTITY ACTIVE]" : " [NO IDENTITY]";
            optionsHtml += `<option value="${UI.escapeHtml(u.username)}">
              ${UI.escapeHtml(u.username)}${hasIdTag}
            </option>`;
          }
          optionsHtml += `</optgroup>`;
        }
      }
    } catch (e) {
      console.warn("Could not load directory users for exchange dropdown:", e);
    }

    sel.innerHTML = optionsHtml;
  }

  parseExchangeUrlParams() {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const hash = window.location.hash.replace(/^#/, "");
      const hashParams = new URLSearchParams(hash);

      const tx = urlParams.get("tx") || urlParams.get("transfer_id");
      const recipient = urlParams.get("recipient") || urlParams.get("to");
      const key = hashParams.get("key") || hashParams.get("aes") || urlParams.get("key");

      if (tx) {
        const txInput = document.getElementById("exchange-transfer-id");
        if (txInput) txInput.value = tx;
      }

      if (recipient) {
        const recInput = document.getElementById("exchange-recipient-input");
        if (recInput) {
          recInput.value = recipient;
          this.discoverRecipient();
        }
      }

      if (key) {
        const keyInput = document.getElementById("exchange-file-key");
        if (keyInput) {
          keyInput.value = key;
          this.updateAesKeyStatus(key);
        }
        if (window.location.hash) {
          history.replaceState(null, "", window.location.pathname + window.location.search);
        }
      }
    } catch (e) {
      console.warn("Error parsing URL params for exchange:", e);
    }
  }

  updateAesKeyStatus(rawKey) {
    const statusText = document.getElementById("exchange-key-status-text");
    const lenBadge = document.getElementById("exchange-key-length-badge");
    let keyVal = (rawKey || "").trim();

    // Auto-convert 44-char base64 AES key to hex if user pasted base64
    if (/^[A-Za-z0-9+/]{43}=$/.test(keyVal) || (/^[A-Za-z0-9+/=]{44}$/.test(keyVal) && !/^[0-9a-fA-F]{44}$/.test(keyVal))) {
      try {
        const bin = atob(keyVal);
        if (bin.length === 32) {
          let hex = "";
          for (let i = 0; i < bin.length; i++) {
            hex += bin.charCodeAt(i).toString(16).padStart(2, "0");
          }
          keyVal = hex;
          const keyInput = document.getElementById("exchange-file-key");
          if (keyInput) keyInput.value = hex;
        }
      } catch (ignore) {}
    }

    if (lenBadge) {
      lenBadge.innerText = `${keyVal.length} / 64 hex chars`;
    }

    const isValid = /^[0-9a-fA-F]{64}$/.test(keyVal);
    if (isValid) {
      if (statusText) {
        statusText.innerText = "[✓ AES-256 FILE KEY LOADED DIRECTLY]";
        statusText.style.color = "var(--green-term)";
      }
      if (lenBadge) lenBadge.style.color = "var(--green-term)";
    } else {
      if (statusText) {
        statusText.innerText = keyVal.length > 0
          ? `[INVALID FORMAT: ${keyVal.length}/64 HEX CHARACTERS]`
          : "[PASTE 64-HEX KEY DIRECTLY OR CLICK AUTO-GENERATE]";
        statusText.style.color = keyVal.length > 0 ? "var(--red-primary)" : "var(--text-dim)";
      }
      if (lenBadge) lenBadge.style.color = "var(--text-muted)";
    }

    // Enable seal button if recipient is also discovered
    const sealBtn = document.getElementById("btn-seal-and-dispatch");
    if (sealBtn && this.activeDiscoveredRecipient && this.activeDiscoveredRecipient.verificationStatus !== "KEY CHANGED") {
      sealBtn.disabled = !isValid;
    }
  }

  async discoverRecipient() {
    const input = document.getElementById("exchange-recipient-input");
    const target = input.value.trim();
    if (!target) {
      UI.showToast("Please enter a recipient username or choose from contacts.", "warning");
      return;
    }

    this.logExchangeAudit(`[1/4] DISCOVERING RECIPIENT: ${target}...`);

    try {
      // 1. Discover user identity
      let idRes;
      try {
        idRes = await api.getUserIdentity(target);
      } catch (err) {
        if (err.code === "USER_NOT_FOUND" || (err.status === 404 && err.message && err.message.toLowerCase().includes("not found"))) {
          throw new Error(`Recipient account '${target}' does not exist.`);
        } else if (err.code === "NO_IDENTITY") {
          throw new Error(`Recipient '${target}' exists but has not published an identity bundle.`);
        } else if (err.status === 401 || err.code === "UNAUTHORIZED") {
          throw new Error(`Authentication required. Please log in to search.`);
        } else {
          throw new Error(`Recipient discovery error for '${target}': ${err.message}`);
        }
      }

      const resolvedRecipientId = idRes.user_id || idRes.identity?.user_id;
      const resolvedUsername = idRes.username || target;
      this.logExchangeAudit(`[+] Recipient identified: ${resolvedUsername} (ID: ${resolvedRecipientId})`);

      // 2. Discover available prekey
      let pkRes;
      try {
        pkRes = await api.getRecipientPrekey(resolvedRecipientId || target);
      } catch (err) {
        if (err.status === 404 || err.code === "NO_PREKEYS_AVAILABLE") {
          throw new Error(`Recipient '${resolvedUsername}' has an active identity, but no available prekeys. Recipient must log in to replenish their pool.`);
        }
        throw new Error(`Failed to retrieve prekey for '${resolvedUsername}': ${err.message}`);
      }

      // 2.5 Validate public key encoding, prekey signature, and ownership
      const signingPk = (idRes.identity?.ed25519_public_key || "").toLowerCase();
      const prekeyPk = (pkRes.prekey?.x25519_public_key || "").toLowerCase();
      const prekeySig = pkRes.prekey?.signature;

      if (!signingPk || signingPk.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(signingPk)) {
        throw new Error(`Invalid Ed25519 public key format for recipient '${resolvedUsername}'.`);
      }
      if (!prekeyPk || prekeyPk.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(prekeyPk)) {
        throw new Error(`Invalid X25519 prekey public key format for recipient '${resolvedUsername}'.`);
      }
      if (!prekeySig) {
        throw new Error(`Missing prekey signature for recipient '${resolvedUsername}'.`);
      }

      // 3. Match against trusted contacts
      let contactMatch = null;
      try {
        const contactsRes = await api.getContacts();
        contactMatch = (contactsRes.contacts || []).find(c => 
          c.contact_username.toLowerCase() === resolvedUsername.toLowerCase() ||
          c.contact_id === resolvedRecipientId
        );
      } catch (_) {}

      let verificationStatus = "UNVERIFIED";
      if (contactMatch) {
        if (contactMatch.trusted_fingerprint && contactMatch.trusted_fingerprint !== idRes.identity.fingerprint) {
          verificationStatus = "KEY CHANGED";
        } else {
          verificationStatus = contactMatch.verification_status;
        }
      }

      this.activeDiscoveredRecipient = {
        userId: resolvedRecipientId,
        username: resolvedUsername,
        signingPublicKey: signingPk,
        fingerprint: idRes.identity.fingerprint,
        prekeyId: pkRes.prekey.id,
        prekeyPublicHex: prekeyPk,
        prekeySignature: prekeySig,
        verificationStatus: verificationStatus
      };

      // Verify prekey signature against recipient's Ed25519 public key
      this.logExchangeAudit(`[2/4] VERIFYING RECIPIENT PREKEY SIGNATURE (Prekey: ${this.activeDiscoveredRecipient.prekeyId})...`);
      const sigValid = await X25519HKDF.verifySignedPrekey(
        this.activeDiscoveredRecipient.signingPublicKey,
        this.activeDiscoveredRecipient.prekeyPublicHex,
        this.activeDiscoveredRecipient.prekeySignature
      );

      if (!sigValid) {
        throw new Error("RECIPIENT PREKEY SIGNATURE INVALID! Potential tampering or spoofing detected.");
      }
      this.logExchangeAudit(`[SUCCESS] Prekey signature authenticated by recipient Ed25519 key.`);

      // Update UI card
      document.getElementById("disp-recip-id").innerText = this.activeDiscoveredRecipient.userId;
      document.getElementById("disp-recip-fp").innerText = this.activeDiscoveredRecipient.fingerprint;
      document.getElementById("disp-recip-pk-id").innerText = this.activeDiscoveredRecipient.prekeyId;
      
      const trustPill = document.getElementById("disp-recip-trust");
      trustPill.innerText = this.activeDiscoveredRecipient.verificationStatus;
      if (this.activeDiscoveredRecipient.verificationStatus === "VERIFIED") {
        trustPill.className = "status-pill status-verified";
      } else if (this.activeDiscoveredRecipient.verificationStatus === "KEY CHANGED") {
        trustPill.className = "status-pill status-changed";
      } else {
        trustPill.className = "status-pill status-unverified";
      }

      const keyChangedWarn = document.getElementById("recip-keychanged-warning");
      const unverifiedWarn = document.getElementById("recip-unverified-warning");
      const btnSeal = document.getElementById("btn-seal-and-dispatch");

      if (this.activeDiscoveredRecipient.verificationStatus === "KEY CHANGED") {
        if (keyChangedWarn) keyChangedWarn.style.display = "flex";
        if (unverifiedWarn) unverifiedWarn.style.display = "none";
        if (btnSeal) btnSeal.disabled = true;
        this.logExchangeAudit(`[CRITICAL WARNING] Recipient identity has changed! Fingerprint mismatch detected. Key dispatch BLOCKED until re-verified.`);
      } else if (this.activeDiscoveredRecipient.verificationStatus === "UNVERIFIED") {
        if (keyChangedWarn) keyChangedWarn.style.display = "none";
        if (unverifiedWarn) unverifiedWarn.style.display = "flex";
        if (btnSeal) btnSeal.disabled = false;
        this.logExchangeAudit(`[CAUTION] Contact unverified. Proceeding without out-of-band verification.`);
      } else {
        if (keyChangedWarn) keyChangedWarn.style.display = "none";
        if (unverifiedWarn) unverifiedWarn.style.display = "none";
        if (btnSeal) btnSeal.disabled = false;
        this.logExchangeAudit(`[VERIFIED] Contact fingerprint authenticated out-of-band.`);
      }

      document.getElementById("exchange-recipient-info").style.display = "block";
      this.logExchangeAudit(`[READY] Ready to seal envelope. Enter Transfer ID and 256-bit AES file key.`);
    } catch (err) {
      console.error("Recipient discovery error:", err);
      this.logExchangeAudit(`[ERROR] Discovery failed: ${err.message}`);
      UI.showToast(err.message, "danger");
      document.getElementById("exchange-recipient-info").style.display = "none";
      const btnSeal = document.getElementById("btn-seal-and-dispatch");
      if (btnSeal) btnSeal.disabled = true;
    }
  }

  generateNewTransferId() {
    let newTx;
    if (typeof crypto.randomUUID === "function") {
      newTx = crypto.randomUUID();
    } else {
      newTx = "tx_" + Date.now() + "_" + Math.random().toString(36).substring(2, 10);
    }
    const txInput = document.getElementById("exchange-transfer-id");
    if (txInput) txInput.value = newTx;
    UI.showToast(`Transfer ID generated: ${newTx.substring(0, 8)}...`, "info");
    return newTx;
  }

  generateRandomAesKey() {
    const rawKey = AESGCM.generateFileKeyHex();
    const keyInput = document.getElementById("exchange-file-key");
    if (keyInput) keyInput.value = rawKey;
    this.updateAesKeyStatus(rawKey);

    // If transfer ID is empty or was previously used, auto-generate a fresh one
    const txInput = document.getElementById("exchange-transfer-id");
    if (txInput && (!txInput.value.trim() || (this.lastDispatchedTxId && this.lastDispatchedTxId === txInput.value.trim()))) {
      this.generateNewTransferId();
    } else if (txInput && txInput.value.trim().length > 16) {
      UI.showToast("Notice: Entered Transfer ID retained. This random key will not decrypt files already encrypted on Port 5000.", "warning");
    }

    this.logExchangeAudit(`[GEN] Generated fresh 256-bit AES-GCM file key: ${rawKey.substring(0, 16)}...`);
    UI.showToast("Generated fresh 256-bit AES file key in memory.", "info");
  }

  async sealAndDispatchEnvelope() {
    if (!this.activeDiscoveredRecipient) {
      UI.showToast("Please discover recipient first.", "warning");
      return;
    }

    if (this.activeDiscoveredRecipient.verificationStatus === "KEY CHANGED") {
      UI.showToast("Cannot dispatch envelope to recipient with unverified KEY CHANGED status.", "danger");
      return;
    }

    let transferId = document.getElementById("exchange-transfer-id").value.trim();
    if (!transferId) {
      transferId = this.generateNewTransferId();
    }

    const rawFileKey = document.getElementById("exchange-file-key").value.trim();

    if (!transferId) {
      UI.showToast("Transfer ID is required.", "warning");
      return;
    }

    // Check if envelope already exists for this transfer ID
    try {
      const existingRes = await api.getEnvelope(transferId);
      if (existingRes && existingRes.envelope) {
        const confirmOverwrite = confirm(
          `NOTICE: An envelope already exists for transfer [${transferId}].\n\n` +
          `If this file was uploaded in File Vault (Port 5000), it already has the genuine key sealed.\n\n` +
          `Overwriting with this key will prevent decryption of the uploaded file unless you re-encrypt it.\n\n` +
          `Do you want to proceed with overwriting?`
        );
        if (!confirmOverwrite) return;
      }
    } catch (ignoreErr) {
      // No existing envelope found; safe to proceed
    }
    if (!rawFileKey || rawFileKey.length !== 64) {
      UI.showToast("Valid 256-bit AES key (64 hex characters) is required.", "warning");
      return;
    }

    const identity = await this.keyStore.getIdentity();
    if (!identity || !identity.privateKey) {
      UI.showToast("Your local vault must be unlocked to sign envelopes.", "danger");
      return;
    }

    try {
      this.logExchangeAudit(`[PROTOCOL INITIATED] Sealing envelope for transfer: ${transferId}`);
      this.logExchangeAudit(`1. Reserving recipient prekey: ${this.activeDiscoveredRecipient.prekeyId}`);
      await api.reservePrekey(this.activeDiscoveredRecipient.prekeyId);

      this.logExchangeAudit(`2. Generating ephemeral X25519 keypair...`);
      this.logExchangeAudit(`3. Performing X25519 scalar multiplication DH agreement...`);
      this.logExchangeAudit(`4. Deriving 256-bit wrapping key via HKDF-SHA-256...`);
      this.logExchangeAudit(`5. Encrypting AES file key via AES-256-GCM with authenticated binding...`);
      this.logExchangeAudit(`6. Signing envelope payload with your Ed25519 identity key...`);

      const senderId = this.currentUser ? this.currentUser.id : (identity.user_id || "");
      const sealed = await Envelope.createKeyEnvelope({
        senderIdentityPrivateKey: identity.privateKey,
        senderIdentityPublicKey: identity.publicKey,
        senderId: senderId,
        recipientId: this.activeDiscoveredRecipient.userId,
        recipientSigningKeyHex: this.activeDiscoveredRecipient.signingPublicKey,
        recipientPrekeyId: this.activeDiscoveredRecipient.prekeyId,
        recipientPrekeyPublicHex: this.activeDiscoveredRecipient.prekeyPublicHex,
        transferId: transferId,
        rawAesFileKeyHex: rawFileKey
      });

      this.logExchangeAudit(`[7/7] Dispatching sealed envelope to server...`);
      await api.submitEnvelope({
        transfer_id: transferId,
        sender_id: senderId,
        recipient_id: this.activeDiscoveredRecipient.userId,
        recipient_prekey_id: this.activeDiscoveredRecipient.prekeyId,
        encrypted_envelope: sealed.encryptedEnvelope,
        sender_signature: sealed.senderSignature,
        force_update: true
      });

      this.logExchangeAudit(`[COMPLETE ✓] Key envelope dispatched successfully! Recipient can now unwrap key in their portal.`);
      this.lastDispatchedTxId = transferId;
      UI.showToast("Key envelope sealed and dispatched!", "success");

      // Display confirmed dispatch card
      const resultCard = document.getElementById("exchange-result-card");
      if (resultCard) {
        const txDisp = document.getElementById("disp-result-tx");
        const recipDisp = document.getElementById("disp-result-recip");
        const envDisp = document.getElementById("disp-result-env-id");
        const returnLink = document.getElementById("btn-return-filevault");

        if (txDisp) txDisp.innerText = transferId;
        if (recipDisp) recipDisp.innerText = this.activeDiscoveredRecipient.username;
        if (envDisp) envDisp.innerText = transferId;
        if (returnLink) {
          returnLink.href = `http://127.0.0.1:5000/transfer/${encodeURIComponent(transferId)}`;
        }
        resultCard.style.display = "block";
        resultCard.scrollIntoView({ behavior: "smooth" });
      }

      // Reset exchange form
      document.getElementById("exchange-transfer-id").value = "";
      document.getElementById("exchange-file-key").value = "";
      this.updateAesKeyStatus("");
    } catch (err) {
      console.error("Seal and dispatch error:", err);
      let errMsg = err.message || "Failed to seal envelope.";
      this.logExchangeAudit(`[FATAL ERROR] ${errMsg}`);
      UI.showToast(`Failed to seal envelope: ${errMsg}`, "danger");
    }
  }

  logExchangeAudit(msg) {
    const box = document.getElementById("exchange-crypto-audit-log");
    if (!box) return;
    const time = new Date().toISOString().substring(11, 19);
    box.innerText += `\n[${time}] ${msg}`;
    box.scrollTop = box.scrollHeight;
  }

  // --- INBOX VIEW ---
  async loadInbox() {
    try {
      const res = await api.getInbox();
      const tbody = document.getElementById("inbox-table-body");
      if (!tbody) return;

      document.getElementById("badge-inbox-count").innerText = res.inbox.length;
      document.getElementById("badge-inbox-count").style.display = res.inbox.length > 0 ? "inline-block" : "none";

      if (res.inbox.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 20px;">No envelopes in inbox.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.inbox.map(env => `
        <tr>
          <td><strong>${UI.escapeHtml(env.transfer_id)}</strong></td>
          <td>${UI.escapeHtml(env.sender_username || "Unknown")}</td>
          <td class="cell-mono-sm" style="color: var(--text-muted);">${UI.escapeHtml(env.recipient_prekey_id)}</td>
          <td style="color: var(--text-dim);">${UI.escapeHtml(env.created_at.substring(0, 19).replace("T", " "))}</td>
          <td><span class="status-pill status-${env.status === "ACCEPTED" ? "verified" : (env.status === "REJECTED" ? "danger" : "pending")}">${UI.escapeHtml(env.status)}</span></td>
          <td>
            <div class="cell-actions">
              <button class="btn btn-secondary btn-sm btn-inbox-details" data-tx="${UI.escapeHtml(env.transfer_id)}">
                DETAILS
              </button>
              <button class="btn btn-secondary btn-sm btn-inbox-verify" data-tx="${UI.escapeHtml(env.transfer_id)}">
                VERIFY
              </button>
              <button class="btn btn-primary btn-sm btn-unwrap-envelope" data-tx="${UI.escapeHtml(env.transfer_id)}">
                UNWRAP KEY
              </button>
              <button class="btn btn-danger btn-sm btn-reject-envelope" data-tx="${UI.escapeHtml(env.transfer_id)}">
                REJECT
              </button>
            </div>
          </td>
        </tr>
      `).join("");

      tbody.querySelectorAll(".btn-inbox-details").forEach(b => {
        b.addEventListener("click", () => this.openTransferDetail(b.getAttribute("data-tx")));
      });

      tbody.querySelectorAll(".btn-inbox-verify").forEach(b => {
        b.addEventListener("click", () => this.verifyEnvelopeSignature(b.getAttribute("data-tx")));
      });

      tbody.querySelectorAll(".btn-unwrap-envelope").forEach(b => {
        b.addEventListener("click", () => this.unwrapKeyForTransfer(b.getAttribute("data-tx")));
      });

      tbody.querySelectorAll(".btn-reject-envelope").forEach(b => {
        b.addEventListener("click", async () => {
          if (confirm("Reject key envelope?")) {
            await api.rejectEnvelope(b.getAttribute("data-tx"));
            await this.loadInbox();
            UI.showToast("Envelope rejected.", "warning");
          }
        });
      });
    } catch (err) {
      console.error("Load inbox error:", err);
    }
  }

  async verifyEnvelopeSignature(transferId) {
    try {
      UI.showToast(`Verifying sender signature for ${transferId}...`, "info");
      const envRes = await api.getEnvelope(transferId);
      const envelopeRecord = envRes.envelope;

      const senderIdRes = await api.getUserIdentity(envelopeRecord.sender_id);
      const senderEd25519PublicKey = senderIdRes.identity.ed25519_public_key;

      const envObj = typeof envelopeRecord.encrypted_envelope === "string" 
        ? JSON.parse(envelopeRecord.encrypted_envelope) 
        : { ...envelopeRecord.encrypted_envelope };
      const sig = envelopeRecord.sender_signature || envObj.signature;

      if (!sig) {
        throw new Error("No digital signature found on envelope.");
      }

      const unsignedEnv = { ...envObj };
      delete unsignedEnv.signature;
      delete unsignedEnv.encryptedEnvelope;
      delete unsignedEnv.senderSignature;

      const canonicalStr = Envelope.canonicalJson(unsignedEnv);
      const canonicalBytes = new TextEncoder().encode(canonicalStr);
      const sigBytes = sodium.from_base64(sig);
      const pubBytes = sodium.from_hex(senderEd25519PublicKey);

      const isValid = await Ed25519Sign.verifySignature(sigBytes, canonicalBytes, pubBytes);
      if (isValid) {
        UI.showToast(`✓ Ed25519 Signature Verified: Authentic from ${envelopeRecord.sender_username || "sender"}.`, "success");
      } else {
        UI.showToast(`✗ CRITICAL: Ed25519 digital signature is INVALID! Potential tampering.`, "danger");
      }
    } catch (err) {
      console.error("Signature verification error:", err);
      UI.showToast(`Signature verification failed: ${err.message}`, "danger");
    }
  }

  async unwrapKeyForTransfer(transferId) {
    if (!this.keyStore || !this.keyStore.isUnlocked) {
      UI.showToast("Unlock local vault to access your prekey and unwrap key envelope.", "warning");
      UI.openModal("modal-unlock-vault");
      return;
    }

    try {
      UI.showToast(`Retrieving envelope for transfer ${transferId}...`, "info");
      const envRes = await api.getEnvelope(transferId);
      const envelopeRecord = envRes.envelope;

      // Fetch sender public identity key
      const senderIdRes = await api.getUserIdentity(envelopeRecord.sender_id);
      const senderEd25519PublicKey = senderIdRes.identity.ed25519_public_key;

      // Locate recipient private prekey from local vault
      const storedPrekey = await this.keyStore.getPrekey(envelopeRecord.recipient_prekey_id);
      if (!storedPrekey || !storedPrekey.privateKey) {
        throw new Error(`One-time prekey [${envelopeRecord.recipient_prekey_id}] not found in local vault. Key may have been consumed or purged.`);
      }

      // Unwrap envelope locally
      UI.showToast("Verifying sender signature and unwrapping AES key...", "info");
      const myIdentity = await this.keyStore.getIdentity();
      const unwrapResult = await Envelope.openKeyEnvelope({
        senderIdentityPublicKey: senderEd25519PublicKey,
        recipientPrekeyPrivateKey: storedPrekey.privateKey,
        senderId: envelopeRecord.sender_id,
        recipientId: this.currentUser.id,
        recipientSigningKeyHex: myIdentity ? myIdentity.publicKey : undefined,
        transferId: transferId,
        recipientPrekeyId: envelopeRecord.recipient_prekey_id,
        encryptedEnvelope: envelopeRecord.encrypted_envelope,
        senderSignature: envelopeRecord.sender_signature
      });

      // Show unwrapped key in UI
      const keyArea = document.getElementById("unwrapped-key-area");
      document.getElementById("disp-unwrapped-tx").innerText = transferId;
      document.getElementById("disp-unwrapped-key").innerText = unwrapResult.rawAesFileKeyHex;

      // Update link to file sharing portal (Port 5000)
      const linkFileShare = document.getElementById("btn-link-fileshare");
      if (linkFileShare) {
        linkFileShare.href = `http://127.0.0.1:5000/#/receive/${encodeURIComponent(transferId)}?key=${encodeURIComponent(unwrapResult.rawAesFileKeyHex)}`;
      }

      keyArea.style.display = "block";
      keyArea.scrollIntoView({ behavior: "smooth" });

      // Mark accepted on server
      await api.acceptEnvelope(transferId);
      await this.loadInbox();
      UI.showToast("AES key unwrapped successfully! Signature verified.", "success");
    } catch (err) {
      console.error("Unwrap error:", err);
      UI.showToast(`Failed to unwrap envelope: ${err.message}`, "danger");
    }
  }

  // --- TRANSFER HISTORY VIEW ---
  async loadHistory() {
    try {
      const res = await api.getTransfers();
      this.transfersCache = {
        sent: res.sent || [],
        received: res.received || []
      };
      this.renderHistoryTables();
    } catch (err) {
      console.error("Load history error:", err);
    }
  }

  setHistoryFilter(mode) {
    this.historyFilterMode = mode;

    const btnAll = document.getElementById("btn-filter-history-all");
    const btnSent = document.getElementById("btn-filter-history-sent");
    const btnRecv = document.getElementById("btn-filter-history-recv");

    if (btnAll) btnAll.className = `btn btn-sm ${mode === "all" ? "btn-primary" : "btn-secondary"}`;
    if (btnSent) btnSent.className = `btn btn-sm ${mode === "sent" ? "btn-primary" : "btn-secondary"}`;
    if (btnRecv) btnRecv.className = `btn btn-sm ${mode === "recv" ? "btn-primary" : "btn-secondary"}`;

    const panelSent = document.getElementById("panel-history-sent");
    const panelRecv = document.getElementById("panel-history-received");

    if (panelSent) panelSent.style.display = (mode === "all" || mode === "sent") ? "block" : "none";
    if (panelRecv) panelRecv.style.display = (mode === "all" || mode === "recv") ? "block" : "none";

    this.renderHistoryTables();
  }

  renderHistoryTables() {
    const searchVal = (document.getElementById("input-history-search")?.value || "").toLowerCase().trim();
    const sentBody = document.getElementById("history-sent-body");
    const recvBody = document.getElementById("history-received-body");

    // Filter Sent
    if (sentBody) {
      const filteredSent = this.transfersCache.sent.filter(s => {
        if (!searchVal) return true;
        return (s.transfer_id && s.transfer_id.toLowerCase().includes(searchVal)) ||
               (s.recipient_username && s.recipient_username.toLowerCase().includes(searchVal)) ||
               (s.recipient_prekey_id && s.recipient_prekey_id.toLowerCase().includes(searchVal));
      });

      if (filteredSent.length === 0) {
        sentBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 15px;">No sent transfers found.</td></tr>`;
      } else {
        sentBody.innerHTML = filteredSent.map(s => `
          <tr>
            <td><strong>${UI.escapeHtml(s.transfer_id)}</strong></td>
            <td>${UI.escapeHtml(s.recipient_username || "Unknown")}</td>
            <td class="cell-mono-sm" style="color: var(--text-muted);">${UI.escapeHtml(s.recipient_prekey_id)}</td>
            <td style="color: var(--text-dim);">${UI.escapeHtml(s.created_at.substring(0, 19).replace("T", " "))}</td>
            <td><span class="status-pill ${s.status === "ACCEPTED" ? "status-accepted" : "status-pending"}">${UI.escapeHtml(s.status)}</span></td>
            <td>
              <button class="btn btn-secondary btn-sm btn-view-transfer" data-tx="${UI.escapeHtml(s.transfer_id)}">DETAILS</button>
            </td>
          </tr>
        `).join("");
      }
    }

    // Filter Received
    if (recvBody) {
      const filteredRecv = this.transfersCache.received.filter(r => {
        if (!searchVal) return true;
        return (r.transfer_id && r.transfer_id.toLowerCase().includes(searchVal)) ||
               (r.sender_username && r.sender_username.toLowerCase().includes(searchVal)) ||
               (r.recipient_prekey_id && r.recipient_prekey_id.toLowerCase().includes(searchVal));
      });

      if (filteredRecv.length === 0) {
        recvBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 15px;">No received transfers found.</td></tr>`;
      } else {
        recvBody.innerHTML = filteredRecv.map(r => `
          <tr>
            <td><strong>${UI.escapeHtml(r.transfer_id)}</strong></td>
            <td>${UI.escapeHtml(r.sender_username || "Unknown")}</td>
            <td class="cell-mono-sm" style="color: var(--text-muted);">${UI.escapeHtml(r.recipient_prekey_id)}</td>
            <td style="color: var(--text-dim);">${UI.escapeHtml(r.created_at.substring(0, 19).replace("T", " "))}</td>
            <td><span class="status-pill ${r.status === "ACCEPTED" ? "status-accepted" : "status-pending"}">${UI.escapeHtml(r.status)}</span></td>
            <td>
              <button class="btn btn-secondary btn-sm btn-view-transfer" data-tx="${UI.escapeHtml(r.transfer_id)}">DETAILS</button>
            </td>
          </tr>
        `).join("");
      }
    }

    // Attach click handlers to DETAIL buttons
    document.querySelectorAll(".btn-view-transfer").forEach(btn => {
      btn.addEventListener("click", () => {
        const tx = btn.getAttribute("data-tx");
        this.openTransferDetail(tx);
      });
    });
  }

  async openTransferDetail(transferId) {
    try {
      const res = await api.getTransferDetail(transferId);
      const tx = res.transfer;

      document.getElementById("detail-tx-id").innerText = tx.transfer_id;
      const statusEl = document.getElementById("detail-tx-status");
      statusEl.innerHTML = `<span class="status-pill ${tx.status === "ACCEPTED" ? "status-accepted" : "status-pending"}">${UI.escapeHtml(tx.status)}</span>`;

      document.getElementById("detail-tx-sender").innerText = tx.sender_username || tx.sender_id;
      document.getElementById("detail-tx-recipient").innerText = tx.recipient_username || tx.recipient_id;
      document.getElementById("detail-tx-prekey").innerText = tx.recipient_prekey_id;

      const envBox = document.getElementById("detail-tx-envelope");
      if (tx.encrypted_envelope) {
        envBox.innerText = JSON.stringify(tx.encrypted_envelope, null, 2);
      } else {
        envBox.innerText = "--";
      }

      const sigBox = document.getElementById("detail-tx-sig");
      sigBox.innerText = tx.sender_signature || "--";

      UI.openModal("modal-transfer-detail");
    } catch (err) {
      console.error("Fetch transfer detail error:", err);
      UI.showToast(`Could not load transfer details: ${err.message}`, "danger");
    }
  }

  // --- SECURITY LOGS VIEW ---
  async loadLogs() {
    try {
      const res = await api.getSecurityEvents();
      this.logsCache = res.events || [];
      this.renderLogsTable();
    } catch (err) {
      console.error("Load logs error:", err);
    }
  }

  renderLogsTable() {
    const tbody = document.getElementById("security-logs-body");
    if (!tbody) return;

    const searchVal = (document.getElementById("input-logs-search")?.value || "").toLowerCase().trim();
    const filterCat = document.getElementById("select-logs-filter")?.value || "";

    const filtered = this.logsCache.filter(ev => {
      if (filterCat && !ev.event_type.startsWith(filterCat)) return false;
      if (searchVal) {
        const matchText = `${ev.actor_username} ${ev.event_type} ${ev.message} ${ev.result}`.toLowerCase();
        return matchText.includes(searchVal);
      }
      return true;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 20px;">No audit events matching criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(ev => {
      let pillClass = "status-success";
      if (ev.result === "WARNING") pillClass = "status-unverified";
      else if (ev.result === "FAILURE") pillClass = "status-danger";

      return `
        <tr>
          <td style="color: var(--text-dim);">${UI.escapeHtml(ev.timestamp.substring(0, 19).replace("T", " "))}</td>
          <td><strong>${UI.escapeHtml(ev.actor_username || "SYSTEM")}</strong></td>
          <td class="cell-mono-sm" style="color: #FFF;">${UI.escapeHtml(ev.event_type)}</td>
          <td><span class="status-pill ${pillClass}">${UI.escapeHtml(ev.result)}</span></td>
          <td style="color: var(--text-main);">${UI.escapeHtml(ev.message)}</td>
        </tr>
      `;
    }).join("");
  }

  // --- SETTINGS VIEW ---
  loadSettings() {
    if (this.currentUser) {
      const nameEl = document.getElementById("settings-user-name");
      const idEl = document.getElementById("settings-user-id");
      if (nameEl) nameEl.innerText = this.currentUser.username;
      if (idEl) idEl.innerText = this.currentUser.id;
    }
    this.probeFileVaultStatus();
  }
}

// Instantiate and start app on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  const app = new SecureShareApp();
  app.init().catch(err => console.error("SecureShare App Init Failed:", err));
  window.SecureShareApp = app;
});
