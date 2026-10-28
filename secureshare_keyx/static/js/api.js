/**
 * SecureShare // KEY EXCHANGE - API Client
 * Robust client wrapper managing CSRF tokens, credentials, and error handling.
 */

class ApiClient {
  constructor() {
    this.csrfToken = null;
    this.baseUrl = "/api";
    this.userId = null;
  }

  setUserId(id) {
    this.userId = id || null;
  }

  async fetchCsrf() {
    try {
      const res = await fetch(`${this.baseUrl}/auth/csrf`, { credentials: "same-origin" });
      if (res.ok) {
        const data = await res.json();
        this.csrfToken = data.csrf_token;
        return this.csrfToken;
      }
    } catch (e) {
      console.warn("Could not fetch CSRF token:", e);
    }
    return null;
  }

  async request(endpoint, options = {}) {
    const url = endpoint.startsWith("http") ? endpoint : `${this.baseUrl}${endpoint}`;
    const headers = options.headers || {};

    if (!headers["Content-Type"] && !(options.body instanceof FormData) && options.body) {
      headers["Content-Type"] = "application/json";
    }

    const method = (options.method || "GET").toUpperCase();
    if (this.userId && !headers["X-User-ID"]) {
      headers["X-User-ID"] = this.userId;
    }

    if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
      if (!this.csrfToken) {
        await this.fetchCsrf();
      }
      if (this.csrfToken) {
        headers["X-CSRF-Token"] = this.csrfToken;
      }
    }

    const config = {
      ...options,
      headers,
      credentials: options.credentials || "same-origin"
    };

    let response;
    try {
      response = await fetch(url, config);
    } catch (err) {
      throw new Error(`NETWORK_UNREACHABLE: ${err.message}`);
    }

    // Refresh CSRF token if returned in body
    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (contentType.includes("application/json")) {
      data = await response.json();
      if (data && data.csrf_token) {
        this.csrfToken = data.csrf_token;
      }
    } else {
      data = await response.text();
    }

    if (!response.ok) {
      // If CSRF error and haven't retried yet, refresh CSRF and retry once
      if (response.status === 403 && data && String(data.error || "").toLowerCase().includes("csrf") && !options._csrfRetry) {
        await this.fetchCsrf();
        return this.request(endpoint, { ...options, _csrfRetry: true });
      }

      const errorMsg = (data && data.error) ? data.error : `HTTP ${response.status}: ${response.statusText}`;
      const err = new Error(errorMsg);
      err.status = response.status;
      err.code = (data && data.code) ? data.code : "HTTP_ERROR";
      err.data = data;
      throw err;
    }

    return data;
  }

  // --- AUTHENTICATION ---
  async getMe() {
    return this.request("/auth/me");
  }

  async login(identifier, password) {
    const data = await this.request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ identifier, password })
    });
    if (data.csrf_token) this.csrfToken = data.csrf_token;
    return data;
  }

  async register(username, email, password) {
    const data = await this.request("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password })
    });
    if (data.csrf_token) this.csrfToken = data.csrf_token;
    return data;
  }

  async logout() {
    const data = await this.request("/auth/logout", { method: "POST" });
    this.csrfToken = null;
    return data;
  }

  // --- IDENTITY ---
  async publishIdentity(ed25519PublicKey, fingerprint) {
    return this.request("/identities", {
      method: "POST",
      body: JSON.stringify({
        ed25519_public_key: ed25519PublicKey,
        fingerprint
      })
    });
  }

  async getMyIdentity() {
    return this.request("/identities/me");
  }

  async getUserIdentity(target) {
    return this.request(`/identities/${encodeURIComponent(target)}`);
  }

  async searchUsers(query) {
    return this.request(`/users/search?q=${encodeURIComponent(query)}`);
  }

  // --- CONTACTS ---
  async getContacts(ownerId) {
    const uid = ownerId || this.userId;
    const query = uid ? `?owner_id=${encodeURIComponent(uid)}` : "";
    return this.request(`/contacts${query}`);
  }

  async addContact(username, ownerId) {
    return this.request("/contacts", {
      method: "POST",
      body: JSON.stringify({
        username,
        owner_id: ownerId || this.userId
      })
    });
  }

  async verifyContact(contactId, fingerprint, ownerId) {
    return this.request(`/contacts/${contactId}/verify`, {
      method: "POST",
      body: JSON.stringify({
        fingerprint,
        owner_id: ownerId || this.userId
      })
    });
  }

  async deleteContact(contactId) {
    return this.request(`/contacts/${contactId}`, { method: "DELETE" });
  }

  // --- PREKEYS ---
  async publishPrekey(prekeyData) {
    return this.request("/prekeys", {
      method: "POST",
      body: JSON.stringify(prekeyData)
    });
  }

  async publishPrekeysBatch(prekeysList) {
    return this.request("/prekeys", {
      method: "POST",
      body: JSON.stringify({ prekeys: prekeysList })
    });
  }

  async getMyPrekeys() {
    return this.request("/prekeys/me");
  }

  async getRecipientPrekey(target) {
    return this.request(`/prekeys/${encodeURIComponent(target)}`);
  }

  async reservePrekey(prekeyId) {
    return this.request(`/prekeys/${prekeyId}/reserve`, { method: "POST" });
  }

  // --- ENVELOPES ---
  async submitEnvelope(payload) {
    return this.request("/envelopes", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  }

  async getInbox() {
    return this.request("/envelopes/inbox");
  }

  async getEnvelope(transferId) {
    return this.request(`/envelopes/${encodeURIComponent(transferId)}`);
  }

  async acceptEnvelope(transferId) {
    return this.request(`/envelopes/${encodeURIComponent(transferId)}/accept`, { method: "POST" });
  }

  async rejectEnvelope(transferId) {
    return this.request(`/envelopes/${encodeURIComponent(transferId)}/reject`, { method: "POST" });
  }

  // --- TRANSFERS ---
  async getTransfers() {
    return this.request("/transfers");
  }

  async getTransferDetail(transferId) {
    return this.request(`/transfers/${encodeURIComponent(transferId)}`);
  }

  // --- SECURITY EVENTS ---
  async getSecurityEvents() {
    return this.request("/security-events");
  }

  // --- HEALTH & TELEMETRY ---
  async getHealth() {
    return this.request("/health");
  }

  async getDashboardStats() {
    return this.request("/dashboard/stats");
  }

  async probeFileVault(url = "http://127.0.0.1:5000") {
    // 1. Try server-side probe on Port 5001 (bypasses browser CORS restrictions completely)
    try {
      const probeRes = await fetch("/api/probe/filevault", { credentials: "same-origin" });
      if (probeRes.ok) {
        const data = await probeRes.json();
        return Boolean(data && data.online);
      }
    } catch (_) {}

    // 2. Direct browser fallback using mode: 'no-cors'
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    try {
      await fetch(`${url}/api/auth/csrf`, {
        method: "GET",
        mode: "no-cors",
        signal: controller.signal,
        credentials: "omit"
      });
      clearTimeout(timeoutId);
      return true;
    } catch (_) {
      clearTimeout(timeoutId);
      return false;
    }
  }
}

export const api = new ApiClient();

