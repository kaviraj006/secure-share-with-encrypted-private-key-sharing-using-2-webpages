/**
 * SecureShare - API Client with CSRF protection and XHR progress tracking
 */

let currentCsrfToken = "";

export function setCsrfToken(token) {
    currentCsrfToken = token;
}

export function getCsrfToken() {
    return currentCsrfToken;
}

async function request(url, options = {}) {
    const defaultHeaders = {
        "Accept": "application/json"
    };
    
    if (currentCsrfToken && options.method && options.method !== "GET") {
        defaultHeaders["X-CSRF-Token"] = currentCsrfToken;
    }
    
    if (options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
        defaultHeaders["Content-Type"] = "application/json";
        options.body = JSON.stringify(options.body);
    }
    
    options.headers = { ...defaultHeaders, ...options.headers };
    options.credentials = "same-origin";
    
    const response = await fetch(url, options);
    
    // Check if new CSRF token returned in json
    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (contentType.includes("application/json")) {
        data = await response.json();
        if (data && data.csrf_token) {
            setCsrfToken(data.csrf_token);
        }
    }
    
    if (!response.ok) {
        const errorMsg = data?.error || `HTTP request failed (${response.status})`;
        const error = new Error(errorMsg);
        error.status = response.status;
        error.code = data?.code;
        throw error;
    }
    
    return data;
}

export const api = {
    async initCsrf() {
        const res = await request("/api/auth/csrf");
        if (res.csrf_token) {
            setCsrfToken(res.csrf_token);
        }
        return res.csrf_token;
    },

    async getCurrentUser() {
        return await request("/api/auth/me");
    },

    async register(username, email, password) {
        return await request("/api/auth/register", {
            method: "POST",
            body: { username, email, password }
        });
    },

    async login(identifier, password) {
        return await request("/api/auth/login", {
            method: "POST",
            body: { identifier, password }
        });
    },

    async logout() {
        return await request("/api/auth/logout", {
            method: "POST"
        });
    },

    async searchUsers(query) {
        return await request(`/api/users/search?q=${encodeURIComponent(query)}`);
    },

    async getRecipientIdentity(target) {
        return await request(`/api/key-exchange/identities/${encodeURIComponent(target)}`);
    },

    async publishIdentity({ signing_public_key, x25519_prekey, fingerprint, prekey_id }) {
        return await request("/api/key-exchange/identities", {
            method: "POST",
            body: { signing_public_key, x25519_prekey, fingerprint, prekey_id }
        });
    },

    uploadCiphertext(ciphertextBlob, nonce, algorithm = "AES-256-GCM", onProgress = null) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", "/api/files/upload", true);
            
            if (currentCsrfToken) {
                xhr.setRequestHeader("X-CSRF-Token", currentCsrfToken);
            }
            
            if (onProgress && xhr.upload) {
                xhr.upload.onprogress = (e) => {
                    if (e.lengthComputable) {
                        const percent = Math.round((e.loaded / e.total) * 100);
                        onProgress(percent, e.loaded, e.total);
                    }
                };
            }
            
            xhr.onload = () => {
                try {
                    const data = JSON.parse(xhr.responseText);
                    if (xhr.status >= 200 && xhr.status < 300) {
                        resolve(data);
                    } else {
                        const err = new Error(data.error || "File upload failed.");
                        err.status = xhr.status;
                        reject(err);
                    }
                } catch (e) {
                    reject(new Error("Invalid response from server."));
                }
            };
            
            xhr.onerror = () => reject(new Error("Network connection error during upload."));
            
            const formData = new FormData();
            formData.append("file", ciphertextBlob, "payload.enc");
            formData.append("nonce", nonce);
            formData.append("algorithm", algorithm);
            formData.append("protocol_version", "1");
            
            xhr.send(formData);
        });
    },

    async submitEnvelope(transferId, recipientId, envelope, senderId = "", recipientUsername = "") {
        const body = { transfer_id: transferId, recipient_id: recipientId, envelope };
        if (senderId) body.sender_id = senderId;
        if (recipientUsername) body.recipient_username = recipientUsername;
        return await request("/api/key-exchange/envelopes", {
            method: "POST",
            body
        });
    },

    async createTransfer(recipient, fileId, envelopeId, expiresInHours = 24) {
        return await request("/api/transfers", {
            method: "POST",
            body: { recipient, file_id: fileId, envelope_id: envelopeId, expires_in_hours: expiresInHours }
        });
    },

    async attachEnvelope(transferId, envelopeId) {
        return await request(`/api/transfers/${encodeURIComponent(transferId)}`, {
            method: "PATCH",
            body: { envelope_id: envelopeId }
        });
    },

    async getTransfer(transferId) {
        return await request(`/api/transfers/${encodeURIComponent(transferId)}`);
    },

    async getKeyEnvelope(transferId) {
        return await request(`/api/key-exchange/envelopes/${encodeURIComponent(transferId)}`);
    },

    downloadCiphertext(transferId, onProgress = null) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open("GET", `/api/transfers/${encodeURIComponent(transferId)}/download`, true);
            xhr.responseType = "arraybuffer";
            
            if (onProgress) {
                xhr.onprogress = (e) => {
                    if (e.lengthComputable) {
                        const percent = Math.round((e.loaded / e.total) * 100);
                        onProgress(percent, e.loaded, e.total);
                    }
                };
            }
            
            xhr.onload = () => {
                if (xhr.status === 200) {
                    const nonce = xhr.getResponseHeader("X-Encryption-Nonce");
                    const algorithm = xhr.getResponseHeader("X-Encryption-Algorithm") || "AES-256-GCM";
                    const protocolVersion = xhr.getResponseHeader("X-Protocol-Version") || "1";
                    
                    resolve({
                        ciphertext: new Uint8Array(xhr.response),
                        nonce,
                        algorithm,
                        protocolVersion
                    });
                } else {
                    let errMsg = `Download failed with HTTP ${xhr.status}`;
                    if (xhr.status === 410) errMsg = "This transfer has expired and is no longer available.";
                    if (xhr.status === 403) errMsg = "Unauthorized: You are not the intended recipient of this transfer.";
                    reject(new Error(errMsg));
                }
            };
            
            xhr.onerror = () => reject(new Error("Network connection error during download."));
            xhr.send();
        });
    },

    async deleteTransfer(transferId) {
        return await request(`/api/transfers/${encodeURIComponent(transferId)}`, {
            method: "DELETE"
        });
    },

    async getTransferHistory() {
        return await request("/api/transfers/history");
    },

    async cleanupExpired() {
        return await request("/api/transfers/cleanup-expired", {
            method: "POST"
        });
    },

    async getKeyExchangeStatus() {
        return await request("/api/key-exchange/status");
    }
};
