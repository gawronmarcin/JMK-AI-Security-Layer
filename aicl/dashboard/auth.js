// AICL dashboard — admin key holder.
// The key lives only in this module's closure (page memory). It is never written to
// localStorage/sessionStorage/cookies, never placed in a URL, never logged and never
// included in error messages. Reloading the page forgets it by design.

let adminKey = null;
let openMode = false; // explicit "backend runs with AICL_ADMIN_OPEN=1" choice by the operator

export const auth = {
  setKey(key) {
    const k = typeof key === 'string' ? key.trim() : '';
    adminKey = k || null;
    openMode = false;
  },
  /** Operator explicitly chose to try without a key (local open mode). Never assumed automatically. */
  useOpenMode() {
    adminKey = null;
    openMode = true;
  },
  clear() {
    adminKey = null;
    openMode = false;
  },
  isOpenMode() {
    return openMode;
  },
  hasCredentials() {
    return adminKey !== null || openMode;
  },
  /** Headers for an admin request. Returns a fresh object each call. */
  headers() {
    return adminKey ? { Authorization: `Bearer ${adminKey}` } : {};
  },
  /** Removes any occurrence of the key from a string (defence in depth for error texts). */
  redact(text) {
    if (!adminKey || typeof text !== 'string') return text;
    return text.split(adminKey).join('[admin-key]');
  },
};
