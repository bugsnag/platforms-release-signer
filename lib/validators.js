// Pure, dependency-free validation/sanitization helpers used by index.js and covered by tests.

const RESERVED_FILENAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i

function isSafeFilename(name) {
    // allow only simple filenames (no path separators/traversal, no leading '-' to avoid
    // being parsed as a flag, no reserved device names, and a reasonable length limit)
    if (typeof name !== 'string' || name.length === 0 || name.length > 255) {
        return false
    }
    if (name === '.' || name === '..' || name.startsWith('-') || RESERVED_FILENAMES.test(name)) {
        return false
    }
    return /^[A-Za-z0-9._-]+$/.test(name)
}

function isValidKeyId(id) {
    // simple allowlist: hex fingerprint or short key id, optional 0x prefix
    return typeof id === 'string' && /^(0x)?[0-9A-Fa-f]+$/.test(id)
}

function redact_secrets(message, secret) {
    // defense-in-depth: strip any known secret that might end up in an argv-derived error message
    if (typeof message !== 'string' || !secret) {
        return message
    }
    return message.split(secret).join('***REDACTED***')
}

module.exports = { isSafeFilename, isValidKeyId, redact_secrets }
