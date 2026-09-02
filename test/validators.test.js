const test = require('node:test')
const assert = require('node:assert/strict')
const { isSafeFilename, isValidKeyId, redact_secrets } = require('../lib/validators')

test('isSafeFilename accepts normal asset names', () => {
    assert.equal(isSafeFilename('myapp-1.2.3.tar.gz'), true)
    assert.equal(isSafeFilename('myapp-1.2.3.zip'), true)
})

test('isSafeFilename rejects path traversal', () => {
    assert.equal(isSafeFilename('.'), false)
    assert.equal(isSafeFilename('..'), false)
    assert.equal(isSafeFilename('../../etc/passwd'), false)
})

test('isSafeFilename rejects leading-dash flag injection', () => {
    assert.equal(isSafeFilename('--homedir=/tmp/evil'), false)
    assert.equal(isSafeFilename('-oevil'), false)
})

test('isSafeFilename rejects reserved device names', () => {
    assert.equal(isSafeFilename('CON'), false)
    assert.equal(isSafeFilename('con.txt'), false)
    assert.equal(isSafeFilename('NUL'), false)
    assert.equal(isSafeFilename('LPT1'), false)
})

test('isSafeFilename rejects empty, non-string, and overlong names', () => {
    assert.equal(isSafeFilename(''), false)
    assert.equal(isSafeFilename(undefined), false)
    assert.equal(isSafeFilename('a'.repeat(256)), false)
    assert.equal(isSafeFilename('a'.repeat(255)), true)
})

test('isValidKeyId accepts hex fingerprints with optional 0x prefix', () => {
    assert.equal(isValidKeyId('ABCDEF0123456789'), true)
    assert.equal(isValidKeyId('0xABCDEF0123456789'), true)
})

test('isValidKeyId rejects non-hex input and shell metacharacters', () => {
    assert.equal(isValidKeyId('key$(rm -rf /)'), false)
    assert.equal(isValidKeyId('; rm -rf /'), false)
    assert.equal(isValidKeyId(''), false)
})

test('redact_secrets masks a known secret in a message', () => {
    const secret = 'sup3r-secret-pass'
    const message = `Command failed: gpg --batch --detach-sig file.tar.gz (secret was ${secret})`
    const redacted = redact_secrets(message, secret)
    assert.match(redacted, /\*\*\*REDACTED\*\*\*/)
    assert.equal(redacted.includes(secret), false)
})

test('redact_secrets is a no-op without a secret', () => {
    assert.equal(redact_secrets('plain message', ''), 'plain message')
    assert.equal(redact_secrets('plain message', undefined), 'plain message')
})
