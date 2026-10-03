'use strict';
// Run with: node --test tests/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const { closeAction } = require('../static/close-action.js');

// Sent by the helper while its auth keys load after a restart (src/helper.rs).
const KEYS_UNAVAILABLE = 'auth keys unavailable — try again shortly';

test('an expired Access session reauthenticates', () => {
    assert.strictEqual(closeAction(4001, 'session expired'), 'reauthenticate');
});

test('keys still loading after a restart shows the reason and reconnects', () => {
    assert.strictEqual(closeAction(4004, KEYS_UNAVAILABLE), 'retry');
});

test('other refusals go to the session picker', () => {
    for (const reason of [
        'session limit reached — kill an old session first',
        "tmux server isn't running — start tmux-server.service",
        'could not start terminal',
        '',
        KEYS_UNAVAILABLE + ' ',
    ]) {
        assert.strictEqual(closeAction(4004, reason), 'picker', JSON.stringify(reason));
    }
});

test('ordinary closes reconnect', () => {
    assert.strictEqual(closeAction(1006, ''), 'reconnect');
    assert.strictEqual(closeAction(1000, ''), 'reconnect');
});
