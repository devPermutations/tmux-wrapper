'use strict';
// Run with: node --test tests/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const ScrollEngine = require('../static/scroll-engine.js');

const PX = 50; // px per step in these tests

function engine() {
    return ScrollEngine.create({ pxPerStep: PX, maxStepsPerFrame: 4 });
}

// Run frames every 16ms from t until the engine goes idle (or a safety cap);
// returns the total steps emitted and the time it went idle.
function drain(e, t) {
    let total = 0;
    for (let i = 0; i < 2000 && e.isActive(); i++) {
        t += 16;
        total += e.frame(t);
    }
    return { total, t };
}

// Drag the finger from y0 to y1 over `ms`, in 16ms moves, framing as we go.
function drag(e, y0, y1, ms, t0 = 0) {
    e.touchStart(100, y0, t0);
    let total = 0;
    const n = Math.max(1, Math.round(ms / 16));
    for (let i = 1; i <= n; i++) {
        const t = t0 + i * 16;
        e.touchMove(100, y0 + ((y1 - y0) * i) / n, t);
        total += e.frame(t);
    }
    return { total, t: t0 + n * 16 };
}

test('a small wobble is a tap, not a scroll', () => {
    const e = engine();
    e.touchStart(100, 300, 0);
    assert.strictEqual(e.touchMove(100, 305, 16), false);
    assert.strictEqual(e.frame(16), 0);
});

test('a mostly horizontal swipe is not claimed as a scroll', () => {
    const e = engine();
    e.touchStart(100, 300, 0);
    assert.strictEqual(e.touchMove(160, 280, 16), false);
});

test('finger moving up scrolls forward (positive steps), one per pxPerStep', () => {
    const e = engine();
    // Slow drag (no momentum): 10 steps' worth over 1.6s, then pause before lifting.
    const d = drag(e, 800, 800 - 10 * PX, 1600);
    e.touchEnd(d.t + 200);
    const rest = drain(e, d.t + 200);
    // The first 10px are the tap threshold; everything after counts.
    assert.ok(d.total + rest.total >= 9 && d.total + rest.total <= 10, `got ${d.total + rest.total}`);
});

test('finger moving down scrolls back into history (negative steps)', () => {
    const e = engine();
    const d = drag(e, 200, 200 + 6 * PX, 1000);
    e.touchEnd(d.t + 200);
    assert.ok(d.total <= -5, `got ${d.total}`);
});

test('steps per frame are capped and the remainder arrives in later frames', () => {
    const e = engine();
    e.touchStart(100, 1000, 0);
    e.touchMove(100, 1000 - 12, 8); // cross the tap threshold
    e.touchMove(100, 1000 - 12 - 10 * PX, 16); // one big jump: 10 steps' worth
    const first = e.frame(16);
    assert.strictEqual(first, 4);
    e.touchEnd(500); // long pause before lift: no momentum
    const rest = drain(e, 500);
    assert.strictEqual(first + rest.total, 10);
});

test('a flick keeps scrolling after the finger lifts, then stops', () => {
    const e = engine();
    // Fast flick: 300px in 100ms (3 px/ms), lifted immediately.
    const d = drag(e, 700, 400, 100);
    e.touchEnd(d.t);
    assert.ok(e.isActive(), 'momentum should be active after a flick');
    const rest = drain(e, d.t);
    assert.ok(rest.total > 0, `momentum should keep scrolling forward, got ${rest.total}`);
    assert.ok(!e.isActive(), 'momentum should come to rest');
    assert.ok(rest.t - d.t < 5000, `momentum ran ${rest.t - d.t}ms`);
});

test('pausing before lifting the finger cancels momentum', () => {
    const e = engine();
    const d = drag(e, 700, 400, 100);
    e.touchEnd(d.t + 150);
    assert.strictEqual(e.isActive(), false);
});

test('touching the screen stops a running momentum scroll', () => {
    const e = engine();
    const d = drag(e, 700, 400, 100);
    e.touchEnd(d.t);
    e.frame(d.t + 16);
    e.touchStart(100, 500, d.t + 32);
    assert.strictEqual(e.frame(d.t + 48), 0);
    assert.strictEqual(e.isActive(), false);
});
