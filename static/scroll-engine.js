// Touch-to-scroll engine for the phone client.
//
// Turns a finger drag into discrete scroll steps (one step = one mouse-wheel
// tick sent to tmux / the app in the pane), paced per animation frame, with
// iOS-style momentum after a flick. Pure logic — no DOM — so it can be unit
// tested under node; terminal.js feeds it touch samples and frame times and
// turns the returned steps into wheel events.
//
// Sign convention matches WheelEvent.deltaY: positive = finger moving up =
// scroll towards newer output; negative = back into history.
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.ScrollEngine = factory();
    }
})(this, function () {
    'use strict';

    var DEFAULTS = {
        pxPerStep: 50,          // finger travel per wheel tick
        maxStepsPerFrame: 4,    // pacing: avoid bursts that trip app wheel acceleration
        tapThreshold: 10,       // px of vertical travel before a touch becomes a scroll
        velocityWindow: 100,    // ms of recent samples used to measure flick speed
        liftPause: 50,          // ms without movement before lift that cancels momentum
        minFlickVelocity: 0.3,  // px/ms needed to start momentum
        stopVelocity: 0.05,     // px/ms below which momentum ends
        friction: 0.997,        // velocity multiplier per ms of momentum
    };

    function create(options) {
        var o = {};
        for (var k in DEFAULTS) o[k] = DEFAULTS[k];
        for (var k2 in options || {}) o[k2] = options[k2];

        var touching = false;
        var scrolling = false;   // this touch has crossed the tap threshold
        var startX = 0, startY = 0, lastY = 0;
        var samples = [];        // recent {y, t} during a scroll, for flick velocity
        var pending = 0;         // px not yet turned into steps (sign as deltaY)
        var velocity = 0;        // px/ms while coasting
        var coasting = false;
        var lastFrame = null;

        function stopCoasting() {
            coasting = false;
            velocity = 0;
            lastFrame = null;
        }

        return {
            touchStart: function (x, y, t) {
                touching = true;
                scrolling = false;
                startX = x; startY = y; lastY = y;
                samples = [];
                pending = 0;
                stopCoasting();
            },

            // Returns true once this touch is a vertical scroll, so the caller
            // can preventDefault and keep the page itself from moving.
            touchMove: function (x, y, t) {
                if (!touching) return false;
                if (!scrolling) {
                    var dy0 = Math.abs(y - startY);
                    if (dy0 <= o.tapThreshold || dy0 <= Math.abs(x - startX)) return false;
                    scrolling = true;
                    lastY = y;  // the tap threshold itself doesn't scroll
                    samples = [{ y: y, t: t }];
                    return true;
                }
                pending += lastY - y;
                lastY = y;
                samples.push({ y: y, t: t });
                while (samples.length > 2 && t - samples[0].t > o.velocityWindow) samples.shift();
                return true;
            },

            touchEnd: function (t) {
                touching = false;
                if (!scrolling) return;
                scrolling = false;
                var last = samples[samples.length - 1];
                var first = samples[0];
                if (!last || t - last.t > o.liftPause || last.t === first.t) return;
                var v = (first.y - last.y) / (last.t - first.t);
                if (Math.abs(v) >= o.minFlickVelocity) {
                    velocity = v;
                    coasting = true;
                    lastFrame = null;
                }
            },

            // Call once per animation frame; returns the signed number of
            // wheel steps to send now.
            frame: function (t) {
                if (coasting) {
                    var dt = lastFrame === null ? 16 : Math.max(0, t - lastFrame);
                    lastFrame = t;
                    pending += velocity * dt;
                    velocity *= Math.pow(o.friction, dt);
                    if (Math.abs(velocity) < o.stopVelocity) {
                        coasting = false;
                        velocity = 0;
                    }
                }
                var steps = pending > 0 ? Math.floor(pending / o.pxPerStep) : Math.ceil(pending / o.pxPerStep);
                if (steps > o.maxStepsPerFrame) steps = o.maxStepsPerFrame;
                if (steps < -o.maxStepsPerFrame) steps = -o.maxStepsPerFrame;
                pending -= steps * o.pxPerStep;
                if (!touching && !coasting && Math.abs(pending) < o.pxPerStep) pending = 0;
                return steps;
            },

            // True while there is anything left to animate: a scroll in
            // progress, momentum, or queued steps.
            isActive: function () {
                return scrolling || coasting || Math.abs(pending) >= o.pxPerStep;
            },
        };
    }

    return { create: create, DEFAULTS: DEFAULTS };
});
