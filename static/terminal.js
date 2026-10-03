(function () {
    'use strict';

    const TAG_DATA = 0x00;
    const TAG_CONTROL = 0x01;

    // --- State ---
    let ws = null;
    let currentSession = null;
    let reconnectDelay = 1000;
    let ctrlActive = false;
    const MAX_RECONNECT_DELAY = 30000;

    // --- Terminal setup ---
    const term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'Menlo, Monaco, "Courier New", monospace',
        theme: {
            background: '#000000',
            foreground: '#ffffff',
        },
        allowProposedApi: true,
        scrollback: 5000,
    });

    const fitAddon = new FitAddon.FitAddon();
    const webLinksAddon = new WebLinksAddon.WebLinksAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);

    const container = document.getElementById('terminal');
    term.open(container);

    // WebGL renderer: much cheaper full-pane redraws than the default DOM
    // renderer, and every scroll step repaints the pane. Falls back to the
    // DOM renderer if WebGL is unavailable or its context is lost (iOS can
    // drop it while the app is backgrounded).
    if (window.WebglAddon) {
        try {
            const webgl = new WebglAddon.WebglAddon();
            webgl.onContextLoss(function () { webgl.dispose(); });
            term.loadAddon(webgl);
        } catch (e) {
            // keep the DOM renderer
        }
    }

    // Disable autocorrect/autocapitalize on xterm's hidden textarea
    const textarea = container.querySelector('.xterm-helper-textarea');
    if (textarea) {
        textarea.setAttribute('autocorrect', 'off');
        textarea.setAttribute('autocapitalize', 'off');
        textarea.setAttribute('autocomplete', 'off');
        textarea.setAttribute('spellcheck', 'false');
    }

    // Fix iOS voice dictation doubling (WebKit bug #261764).
    // iOS dictation does NOT fire compositionstart/compositionend. Instead it
    // fires keydown(229) + input(insertText), which triggers BOTH xterm's
    // _inputEvent handler AND its CompositionHelper, doubling all text.
    // Fix: after xterm's _inputEvent processes insertText, clear the textarea
    // so CompositionHelper's diff finds nothing new.
    if (textarea) {
        var lastInsertTime = 0;
        textarea.addEventListener('beforeinput', function (e) {
            if (e.inputType === 'insertText' && e.data) {
                lastInsertTime = Date.now();
            }
        }, true);
        textarea.addEventListener('input', function (e) {
            if (e.inputType === 'insertText' && (Date.now() - lastInsertTime) < 50) {
                setTimeout(function () { textarea.value = ''; }, 0);
            }
        }, false);
    }

    // --- Session picker ---
    const picker = document.getElementById('session-picker');
    const sessionList = document.getElementById('session-list');
    const newSessionInput = document.getElementById('new-session-name');
    const newSessionBtn = document.getElementById('new-session-btn');

    async function fetchSessions() {
        try {
            const resp = await fetch('/api/sessions');
            if (!resp.ok) {
                if (resp.status === 401) {
                    // Cloudflare Access token missing/expired — a full reload
                    // bounces through CF Access and re-authenticates.
                    showOverlay('Session expired — reload the page');
                    return null;
                }
                if (resp.status === 403) {
                    showOverlay('Access denied');
                    return null;
                }
                return [];
            }
            return await resp.json();
        } catch (e) {
            return [];
        }
    }

    function showPicker() {
        container.style.display = 'none';
        document.getElementById('key-bar').style.display = 'none';
        picker.classList.remove('hidden');
    }

    function hidePicker() {
        picker.classList.add('hidden');
        container.style.display = '';
        document.getElementById('key-bar').style.display = '';
    }

    async function loadSessionPicker() {
        showPicker();
        sessionList.innerHTML = '<div class="session-loading">Loading sessions...</div>';

        const sessions = await fetchSessions();
        if (sessions === null) return; // auth failure

        sessionList.innerHTML = '';

        if (sessions.length === 0) {
            sessionList.innerHTML = '<div class="session-empty">No tmux sessions found</div>';
        } else {
            sessions.forEach(function (s) {
                var row = document.createElement('div');
                row.className = 'session-row';

                var btn = document.createElement('button');
                btn.className = 'session-btn';
                btn.innerHTML =
                    '<span class="session-name">' + escapeHtml(s.name) + '</span>' +
                    '<span class="session-info">' + s.windows + ' window' + (s.windows !== 1 ? 's' : '') +
                    (s.attached ? ' (attached)' : '') + '</span>';
                btn.addEventListener('click', function () {
                    connectToSession(s.name);
                });

                var killBtn = document.createElement('button');
                killBtn.className = 'session-kill-btn';
                killBtn.textContent = '\u00D7';
                killBtn.title = 'Kill session';
                killBtn.addEventListener('click', function (e) {
                    e.stopPropagation();
                    confirmKillSession(s.name);
                });

                row.appendChild(btn);
                row.appendChild(killBtn);
                sessionList.appendChild(row);
            });
        }
    }

    function confirmKillSession(name) {
        var dialog = document.getElementById('confirm-dialog');
        var msg = document.getElementById('confirm-msg');
        var yesBtn = document.getElementById('confirm-yes');
        var noBtn = document.getElementById('confirm-no');

        msg.textContent = 'Kill session "' + name + '"?';
        dialog.classList.remove('hidden');

        function cleanup() {
            dialog.classList.add('hidden');
            yesBtn.removeEventListener('click', onYes);
            noBtn.removeEventListener('click', onNo);
        }
        function onYes() {
            cleanup();
            killSession(name);
        }
        function onNo() {
            cleanup();
        }
        yesBtn.addEventListener('click', onYes);
        noBtn.addEventListener('click', onNo);
    }

    async function killSession(name) {
        try {
            var resp = await fetch('/api/sessions/' + encodeURIComponent(name), {
                method: 'DELETE',
            });
            if (!resp.ok) {
                showOverlay('Failed to kill session');
                setTimeout(hideOverlay, 2000);
            }
        } catch (e) {
            showOverlay('Failed to kill session');
            setTimeout(hideOverlay, 2000);
        }
        loadSessionPicker();
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    newSessionBtn.addEventListener('click', function () {
        var name = newSessionInput.value.trim();
        if (name && /^[a-zA-Z0-9_-]+$/.test(name)) {
            connectToSession(name);
        }
    });

    newSessionInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            newSessionBtn.click();
        }
    });

    function connectToSession(name) {
        currentSession = name;
        hidePicker();
        term.clear();
        term.focus();
        fitAddon.fit();
        connect();
    }

    function switchSession() {
        if (ws) {
            ws.onclose = null;
            ws.onerror = null;
            ws.close();
            ws = null;
        }
        currentSession = null;
        loadSessionPicker();
    }

    // --- WebSocket connection ---
    function wsUrl() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var url = proto + '//' + location.host + '/ws';
        if (currentSession) {
            url += '?session=' + encodeURIComponent(currentSession);
        }
        return url;
    }

    function showOverlay(text) {
        var overlay = document.getElementById('overlay');
        document.getElementById('overlay-text').textContent = text;
        overlay.classList.remove('hidden');
    }

    function hideOverlay() {
        document.getElementById('overlay').classList.add('hidden');
    }

    function sendData(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            var payload = new Uint8Array(1 + data.length);
            payload[0] = TAG_DATA;
            payload.set(data, 1);
            ws.send(payload.buffer);
        }
    }

    function sendControl(msg) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            var json = JSON.stringify(msg);
            var encoded = new TextEncoder().encode(json);
            var payload = new Uint8Array(1 + encoded.length);
            payload[0] = TAG_CONTROL;
            payload.set(encoded, 1);
            ws.send(payload.buffer);
        }
    }

    function sendResize() {
        sendControl({
            type: 'resize',
            cols: term.cols,
            rows: term.rows,
        });
    }

    function connect() {
        if (ws) {
            ws.onclose = null;
            ws.onerror = null;
            ws.close();
        }

        ws = new WebSocket(wsUrl());
        ws.binaryType = 'arraybuffer';

        ws.onopen = function () {
            hideOverlay();
            reconnectDelay = 1000;
            fitAddon.fit();
            sendResize();
        };

        ws.onmessage = function (event) {
            var data = new Uint8Array(event.data);
            if (data.length < 1) return;
            if (data[0] === TAG_DATA) {
                term.write(data.slice(1));
            }
        };

        ws.onclose = function (event) {
            if (event.code === 4004) {
                // Server refused: connection or session limit reached.
                // Show the reason, then return to the picker so the user
                // can kill an old session.
                showOverlay(event.reason || 'Limit reached');
                setTimeout(function () {
                    hideOverlay();
                    switchSession();
                }, 3000);
                return;
            }
            scheduleReconnect();
        };

        ws.onerror = function () {};
    }

    function scheduleReconnect() {
        showOverlay('Reconnecting...');
        setTimeout(function () {
            connect();
            reconnectDelay = Math.min(reconnectDelay * 1.5, MAX_RECONNECT_DELAY);
        }, reconnectDelay);
    }

    // --- Terminal input (with iOS dictation dedup) ---
    var lastSentData = '';
    var lastSentTime = 0;
    var DEDUP_WINDOW_MS = 50;

    term.onData(function (data) {
        if (ctrlActive && data.length === 1) {
            var code = data.toUpperCase().charCodeAt(0) - 64;
            if (code > 0 && code < 32) {
                sendData(new Uint8Array([code]));
            }
            ctrlActive = false;
            btnCtrl.classList.remove('active');
            return;
        }
        // Dedup: iOS dictation fires the same multi-char string twice
        // within milliseconds via two xterm input paths. Drop the duplicate.
        var now = Date.now();
        if (data.length > 1 && data === lastSentData
            && (now - lastSentTime) < DEDUP_WINDOW_MS) {
            return;
        }
        lastSentData = data;
        lastSentTime = now;
        sendData(new TextEncoder().encode(data));
    });

    term.onBinary(function (data) {
        var bytes = new Uint8Array(data.length);
        for (var i = 0; i < data.length; i++) {
            bytes[i] = data.charCodeAt(i);
        }
        sendData(bytes);
    });

    // --- Resize handling ---
    function doFit() {
        fitAddon.fit();
        sendResize();
    }

    window.addEventListener('resize', doFit);

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', function () {
            var vv = window.visualViewport;
            var keyBar = document.getElementById('key-bar');
            var keyBarHeight = keyBar.offsetHeight || 0;
            container.style.height = vv.height - keyBarHeight + 'px';
            keyBar.style.bottom = (window.innerHeight - vv.height - vv.offsetTop) + 'px';
            doFit();
        });
    }

    // --- Key bar ---
    var btnCtrl = document.getElementById('btn-ctrl');
    var keyBar = document.getElementById('key-bar');

    keyBar.addEventListener('click', function (e) {
        var btn = e.target.closest('button');
        if (!btn) return;
        var key = btn.dataset.key;

        if (key === 'sessions') {
            switchSession();
            return;
        }

        if (key === 'ctrl') {
            ctrlActive = !ctrlActive;
            btnCtrl.classList.toggle('active', ctrlActive);
            term.focus();
            return;
        }

        if (ctrlActive) {
            if (key.length === 1) {
                var code = key.toUpperCase().charCodeAt(0) - 64;
                if (code > 0 && code < 32) {
                    sendData(new Uint8Array([code]));
                }
            } else {
                sendSpecialKey(key, true);
            }
            ctrlActive = false;
            btnCtrl.classList.remove('active');
        } else {
            sendSpecialKey(key, false);
        }

        term.focus();
    });

    function sendSpecialKey(key, ctrl) {
        var sequences = {
            'Escape': '\x1b',
            'Tab': '\t',
            '|': '|',
            '~': '~',
            '-': '-',
            'ArrowUp': ctrl ? '\x1b[1;5A' : '\x1b[A',
            'ArrowDown': ctrl ? '\x1b[1;5B' : '\x1b[B',
            'ArrowRight': ctrl ? '\x1b[1;5C' : '\x1b[C',
            'ArrowLeft': ctrl ? '\x1b[1;5D' : '\x1b[D',
            // Scroll keys — Claude Code (fullscreen) scrolls half a screen on
            // PgUp/PgDn, jumps to the start on Ctrl+Home and back to the
            // latest message on Ctrl+End. tmux passes all four through.
            'PageUp': '\x1b[5~',
            'PageDown': '\x1b[6~',
            'ScrollTop': '\x1b[1;5H',
            'ScrollBottom': '\x1b[1;5F',
        };
        var seq = sequences[key];
        if (seq) {
            sendData(new TextEncoder().encode(seq));
        }
    }

    // --- Mobile touch scrolling ---
    // Touches land on xterm's render surface, not a native scroller, so we
    // scroll by sending wheel ticks: tmux scrolls copy-mode on them, and
    // mouse-aware apps (Claude Code fullscreen, vim, less) get them as mouse
    // wheel reports. ScrollEngine turns finger travel into a paced number of
    // ticks, with momentum after a flick. Each tick is a one-line wheel
    // event, which xterm.js turns into exactly one wheel report.
    (function () {
        var screen = container.querySelector('.xterm-screen');
        if (!screen || !window.ScrollEngine) return;

        // ~2 rows of 14px text per tick: keeps slow drags at about the tick
        // rate the old per-touchmove wheel handler produced, while flicks now
        // coast. Claude Code's lines-per-tick is undocumented; tune by feel.
        var engine = ScrollEngine.create({ pxPerStep: 35, maxStepsPerFrame: 4 });
        var animating = false;

        function sendWheelTick(direction) {
            screen.dispatchEvent(new WheelEvent('wheel', {
                deltaY: direction,
                deltaMode: WheelEvent.DOM_DELTA_LINE,
                bubbles: true,
                cancelable: true,
            }));
        }

        function tick() {
            var steps = engine.frame(performance.now());
            var direction = steps > 0 ? 1 : -1;
            for (var i = 0; i < Math.abs(steps); i++) {
                sendWheelTick(direction);
            }
            if (engine.isActive()) {
                requestAnimationFrame(tick);
            } else {
                animating = false;
            }
        }

        function animate() {
            if (!animating && engine.isActive()) {
                animating = true;
                requestAnimationFrame(tick);
            }
        }

        container.addEventListener('touchstart', function (e) {
            if (e.touches.length !== 1) return;
            engine.touchStart(e.touches[0].clientX, e.touches[0].clientY, performance.now());
        }, { passive: true });

        container.addEventListener('touchmove', function (e) {
            if (e.touches.length !== 1) return;
            if (engine.touchMove(e.touches[0].clientX, e.touches[0].clientY, performance.now())) {
                e.preventDefault();
                animate();
            }
        }, { passive: false });

        function onTouchEnd() {
            engine.touchEnd(performance.now());
            animate();
        }
        container.addEventListener('touchend', onTouchEnd, { passive: true });
        container.addEventListener('touchcancel', onTouchEnd, { passive: true });
    })();

    // Keep terminal focused
    document.addEventListener('click', function (e) {
        if (!e.target.closest('#key-bar') && !e.target.closest('#session-picker')) {
            term.focus();
        }
    });

    // --- Start: show session picker ---
    loadSessionPicker();
})();
