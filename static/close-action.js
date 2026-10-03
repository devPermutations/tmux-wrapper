// What the phone client does when its terminal socket closes. Pure logic —
// no DOM — so it can be unit tested under node; terminal.js acts on the
// returned action.
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.CloseAction = factory();
    }
})(this, function () {
    'use strict';

    // Close codes sent by the server (src/ws.rs).
    var CLOSE_AUTH_EXPIRED = 4001;
    var CLOSE_REFUSED = 4004;

    // The helper refuses with this while its auth keys load after a restart.
    // It clears on its own, so the client retries instead of giving up.
    var KEYS_UNAVAILABLE = 'auth keys unavailable — try again shortly';

    // 'reauthenticate' — the Access session lapsed: reload through login.
    // 'picker'         — refused (e.g. a limit): show the reason, then the
    //                    session picker so the user can kill an old session.
    // 'retry'          — refused only until the helper's keys load: show the
    //                    reason and reconnect.
    // 'reconnect'      — anything else: back off and reconnect.
    function closeAction(code, reason) {
        if (code === CLOSE_AUTH_EXPIRED) return 'reauthenticate';
        if (code === CLOSE_REFUSED) {
            return reason === KEYS_UNAVAILABLE ? 'retry' : 'picker';
        }
        return 'reconnect';
    }

    return { closeAction: closeAction };
});
