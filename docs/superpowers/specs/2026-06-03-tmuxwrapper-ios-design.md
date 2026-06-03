# tmuxwrapper-ios — Design

**Date:** 2026-06-03
**Status:** Approved (brainstorming) → ready for implementation plan
**Related project:** `tmuxwrapper` (Rust/axum web terminal, lab LXC `~/projects/tmuxwrapper`)

## Summary

A thin native **SwiftUI iOS app** that wraps the existing `tmuxwrapper` PWA in a
`WKWebView`, gated by **Face ID**. The app does Face ID locally, fetches a
session cookie from the existing password-auth endpoint, injects it into the
WebView's cookie store, and loads the terminal — already authenticated.

**Zero backend changes.** The Rust server, `static/` frontend, xterm.js,
mobile key-bar, session picker, and TTS all remain exactly as they are. The app
is effectively a smarter "Add to Home Screen" with a biometric lock and
credential storage.

## Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| App approach | WebView wrapper (`WKWebView`) + native Face ID | Reuses 100% of existing frontend; smallest effort |
| Server reachability | Cloudflare tunnel + **password auth mode** | Cleanest case — no SSO page to fight inside the WebView |
| Login handoff | Native `URLSession` POST `/api/login` → capture cookie → inject into WebView | Avoids scraping the HTML login form |
| Build & install | Mac + Xcode, **free personal Apple ID sideload** | Personal tool; accepts 7-day re-sign chore |
| Face ID trigger | **Cold launch only** | Convenience; backgrounded app resumes into live terminal |
| Face ID fallback | **Device passcode** (`deviceOwnerAuthentication`) | Standard, still requires device owner |
| Credential storage | iOS Keychain (`whenUnlockedThisDeviceOnly`) | Store password, never a long-lived cookie |

## Architecture

```
App launch (cold)
  └─ BiometricGate: LAContext.evaluatePolicy(.deviceOwnerAuthentication)
       └─ KeychainService: read {serverURL, username, password}
            └─ LoginService: URLSession POST /api/login {username,password}
                 └─ capture Set-Cookie: tmw_session
                      └─ inject into WKWebsiteDataStore.httpCookieStore (await completion)
                           └─ TerminalWebView (WKWebView): load https://<serverURL>/
                                └─ existing terminal UI, already authenticated
```

Re-authenticating on every cold launch (rather than persisting the cookie) is
deliberate: it sidesteps `tmw_session` `Max-Age` expiry entirely and means only
the password lives in the Keychain, never a long-lived session cookie on disk.

### State machine

```
needsSetup ──(creds saved)──> locked
locked ──(Face ID ok)──> loggingIn ──(cookie ok)──> ready
locked ──(Face ID fail)──> locked (retry)
loggingIn ──(login fail)──> error ──(retry / open settings)──> locked | needsSetup
ready ──(cold launch)──> locked
```

## Components (all native Swift, ~300–400 LOC total)

1. **`TmuxwrapperApp` (App + state machine)** — owns the
   `needsSetup → locked → loggingIn → ready → error` state and renders the
   matching view. Triggers Face ID on cold launch (`scenePhase`).

2. **`KeychainService`** — stores/reads `serverURL`, `username`, `password`
   with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Exposes
   `hasCredentials` to decide `needsSetup` vs `locked`.

3. **`SettingsView`** — first-run screen to enter server URL + username +
   password; writes to Keychain. Reachable later to edit credentials.

4. **`BiometricGate`** — wraps `LAContext.evaluatePolicy(
   .deviceOwnerAuthentication, localizedReason:)`. This policy gives Face ID
   with automatic **device-passcode fallback**. Handles "no biometry enrolled"
   by falling through to passcode.

5. **`LoginService`** — `URLSession` POST to `/api/login` with JSON
   `{"username":…,"password":…}`. Reads `Set-Cookie` from the response and
   extracts the `tmw_session` value. Returns the cookie or a typed error.

6. **`TerminalWebView`** — `UIViewRepresentable` over `WKWebView`. Before
   `load()`, writes the `tmw_session` cookie into
   `WKWebsiteDataStore.default().httpCookieStore` and **awaits the completion
   handler**, then loads `https://<serverURL>/`. `WKHTTPCookieStore` may set
   `HttpOnly`/`Secure` cookies, so the server's strict cookie flags are no
   obstacle.

## What is reused for free (no reimplementation)

Because the terminal itself stays a web page rendered in the WebView:

- xterm.js rendering + scrollback
- Mobile key-bar (Esc / Ctrl / Tab / `|` / `~` / `-` / arrows)
- Session picker (`/api/sessions`, create/kill)
- TTS button
- Reconnect overlay and WebSocket reconnect logic

## Networking notes

- `wss://` from inside `WKWebView` works through the Cloudflare tunnel exactly
  as it does for the current PWA (the tunnel already passes the WS upgrade).
- App Transport Security: the tunnel hostname is HTTPS with a valid cert, so no
  ATS exceptions are required.
- The cookie domain must match the tunnel hostname; set it explicitly when
  constructing the `HTTPCookie` to inject.

## Risks / sharp edges

1. **Cookie injection timing (the one fiddly part).** Must populate
   `WKHTTPCookieStore` and wait for its completion handler *before* `load()`,
   or the WebView lands on `/login.html`. Mitigation: gate `load()` behind the
   cookie-set completion closure; add a one-shot fallback that, if the WebView
   navigates to `/login.html`, re-runs login.

2. **Free-signing 7-day expiry.** App must be re-installed from Xcode weekly.
   Accepted cost of personal sideload; upgrading to the $99/yr account (and
   TestFlight) removes it later without code changes.

3. **Cold-launch-only gate.** A backgrounded app resumes straight into the live
   terminal with no re-prompt. Accepted for this threat model; documented so it
   is a conscious choice, not an oversight.

4. **Login failure UX.** Wrong creds / server down must surface a clear error
   with a path to Settings, not a blank WebView.

## Out of scope (YAGNI)

- Native terminal (SwiftTerm) — explicitly rejected in favor of the WebView.
- WebAuthn/passkeys / any backend auth change.
- Cloudflare Access SSO handling (server is in password mode).
- App Store distribution, push notifications, multi-server profiles.
- Background re-lock timeout (cold-launch-only chosen).

## Success criteria

- Cold launch prompts Face ID (passcode fallback works).
- After a successful scan, the terminal loads authenticated with no visible
  login page.
- Typing, the key-bar, session switching, and WebSocket reconnect all work.
- Wrong/missing credentials show a clear error and route to Settings.
- Credentials persist across launches in the Keychain; no cookie persisted to
  disk.
