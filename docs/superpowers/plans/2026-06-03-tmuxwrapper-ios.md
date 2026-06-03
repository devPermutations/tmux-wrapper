# tmuxwrapper-ios Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Execution environment:** This plan is built and run **on a Mac in Xcode**, not in the lab LXC. Unit tests run via `xcodebuild test` / Xcode (⌘U). Steps that require Face ID, the Keychain, or the live WebView are verified on a physical iPhone (the Simulator has no Face ID hardware but can *simulate* enrolled faces via Features → Face ID).

**Goal:** A thin SwiftUI iOS app that gates the existing `tmuxwrapper` PWA behind Face ID, fetching a session cookie and injecting it into a `WKWebView` so the terminal loads already-authenticated.

**Architecture:** Native shell, zero backend changes. On cold launch: Face ID → read credentials from Keychain → `URLSession` POST `/api/login` → capture `tmw_session` cookie → inject into `WKHTTPCookieStore` → `WKWebView` loads `/`. Reuses 100% of the existing web frontend.

**Tech Stack:** Swift 5.9+, SwiftUI, `LocalAuthentication`, `Security` (Keychain), `WebKit` (`WKWebView`), `URLSession`, `XCTest`.

**Spec:** `docs/superpowers/specs/2026-06-03-tmuxwrapper-ios-design.md`

---

## File Structure

```
tmuxwrapper-ios/
├── tmuxwrapper_ios/
│   ├── TmuxwrapperApp.swift        # @main App + AppState state machine + scenePhase gate
│   ├── AppState.swift              # ObservableObject: needsSetup/locked/loggingIn/ready/error
│   ├── KeychainService.swift       # store/read serverURL, username, password
│   ├── BiometricGate.swift         # LocalAuthentication wrapper (Face ID + passcode fallback)
│   ├── LoginService.swift          # URLSession POST /api/login → tmw_session cookie
│   ├── TerminalWebView.swift       # UIViewRepresentable WKWebView + cookie injection
│   ├── SettingsView.swift          # first-run credential entry
│   ├── ContentView.swift           # routes views off AppState.phase
│   └── Info.plist                  # NSFaceIDUsageDescription
└── tmuxwrapper_iosTests/
    ├── KeychainServiceTests.swift
    └── LoginServiceTests.swift
```

**Responsibilities:** Each file is one unit. `KeychainService` and `LoginService` are pure/injectable and unit-tested. `BiometricGate` and `TerminalWebView` wrap Apple frameworks and are verified on device. `AppState` is the single source of truth; views are thin.

---

## Task 1: Xcode project + signing

**Files:**
- Create: `tmuxwrapper-ios/` Xcode project
- Modify: `Info.plist`

- [ ] **Step 1: Create the project**

In Xcode: File → New → Project → iOS → App.
- Product Name: `tmuxwrapper-ios`
- Interface: **SwiftUI**, Language: **Swift**
- Include Tests: **checked**
- Save into the repo (or a sibling dir you'll add to git).

- [ ] **Step 2: Configure free-signing**

Target → Signing & Capabilities → check **Automatically manage signing** → Team: your personal Apple ID (add it under Xcode → Settings → Accounts if absent). Set a unique Bundle Identifier, e.g. `ca.inferex.tmuxwrapper-ios`.

- [ ] **Step 3: Add Face ID usage string**

In `Info.plist` add key `NSFaceIDUsageDescription` (String):
```
Unlock the terminal with Face ID.
```
Without this key the app crashes the first time it touches Face ID.

- [ ] **Step 4: Verify it builds and runs**

Run: select your iPhone (or a Simulator) → ⌘R.
Expected: the default "Hello, world!" SwiftUI screen launches.

- [ ] **Step 5: Commit**

```bash
git add tmuxwrapper-ios
git commit -m "chore: scaffold tmuxwrapper-ios Xcode project with Face ID usage string"
```

---

## Task 2: KeychainService (TDD)

**Files:**
- Create: `tmuxwrapper_ios/KeychainService.swift`
- Test: `tmuxwrapper_iosTests/KeychainServiceTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import tmuxwrapper_ios

final class KeychainServiceTests: XCTestCase {
    let kc = KeychainService(service: "ca.inferex.tmuxwrapper-ios.tests")

    override func tearDown() {
        try? kc.clear()
        super.tearDown()
    }

    func test_roundtrip_credentials() throws {
        XCTAssertFalse(kc.hasCredentials)
        try kc.save(Credentials(serverURL: "https://term.example.com",
                                username: "ktulu", password: "s3cret"))
        XCTAssertTrue(kc.hasCredentials)
        let loaded = try XCTUnwrap(kc.load())
        XCTAssertEqual(loaded.serverURL, "https://term.example.com")
        XCTAssertEqual(loaded.username, "ktulu")
        XCTAssertEqual(loaded.password, "s3cret")
    }

    func test_clear_removes_credentials() throws {
        try kc.save(Credentials(serverURL: "https://x", username: "u", password: "p"))
        try kc.clear()
        XCTAssertFalse(kc.hasCredentials)
        XCTAssertNil(kc.load())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: ⌘U (or `xcodebuild test -scheme tmuxwrapper-ios -destination 'platform=iOS Simulator,name=iPhone 15'`).
Expected: FAIL — `KeychainService` / `Credentials` not defined.

- [ ] **Step 3: Write minimal implementation**

```swift
import Foundation
import Security

struct Credentials: Codable, Equatable {
    var serverURL: String
    var username: String
    var password: String
}

struct KeychainService {
    let service: String
    private let account = "tmuxwrapper-credentials"

    var hasCredentials: Bool { load() != nil }

    func save(_ creds: Credentials) throws {
        let data = try JSONEncoder().encode(creds)
        try clear()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.os(status) }
    }

    func load() -> Credentials? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let creds = try? JSONDecoder().decode(Credentials.self, from: data)
        else { return nil }
        return creds
    }

    func clear() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.os(status)
        }
    }
}

enum KeychainError: Error { case os(OSStatus) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: ⌘U.
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tmuxwrapper_ios/KeychainService.swift tmuxwrapper_iosTests/KeychainServiceTests.swift
git commit -m "feat: Keychain-backed credential storage"
```

---

## Task 3: LoginService cookie parsing (TDD)

**Files:**
- Create: `tmuxwrapper_ios/LoginService.swift`
- Test: `tmuxwrapper_iosTests/LoginServiceTests.swift`

Uses a custom `URLProtocol` to stub the network so cookie extraction is tested without a live server.

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import tmuxwrapper_ios

final class LoginServiceTests: XCTestCase {
    override func setUp() { URLProtocol.registerClass(StubURLProtocol.self) }
    override func tearDown() { StubURLProtocol.handler = nil; URLProtocol.unregisterClass(StubURLProtocol.self) }

    private func makeService() -> LoginService {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubURLProtocol.self]
        return LoginService(session: URLSession(configuration: cfg))
    }

    func test_extracts_tmw_session_cookie() async throws {
        StubURLProtocol.handler = { req in
            let resp = HTTPURLResponse(
                url: req.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Set-Cookie": "tmw_session=abc.def.123; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400"]
            )!
            return (resp, Data())
        }
        let token = try await makeService().login(
            serverURL: "https://term.example.com", username: "ktulu", password: "pw")
        XCTAssertEqual(token, "abc.def.123")
    }

    func test_bad_credentials_throws() async {
        StubURLProtocol.handler = { req in
            (HTTPURLResponse(url: req.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!, Data())
        }
        do {
            _ = try await makeService().login(serverURL: "https://x", username: "u", password: "bad")
            XCTFail("expected error")
        } catch LoginError.unauthorized { /* ok */ }
        catch { XCTFail("wrong error: \(error)") }
    }
}

final class StubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let h = Self.handler else { return }
        let (resp, data) = h(request)
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: ⌘U.
Expected: FAIL — `LoginService` / `LoginError` not defined.

- [ ] **Step 3: Write minimal implementation**

```swift
import Foundation

enum LoginError: Error { case badURL, unauthorized, noCookie, server(Int) }

struct LoginService {
    let session: URLSession
    init(session: URLSession = .shared) { self.session = session }

    /// POSTs credentials to /api/login and returns the tmw_session token value.
    func login(serverURL: String, username: String, password: String) async throws -> String {
        guard let base = URL(string: serverURL),
              let url = URL(string: "/api/login", relativeTo: base) else { throw LoginError.badURL }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(
            withJSONObject: ["username": username, "password": password])

        let (_, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw LoginError.server(-1) }
        switch http.statusCode {
        case 200..<300: break
        case 401, 403: throw LoginError.unauthorized
        default: throw LoginError.server(http.statusCode)
        }

        let setCookie = http.value(forHTTPHeaderField: "Set-Cookie") ?? ""
        guard let token = Self.tmwSessionValue(from: setCookie) else { throw LoginError.noCookie }
        return token
    }

    /// Extracts the tmw_session value from a Set-Cookie header.
    static func tmwSessionValue(from setCookie: String) -> String? {
        for part in setCookie.split(separator: ";") {
            let kv = part.trimmingCharacters(in: .whitespaces)
            if kv.hasPrefix("tmw_session=") {
                return String(kv.dropFirst("tmw_session=".count))
            }
        }
        return nil
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: ⌘U.
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tmuxwrapper_ios/LoginService.swift tmuxwrapper_iosTests/LoginServiceTests.swift
git commit -m "feat: login service that extracts tmw_session cookie"
```

---

## Task 4: BiometricGate (device-verified)

**Files:**
- Create: `tmuxwrapper_ios/BiometricGate.swift`

`LocalAuthentication` cannot be meaningfully unit-tested (no injectable seam without heavy mocking). Keep it tiny and verify on device/Simulator.

- [ ] **Step 1: Write the implementation**

```swift
import LocalAuthentication

enum BiometricResult { case success, failed, unavailable }

struct BiometricGate {
    /// Prompts for Face ID; falls back to device passcode automatically
    /// because we use .deviceOwnerAuthentication (not ...WithBiometrics).
    func authenticate() async -> BiometricResult {
        let ctx = LAContext()
        ctx.localizedFallbackTitle = "Use Passcode"

        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return .unavailable
        }
        do {
            let ok = try await ctx.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Unlock the terminal")
            return ok ? .success : .failed
        } catch {
            return .failed
        }
    }
}
```

- [ ] **Step 2: Verify on device**

Temporarily wire a button in `ContentView` that calls `await BiometricGate().authenticate()` and prints the result. Run on iPhone (⌘R).
Expected: Face ID sheet appears; success prints `.success`; cancelling prints `.failed`; "Use Passcode" path works. (Simulator: enable Features → Face ID → Enrolled, then Matching/Non-matching Face.)
Remove the temporary button after verifying.

- [ ] **Step 3: Commit**

```bash
git add tmuxwrapper_ios/BiometricGate.swift
git commit -m "feat: Face ID gate with passcode fallback"
```

---

## Task 5: AppState + SettingsView

**Files:**
- Create: `tmuxwrapper_ios/AppState.swift`
- Create: `tmuxwrapper_ios/SettingsView.swift`

- [ ] **Step 1: Write AppState**

```swift
import SwiftUI

enum Phase: Equatable {
    case needsSetup
    case locked
    case loggingIn
    case ready(token: String, serverURL: String)
    case error(String)
}

@MainActor
final class AppState: ObservableObject {
    @Published var phase: Phase = .needsSetup

    let keychain = KeychainService(service: "ca.inferex.tmuxwrapper-ios")
    let biometrics = BiometricGate()
    let login = LoginService()

    func bootstrap() {
        phase = keychain.hasCredentials ? .locked : .needsSetup
    }

    /// Cold-launch gate: Face ID, then log in and move to .ready.
    func unlock() async {
        guard let creds = keychain.load() else { phase = .needsSetup; return }
        switch await biometrics.authenticate() {
        case .success: break
        case .failed, .unavailable: phase = .locked; return
        }
        phase = .loggingIn
        do {
            let token = try await login.login(
                serverURL: creds.serverURL, username: creds.username, password: creds.password)
            phase = .ready(token: token, serverURL: creds.serverURL)
        } catch LoginError.unauthorized {
            phase = .error("Wrong username or password.")
        } catch {
            phase = .error("Couldn't reach the server.")
        }
    }

    func saveCredentials(_ creds: Credentials) {
        try? keychain.save(creds)
        phase = .locked
    }

    func relock() { if case .ready = phase { phase = .locked } }
}
```

- [ ] **Step 2: Write SettingsView**

```swift
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var app: AppState
    @State private var serverURL = ""
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        Form {
            Section("Server") {
                TextField("https://term.example.com", text: $serverURL)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .keyboardType(.URL)
            }
            Section("Credentials") {
                TextField("Username", text: $username)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("Password", text: $password)
            }
            Button("Save") {
                app.saveCredentials(Credentials(
                    serverURL: serverURL.trimmingCharacters(in: .whitespaces),
                    username: username, password: password))
            }
            .disabled(serverURL.isEmpty || username.isEmpty || password.isEmpty)
        }
        .onAppear {
            if let c = app.keychain.load() {
                serverURL = c.serverURL; username = c.username; password = c.password
            }
        }
    }
}
```

- [ ] **Step 3: Verify it builds**

Run: ⌘B. Expected: build succeeds (views not yet wired into the app — Task 7).

- [ ] **Step 4: Commit**

```bash
git add tmuxwrapper_ios/AppState.swift tmuxwrapper_ios/SettingsView.swift
git commit -m "feat: app state machine and first-run settings screen"
```

---

## Task 6: TerminalWebView with cookie injection

**Files:**
- Create: `tmuxwrapper_ios/TerminalWebView.swift`

This is the fiddly part: the cookie MUST be set (completion handler fired) **before** `load()`, or the WebView lands on `/login.html`.

- [ ] **Step 1: Write the implementation**

```swift
import SwiftUI
import WebKit

struct TerminalWebView: UIViewRepresentable {
    let serverURL: String
    let token: String
    var onAuthLost: () -> Void = {}

    func makeCoordinator() -> Coordinator { Coordinator(onAuthLost: onAuthLost) }

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView(frame: .zero)
        webView.navigationDelegate = context.coordinator
        webView.scrollView.bounces = false

        guard let base = URL(string: serverURL), let host = base.host else { return webView }

        let cookie = HTTPCookie(properties: [
            .domain: host,
            .path: "/",
            .name: "tmw_session",
            .value: token,
            .secure: "TRUE",
        ])!

        // Inject the cookie, THEN load — ordering is critical.
        webView.configuration.websiteDataStore.httpCookieStore.setCookie(cookie) {
            webView.load(URLRequest(url: base))
        }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        let onAuthLost: () -> Void
        init(onAuthLost: @escaping () -> Void) { self.onAuthLost = onAuthLost }

        // If the server bounced us to the login page, the cookie was rejected/expired.
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            if webView.url?.path.contains("login") == true { onAuthLost() }
        }
    }
}
```

- [ ] **Step 2: Verify it builds**

Run: ⌘B. Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add tmuxwrapper_ios/TerminalWebView.swift
git commit -m "feat: WKWebView terminal host with pre-load cookie injection"
```

---

## Task 7: Wire it together + cold-launch gate

**Files:**
- Modify: `tmuxwrapper_ios/TmuxwrapperApp.swift`
- Create: `tmuxwrapper_ios/ContentView.swift`

- [ ] **Step 1: Write ContentView (routes off phase)**

```swift
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var app: AppState

    var body: some View {
        switch app.phase {
        case .needsSetup:
            SettingsView()
        case .locked:
            VStack(spacing: 20) {
                Image(systemName: "faceid").font(.system(size: 64))
                Button("Unlock") { Task { await app.unlock() } }
            }
            .task { await app.unlock() }   // auto-prompt on appear
        case .loggingIn:
            ProgressView("Connecting…")
        case let .ready(token, serverURL):
            TerminalWebView(serverURL: serverURL, token: token,
                            onAuthLost: { app.phase = .error("Session rejected. Try again.") })
                .ignoresSafeArea()
        case let .error(msg):
            VStack(spacing: 16) {
                Text(msg).multilineTextAlignment(.center)
                Button("Retry") { Task { await app.unlock() } }
                Button("Settings") { app.phase = .needsSetup }
            }.padding()
        }
    }
}
```

- [ ] **Step 2: Write the App entrypoint with scenePhase gate**

```swift
import SwiftUI

@main
struct TmuxwrapperApp: App {
    @StateObject private var app = AppState()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(app)
                .onAppear { app.bootstrap() }
                .preferredColorScheme(.dark)
        }
        .onChange(of: scenePhase) { _, newPhase in
            // Cold-launch-only policy: we do NOT relock on background/foreground.
            // bootstrap() on first appear sets .locked, which auto-runs unlock().
            if newPhase == .active, app.phase == .needsSetup, app.keychain.hasCredentials {
                app.phase = .locked
            }
        }
    }
}
```

- [ ] **Step 3: Verify build**

Run: ⌘B. Expected: build succeeds, no unused-symbol warnings for the views.

- [ ] **Step 4: Commit**

```bash
git add tmuxwrapper_ios/ContentView.swift tmuxwrapper_ios/TmuxwrapperApp.swift
git commit -m "feat: wire app phases, auto Face ID on launch, cold-launch-only policy"
```

---

## Task 8: End-to-end verification on device

**Files:** none (manual verification)

- [ ] **Step 1: First-run setup**

Install on iPhone (⌘R). Expected: `SettingsView` appears (no creds yet). Enter your tunnel URL (`https://<your-tunnel-host>`), username, password → Save.

- [ ] **Step 2: Face ID → terminal**

App moves to `.locked` and auto-prompts Face ID. On success: brief "Connecting…", then the **xterm.js terminal loads already logged in** (no `/login.html`).
Expected: you can type, the key-bar works, and the session picker lists tmux sessions.

- [ ] **Step 3: WebSocket sanity**

Run a command that produces continuous output (e.g. `top`). Expected: live updates render — confirms `wss://` works through the tunnel inside the WebView.

- [ ] **Step 4: Negative paths**

- Kill the connection (airplane mode) and relaunch → expect the `.error("Couldn't reach the server.")` screen with Retry/Settings.
- Open Settings, change password to a wrong value, relaunch → expect `.error("Wrong username or password.")`.
- Restore the correct password.

- [ ] **Step 5: Cold-launch gate**

Force-quit the app and reopen → Face ID is required again. Background and foreground (without quitting) → terminal resumes WITHOUT a new prompt (cold-launch-only policy, as designed).

- [ ] **Step 6: Final commit / tag**

```bash
git commit --allow-empty -m "test: verified end-to-end on device (Face ID, login handoff, websocket)"
git tag v0.1.0
```

---

## Self-Review

**Spec coverage:**
- WebView wrapper + Face ID → Tasks 4, 6, 7 ✓
- Password-mode login handoff (URLSession → cookie → inject) → Tasks 3, 6 ✓
- Keychain credential storage, no persisted cookie → Task 2; cookie only held in `Phase.ready` in memory ✓
- Cold-launch-only Face ID, passcode fallback → Tasks 4, 7 ✓
- First-run settings UX, clear error → login page → Tasks 5, 7 ✓
- Reused frontend (key-bar/sessions/TTS/reconnect) → verified Task 8 ✓
- Free-signing build/run → Task 1 ✓

**Placeholder scan:** none — all steps contain real Swift/commands.

**Type consistency:** `Credentials`, `KeychainService(service:)`, `LoginService.login(serverURL:username:password:)`, `BiometricGate.authenticate()→BiometricResult`, `Phase`, `AppState.unlock()/saveCredentials/bootstrap`, `TerminalWebView(serverURL:token:onAuthLost:)` are used consistently across tasks. ✓

---

## Notes & follow-ups (out of scope for v0.1)

- **7-day re-sign:** free signing expires weekly; re-run ⌘R from Xcode. Upgrade to a $99/yr Apple Developer account for TestFlight to remove this — no code changes needed.
- If `connect-src` ever tightens the server CSP, confirm it still allows `wss:` (it currently does in `src/main.rs`).
- Possible later nicety: a manual "lock now" button and/or a background-timeout relock (`AppState.relock()` already exists, just unused).
