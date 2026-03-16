# Voice TTS Implementation Plan

Server-side text-to-speech using Piper, streamed to the browser over the existing WebSocket.

## Architecture

```
PTY output (Task 2: pty_to_ws)
        │
        ├──→ 0x00 frames → xterm.js (unchanged, visual output)
        │
        └──→ TTS pipeline (new, opt-in when client enables it)
                │
                ├─ Strip ANSI escape codes
                ├─ Buffer into sentence boundaries
                ├─ Skip input echo / shell prompts
                ├─ Pipe text to Piper subprocess → WAV/OGG audio
                └─ Send as 0x02 WebSocket frames → browser plays them
```

## WebSocket Protocol Extension

Current message tags:
- `0x00` — terminal data (PTY bytes)
- `0x01` — control messages (JSON: resize)

New tags:
- `0x02` — audio frame (server → client): OGG/Opus audio chunk
- `0x03` — TTS control (client → server, JSON):
  ```json
  {"msg_type": "tts", "enabled": true, "voice": "en_US-lessac-medium"}
  ```

## Implementation Steps

### Phase 1: Install Piper on the server

1. Download Piper binary and a default voice model (e.g. `en_US-lessac-medium`)
2. Place in a known path (e.g. `/opt/piper/` or configurable in `config.toml`)
3. Verify it works: `echo "Hello world" | piper --model en_US-lessac-medium --output_raw | ffmpeg -f s16le -ar 22050 -ac 1 -i - -c:a libopus test.ogg`
4. Add `tts` section to `config.toml`:
   ```toml
   [tts]
   enabled = true
   piper_binary = "/opt/piper/piper"
   voices_dir = "/opt/piper/voices"
   default_voice = "en_US-lessac-medium"
   ```

### Phase 2: ANSI stripping + text buffering (Rust, new module `src/tts.rs`)

Create `src/tts.rs` with:

1. **`strip_ansi(bytes: &[u8]) -> String`** — strip all CSI/OSC/SGR escape sequences, returning clean UTF-8 text. Use a state machine or the `strip-ansi-escapes` crate.

2. **`TtsBuffer`** struct that accumulates text and emits sentence-sized chunks:
   - Append stripped text as it arrives from PTY reads
   - Detect sentence boundaries (`. `, `? `, `! `, `\n\n`, or a 300ms silence/pause in output)
   - Return `Option<String>` — `Some(sentence)` when a chunk is ready
   - Minimum chunk size (~20 chars) to avoid speaking tiny fragments
   - Skip lines that look like shell prompts (configurable regex, e.g. `^\$\s`, `^❯`, `^[a-z]+@`)
   - Skip lines that are exact echo of recent input (keep a small ring buffer of sent input for comparison)

3. **`PiperSynthesizer`** struct:
   - Spawns `piper` as a long-running subprocess with `--output_raw` flag
   - Pipe text via stdin, read raw PCM (16-bit, 22050Hz mono) from stdout
   - Convert PCM to OGG/Opus in-memory (use `ogg`+`opus` crates, or shell out to `opusenc`/`ffmpeg` for simplicity in v1)
   - Returns `Vec<u8>` of encoded audio for each chunk
   - Method to switch voice model (restarts subprocess)

### Phase 3: Wire TTS into the WebSocket bridge (`src/ws.rs`)

Modify `run_bridge()`:

1. Add a `tts_enabled: Arc<AtomicBool>` shared between tasks
2. Add a `tts_voice: Arc<Mutex<String>>` for current voice selection

3. **In Task 1 (WebSocket I/O loop)** — handle new `0x03` control messages:
   ```rust
   0x03 => {
       if let Ok(ctrl) = serde_json::from_slice::<TtsControl>(&data[1..]) {
           tts_enabled.store(ctrl.enabled, Ordering::Relaxed);
           if let Some(voice) = ctrl.voice {
               *tts_voice.lock().await = voice;
           }
       }
   }
   ```

4. **In Task 2 (PTY → WebSocket)** — fork the output into TTS pipeline:
   ```rust
   // After sending the 0x00 frame (existing code):
   if tts_enabled.load(Ordering::Relaxed) {
       if let Some(sentence) = tts_buffer.feed(&buf[..n]) {
           // Spawn TTS on blocking thread pool to avoid stalling PTY reads
           let audio = synthesizer.speak(sentence).await;
           let mut frame = Vec::with_capacity(1 + audio.len());
           frame.push(0x02);
           frame.extend_from_slice(&audio);
           let _ = ws_out_tx_clone.send(Message::Binary(frame.into())).await;
       }
   }
   ```

   Important: TTS generation must not block the PTY read loop. Options:
   - Run `synthesizer.speak()` via `tokio::task::spawn_blocking`
   - Or use a dedicated TTS channel: PTY task sends text to a TTS task, TTS task sends audio frames to ws_out_tx

   **Preferred: dedicated TTS task (Task 4)**:
   ```
   Task 2 (PTY read) --sentence--> mpsc --> Task 4 (TTS) --audio--> ws_out_tx
   ```
   This decouples TTS latency from terminal responsiveness entirely.

### Phase 4: Client-side audio playback (`static/terminal.js`)

1. **Add TTS toggle button** to `#key-bar` in `index.html`:
   ```html
   <button data-key="tts" id="btn-tts" title="Text-to-speech">&#128264;</button>
   ```

2. **Audio playback queue** in `terminal.js`:
   ```js
   const TAG_AUDIO = 0x02;
   const TAG_TTS_CTRL = 0x03;
   let ttsEnabled = false;
   let audioQueue = [];
   let audioPlaying = false;

   function playNextAudio() {
       if (audioQueue.length === 0) { audioPlaying = false; return; }
       audioPlaying = true;
       const blob = new Blob([audioQueue.shift()], { type: 'audio/ogg' });
       const audio = new Audio(URL.createObjectURL(blob));
       audio.onended = () => { URL.revokeObjectURL(audio.src); playNextAudio(); };
       audio.onerror = () => { URL.revokeObjectURL(audio.src); playNextAudio(); };
       audio.play().catch(() => playNextAudio());
   }
   ```

3. **Handle 0x02 frames** in the WebSocket message handler:
   ```js
   // In the existing binary message handler:
   const tag = data[0];
   if (tag === TAG_DATA) {
       term.write(data.slice(1));
   } else if (tag === TAG_AUDIO) {
       audioQueue.push(data.slice(1));
       if (!audioPlaying) playNextAudio();
   }
   ```

4. **TTS toggle button handler**:
   ```js
   document.getElementById('btn-tts').addEventListener('click', function() {
       ttsEnabled = !ttsEnabled;
       this.classList.toggle('active', ttsEnabled);
       // First click satisfies iOS user-gesture requirement for audio playback
       const ctrl = new TextEncoder().encode(JSON.stringify({
           msg_type: 'tts', enabled: ttsEnabled
       }));
       const frame = new Uint8Array(1 + ctrl.length);
       frame[0] = TAG_TTS_CTRL;
       frame.set(ctrl, 1);
       ws.send(frame);
   });
   ```

5. **Voice picker** (optional, Phase 4b):
   - Add `GET /api/tts/voices` endpoint that lists available Piper models in `voices_dir`
   - Dropdown in session picker or a small menu on long-press of the TTS button
   - Sends voice name in the `0x03` control message

### Phase 5: Input echo suppression

The hardest part — distinguishing "response" from "input echo" in raw PTY output.

**Approach: track what the user types and suppress it.**

1. In Task 3 (WebSocket → PTY write), also copy every written byte into a ring buffer (`recent_input`)
2. In the TTS buffer, compare incoming text against `recent_input` — if a line matches something recently typed, skip it
3. Also skip common prompt patterns via configurable regex in `config.toml`:
   ```toml
   [tts]
   skip_patterns = [
       "^\\$\\s",
       "^❯\\s",
       "^\\w+@\\w+:",
       "^claude-[0-9]",
   ]
   ```
4. For Claude Code specifically: skip lines starting with `╭`, `╰`, `─` and other box-drawing chars used for UI chrome

## New Dependencies (Cargo.toml)

```toml
strip-ansi-escapes = "0.2"   # ANSI code stripping
regex = "1"                   # prompt pattern matching
```

Audio encoding: for v1, shell out to `opusenc` or `ffmpeg` to convert raw PCM to OGG. Avoids pulling in audio codec crates. Can optimize later with native encoding if needed.

## File Changes Summary

| File | Change |
|------|--------|
| `src/tts.rs` | **New** — ANSI stripping, TtsBuffer, PiperSynthesizer |
| `src/ws.rs` | Add TTS control handling, Task 4 (TTS worker), feed PTY output to TTS buffer |
| `src/config.rs` | Add `TtsConfig` struct, parse `[tts]` section |
| `src/main.rs` | Register TTS config, initialize Piper on startup |
| `static/terminal.js` | Audio queue, playback, TTS toggle, voice picker |
| `static/index.html` | TTS button in key-bar |
| `static/terminal.css` | Style for TTS button active state |
| `Cargo.toml` | Add `strip-ansi-escapes`, `regex` |
| `config.toml` | Add `[tts]` section |

## Build Order

1. Phase 1 first — get Piper working standalone on the server
2. Phase 2 — `tts.rs` module, unit-testable independently
3. Phase 3 — wire into WebSocket bridge
4. Phase 4 — client-side playback
5. Phase 5 — input echo suppression (iterative, tune skip patterns over time)

Phase 2 and Phase 4 can be developed in parallel since they're server and client respectively.

## Testing

- `cargo test -p tmuxwrapper` for ANSI stripping and buffer logic
- Manual test: enable TTS, type `echo "hello world"` in terminal, verify only "hello world" is spoken (not the command or prompt)
- Test on iOS Safari PWA specifically — audio playback autoplay restrictions
- Test with long Claude responses — verify streaming chunks play sequentially without gaps or overlap
