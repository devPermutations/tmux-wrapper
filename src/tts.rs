use std::process::Stdio;
use tracing::error;

/// Split a response into sentence-sized chunks for TTS synthesis.
/// Splits on ". ", "? ", "! ", and double newlines.
pub fn split_sentences(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Paragraph break — flush current
            if !current.trim().is_empty() {
                sentences.push(current.trim().to_string());
                current.clear();
            }
            continue;
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(trimmed);

        // Split on sentence-ending punctuation
        loop {
            let bytes = current.as_bytes();
            let mut split_at = None;
            for i in 0..bytes.len().saturating_sub(1) {
                if (bytes[i] == b'.' || bytes[i] == b'?' || bytes[i] == b'!')
                    && bytes[i + 1] == b' '
                    && i >= 20
                {
                    split_at = Some(i + 1);
                    break;
                }
            }
            match split_at {
                Some(pos) => {
                    let sentence = current[..pos].trim().to_string();
                    current = current[pos..].trim_start().to_string();
                    if !sentence.is_empty() {
                        sentences.push(sentence);
                    }
                }
                None => break,
            }
        }
    }

    // Flush remainder
    let remainder = current.trim().to_string();
    if !remainder.is_empty() {
        sentences.push(remainder);
    }

    sentences
}

/// Synthesizes text to OGG/Opus audio using Piper + ffmpeg.
pub struct PiperSynthesizer {
    piper_binary: String,
    model_path: String,
}

impl PiperSynthesizer {
    pub fn new(piper_binary: &str, voices_dir: &str, voice: &str) -> Self {
        let model_path = format!("{}/{}.onnx", voices_dir, voice);
        Self {
            piper_binary: piper_binary.to_string(),
            model_path,
        }
    }

    /// Synthesize text to OGG/Opus audio bytes.
    pub async fn speak(&self, text: String) -> Option<Vec<u8>> {
        let piper_binary = self.piper_binary.clone();
        let model_path = self.model_path.clone();

        tokio::task::spawn_blocking(move || {
            Self::speak_blocking(&piper_binary, &model_path, &text)
        })
        .await
        .ok()
        .flatten()
    }

    fn speak_blocking(piper_binary: &str, model_path: &str, text: &str) -> Option<Vec<u8>> {
        use std::process::Command as StdCommand;

        let mut piper = StdCommand::new(piper_binary)
            .args(["--model", model_path, "--output_raw"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| error!(error = %e, "failed to spawn piper"))
            .ok()?;

        if let Some(mut stdin) = piper.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        }

        let piper_stdout = piper.stdout.take()?;

        let ffmpeg = StdCommand::new("/usr/bin/ffmpeg")
            .args([
                "-f", "s16le",
                "-ar", "22050",
                "-ac", "1",
                "-i", "pipe:0",
                "-c:a", "libopus",
                "-b:a", "24k",
                "-application", "voip",
                "-f", "ogg",
                "pipe:1",
            ])
            .stdin(piper_stdout)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| error!(error = %e, "failed to spawn ffmpeg"))
            .ok()?;

        let output = ffmpeg
            .wait_with_output()
            .map_err(|e| error!(error = %e, "ffmpeg failed"))
            .ok()?;

        let _ = piper.wait();

        if output.status.success() && !output.stdout.is_empty() {
            Some(output.stdout)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_sentences_basic() {
        let text = "This is a longer first sentence. This is a second sentence that is also long enough.";
        let sentences = split_sentences(text);
        assert!(sentences.len() >= 2);
    }

    #[test]
    fn test_split_sentences_paragraphs() {
        let text = "First paragraph content here.\n\nSecond paragraph content here.";
        let sentences = split_sentences(text);
        assert_eq!(sentences.len(), 2);
    }

    #[test]
    fn test_split_sentences_short_text() {
        let text = "Short.";
        let sentences = split_sentences(text);
        assert_eq!(sentences.len(), 1);
        assert_eq!(sentences[0], "Short.");
    }
}
