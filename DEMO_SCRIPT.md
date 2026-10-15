# PhishLens — 3-minute demo script

## 0:00–0:20 — Problem
"People receive messages designed to create urgency and trick them into sharing credentials or money. PhishLens helps users slow down, see specific warning signs, and choose safer next steps. It doesn't claim certainty."

## 0:20–1:00 — Suspicious message
1. Open the app and select **Suspicious bank text**.
2. Click **Analyze message**.
3. Show score, risk band, evidence, and safe next steps.
4. Point out that the score comes from transparent local rules and the model only adds an explanation.

## 1:00–1:35 — Explainability and URL handling
1. Open **Detected indicators** and explain urgency, credential request, and URL signals.
2. Open **URLs found**. Emphasize that links are extracted as text; the app never opens them.

## 1:35–2:00 — False-positive discipline
1. Select **Possible legitimate reminder** and analyze.
2. Explain that a low score is not a promise that a message is safe. Users should verify sensitive requests independently.

## 2:00–2:35 — Open AI integration
1. If a local Gemma model is already installed, switch to **Local Gemma via Ollama** and analyze the same synthetic message.
2. Show the model-generated explanation. If a model is not configured, show offline mode and explain that local Gemma is optional for first-run reliability.

## 2:35–3:00 — Responsible design
"PhishLens uses synthetic examples, does not open URLs, does not execute attachments, and avoids mailbox permissions. Hosted AI mode is opt-in because it sends the text to a remote API."

## Judge Q&A points
- **What is AI doing?** Gemma produces a contextual explanation and safer next steps; explainable local rules provide deterministic indicators and the heuristic score.
- **Why not just use a keyword detector?** Rules are transparent and provide a baseline; the model adds contextual summarization, while the app preserves uncertainty and shows evidence.
- **What is the safety design?** No active URL retrieval, file execution, or mailbox access. Prompt-injection-like text is treated as untrusted input.
- **What would be next?** Add URL/domain reputation checks through an approved provider, sender authentication metadata analysis, multilingual testing, and evaluation on a consented labeled dataset.
