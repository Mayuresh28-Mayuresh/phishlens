# PhishLens 🛡️

**AI-powered phishing detection and explanation** — an open-source defensive-security hackathon prototype for reviewing suspicious emails, SMS messages, and chat text.

PhishLens combines an explainable local rule engine with optional Google Gemma inference. Its purpose is to help users pause, understand risk indicators, and verify requests through trusted channels. It is **not** a definitive phishing verdict or a replacement for security tooling.

## Features

- Streamlit web UI with synthetic sample messages.
- Explainable 0–100 heuristic score and Low / Medium / High triage bands.
- Indicators for credential requests, urgency, financial lures, attachment instructions, suspicious URL structure, shortened links, IP-address links, punycode, and possible brand/domain mismatch.
- Optional **local Gemma** integration through Ollama.
- Optional **hosted Gemma API** integration.
- Offline rules-only mode; no API key or model is required for a demo.
- Downloadable JSON report and automated unit tests.
- Privacy-aware: no accounts, analytics, database, automatic link browsing, or attachment execution.

## Architecture

```text
User-provided message
        |
        v
Input validation + URL extraction
        |
        v
Explainable heuristic rules -----> risk score + indicator list
        |                                      |
        +---------> Local Gemma / Hosted Gemma -+----> explanation + safe actions
                                               |
                                               v
                                Streamlit report + JSON export
```

The heuristic score is calculated locally and is **not** replaced by the model's opinion. Model-generated text is treated as explanatory assistance only.

## Requirements

- Python 3.10 or newer recommended.
- For the simplest demo: Python packages in `requirements.txt`.
- Optional local inference: [Ollama](https://ollama.com/) plus a Gemma model supported by your installed Ollama version.
- Optional hosted inference: an API key for a supported Gemma model. Check [Google's current Gemma API guide](https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api) for currently supported model IDs.

## Run the offline demo

### Windows PowerShell

```powershell
cd phishlens
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux

```bash
cd phishlens
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Streamlit normally opens a local browser tab. Select a sample, click **Analyze message**, and inspect the result. Offline mode requires no model download or API key.

## Enable local Gemma (recommended for privacy)

1. Install Ollama only on a device where you are authorized to install software.
2. Choose a Gemma model supported by your Ollama version and hardware.
3. Pull the model using the exact tag shown by your Ollama model library (for example, `ollama pull gemma4:e2b` if that tag is available to your installation).
4. Start Ollama and confirm its local service is available at `http://localhost:11434`.
5. Launch PhishLens, then choose **Local Gemma via Ollama** in the sidebar. Enter the exact installed model tag if different.

If the model is unavailable, the app shows a rules-only fallback instead of crashing. To change the endpoint, set `PHISHLENS_OLLAMA_URL`.

> Local inference keeps message text on the local machine only if Ollama is actually running locally and no other proxy/remote endpoint is configured. Follow your organization's software and data policies.

## Enable hosted Gemma API

1. Create an API key through an official Google AI developer console account, if permitted.
2. Set it as an environment variable instead of committing it into source code.

PowerShell for the current terminal:

```powershell
$env:GEMMA_API_KEY = "YOUR_KEY_HERE"
streamlit run app.py
```

macOS / Linux:

```bash
export GEMMA_API_KEY="YOUR_KEY_HERE"
streamlit run app.py
```

In the sidebar select **Hosted Gemma API** and provide the supported model ID. The default in the UI is illustrative and may need updating to a model currently available to your key/account. Check the official docs above. **Hosted mode sends the pasted message to a remote provider. Never use company messages, customer data, secrets, or confidential content unless you have explicit authorization and have reviewed the provider's data handling terms.**

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Example demo inputs

- **Suspicious bank text:** urgency + account verification + OTP + suspicious destination.
- **Suspicious delivery notice:** shortened URL + payment urgency.
- **Possible legitimate reminder:** neutral appointment reminder; low score must not be described as proof of safety.
- **Prize lure:** unexpected prize + request for sensitive data.

All built-in examples are synthetic and use reserved/example domains. No real messages are needed for the demonstration.

## Security and privacy design

- Never automatically opens, fetches, resolves, or follows URLs.
- Never executes attachments, scripts, or macros.
- Does not store messages in a database or write them to disk by default.
- The optional JSON export contains the submitted message; users must choose when and where to save it.
- Hosted Gemma mode forwards the text to an API; the app displays a warning before use.
- The model prompt explicitly treats the provided message as untrusted data and asks the model not to follow instructions embedded within it.
- Heuristic findings are explanations, not proof. Attackers can evade rules; legitimate messages can trigger false positives.

## Scope and known limitations

- Only analyzes pasted text; it does not read mailboxes or SMS accounts.
- Does not verify sender SPF/DKIM/DMARC, inspect HTML rendering, expand short links, browse websites, scan files, or check live threat-intelligence feeds.
- The risk score is a hand-tuned heuristic, not a calibrated probability.
- AI may make mistakes or produce incorrect explanations. Confirm significant findings with trusted security processes.
- Designed as a demonstration and starting point, not production security software.

## Suggested GitHub repository description

`Open-source defensive AI prototype that explains phishing indicators in messages using transparent heuristics and optional local/hosted Gemma inference.`

## License

Released under the MIT License. Model weights and hosted API services have their own licenses and terms; review them separately.
