# Hackathon submission copy

## Project title
PhishLens — AI-Powered Phishing Detection and Explanation

## One-line summary
An open-source defensive AI assistant that analyzes suspicious email/SMS text, explains social-engineering signals, and recommends safe verification steps without opening links or attachments.

## Problem
Phishing and social engineering often rely on urgency, impersonation, unexpected payment requests, credential harvesting, and unfamiliar links. People may notice a message is unusual but not understand which signals matter or what to do next.

## Solution
PhishLens combines transparent, explainable local heuristics with optional Gemma inference. The heuristics identify visible indicators and compute a triage score. Gemma can provide a contextual explanation, evidence summary, and next-step guidance. The app preserves uncertainty and makes clear that a low score is not proof of safety.

## What is original about the implementation?
- A purpose-built hybrid workflow that keeps the score explainable and uses model inference for contextual narrative.
- Defensive prompt construction that treats the message as untrusted data and tells the model not to follow instructions embedded in it.
- Local-first inference option, opt-in hosted API, and offline fallback.
- A non-invasive design: no automatic URL visits, redirect resolution, mailbox permissions, attachment execution, or user database.
- Synthetic demo inputs, JSON report export, unit tests, test plan, and demo script included in the repository.

## Technology
Python, Streamlit, requests, explainable rule engine, optional Gemma through Ollama or Google's hosted Gemma API.

## How to demonstrate
Launch the app, analyze the synthetic suspicious-bank example, show the risk indicators and extracted URLs (not opened), then compare with the neutral reminder. For an AI-category submission, demonstrate a configured Gemma provider and clearly identify the model and data flow.

## Responsible use
The tool is a prototype and triage aid, not a production security verdict. Hosted inference sends message text to a remote service; use only synthetic or explicitly approved data. All demo samples are synthetic.

## Category fit
- **Defend with Intelligence: AI-Powered Security:** core use case is defensive phishing/social-engineering triage.
- **Best Open-Source AI Project:** the repository is MIT-licensed and supports open-weight Gemma inference; judges should be shown the actual Gemma integration running.
- **Best Use of Gemma:** applicable only when Gemma is actively configured and shown in the demo, not when using rules-only fallback.

## Repository checklist before submission
- [ ] Publish the source repository publicly on GitHub.
- [ ] Confirm the MIT license is included.
- [ ] Ensure there are no API keys, `.env` files, company documents, customer data, or confidential materials in the repository.
- [ ] Add a screenshot or short demo video only if captured using synthetic inputs and permitted by event/company policies.
- [ ] Run the tests and include the correct repository URL in the event submission.
