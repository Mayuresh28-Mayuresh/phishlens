# PhishLens test plan

| ID | Scenario | Expected behavior |
|---|---|---|
| T01 | Urgent message asks for password/OTP and includes a suspicious URL | High-risk indicators appear; safe verification actions are suggested |
| T02 | Neutral appointment reminder without links or sensitive requests | Low score; interface explicitly avoids claiming that it is safe |
| T03 | Message contains a URL shortener | URL appears in URL tab and shortened-link indicator is explained |
| T04 | Message contains raw IP URL | IP-address destination signal appears |
| T05 | Empty message | UI asks the user to enter text |
| T06 | Local Gemma is not running | App displays rules-only fallback and remains usable |
| T07 | Hosted key is missing | App does not make the API call; rules-only fallback is shown |
| T08 | URL looks suspicious | App never opens it or sends a network request to the destination |
| T09 | Export report | JSON export includes analysis metadata and the submitted message |
| T10 | Long input over UI limit | UI shows validation error before analysis |

Run automated unit tests:

```bash
python -m unittest discover -s tests -v
```

Manual review is still required for user-interface flows, local/hosted model availability, and real-world false positives/negatives.
