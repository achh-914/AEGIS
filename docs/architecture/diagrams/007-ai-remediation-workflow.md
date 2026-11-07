# 007: AI remediation workflow

Status: PLANNED (not implemented, see ADR-0006)

```mermaid
flowchart LR
    G["Graph evidence"] --> AI["AI explanation (optional)"]
    AI --> H["Human review"]
    H --> P["Patch applied by the user"]
```

AI would only explain evidence the graph already contains.
It would never change findings or apply changes by itself.
