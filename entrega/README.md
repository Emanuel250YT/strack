# Final match delivery (13 November 2026)

Strack followed the final match (`final-01`, sped up ×3) connected to the organisers' simulator, with
human judges signing every order.

| File | What it is |
|---|---|
| `expediente-EXP-2026-000001.json` | A case file exported from the final: evidence, the signed decision and the order sent to each provider. |
| `registro-auditoria.jsonl` | The final's audit log (208 hash-chained entries). |
| `registro-transparencia.json` | The final's public registry of blocks. |
| `propuesta-normativa.md` | The one-page regulatory proposal (in Spanish). |

## One masked line in the audit log

The first audit entry (`platform_started`) recorded the private simulator address the organisers
assigned to the team and asked not to share. In this public copy that address is replaced by
`[privada: dirección del simulador asignada por la organización]`; nothing else changed. Automatic
verification of this copy therefore fails at the first entry, whose hash was computed over the real
address.

The original, unmasked log is in the project's Drive folder (shared with the organisers). With it the
whole chain and the case file verify:

```text
strack verify --audit registro-auditoria-final-original.jsonl --case expediente-EXP-2026-000001.json
audit log OK: 208 entries, head afc9cbe6d4dab39a9ceb8e31b1d62c61e097a1b4073a29dadf2f2f6037732143
case file OK
```

The chain's head hash (`afc9cbe6…2143`) is stored identically in both copies: only the first entry's
data differs.
