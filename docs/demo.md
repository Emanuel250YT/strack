# Quick demo (about 3 minutes)

Everything runs on one machine with fictitious data. Nothing real is blocked.

## Start

```powershell
powershell -ExecutionPolicy Bypass -File scripts/demo.ps1            # one match at 6x (17.5 min)
powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 -Speed 10  # faster
powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 -TwoMatches
```

It builds the release binary, starts with fresh state in `var/demo/` and runs:

| What | Where |
|---|---|
| Strack | http://127.0.0.1:3000 |
| Challenge simulator (match 1; match 2 with `-TwoMatches`) | http://127.0.0.1:8090 (8091) |
| Demo licensed platform, TV Ficticia Play (synthetic picture, no third-party footage) | http://127.0.0.1:8100 |
| Demo pirate site restreaming three subscriber accounts | http://127.0.0.1:8200 |

The challenge repository is expected in `var/challenge/` (pass `-Challenge <folder>` otherwise).
Stop everything with `scripts/demo-stop.ps1`; the state stays in `var/demo/` for review.

| User | Password | Role |
|---|---|---|
| `laura` | `laura-demo-2026` | Judge on duty until minute 50 |
| `martin` | `martin-demo-2026` | Judge from minute 50 |
| `fiscalia` | `fiscalia-demo-2026` | Operations (loads pirate sites) |
| `tvf` | `tvf-demo-2026` | TV Ficticia Play's portal |
| `admin` | `admin-demo-2026` | Administration |

Use two browser windows (or a phone for the judge): one signed in as `laura`, one as `fiscalia`.
The theme switch in the top bar picks light or dark.

## Walkthrough

1. **0:00 · Transparencia** (http://127.0.0.1:3000). The public page: the live match in the bar,
   nothing blocked yet. "Ingresar" opens the sign-in screen.
2. **0:20 · The judge.** Sign in as `laura`. Cases arrive in the inbox within seconds of each
   detection (minutes 2, 6, 9 of the match). Open one: "Qué se verificó" says in plain words that
   it is the official signal, which server delivers it and whether the IP is shared. "Qué se pide"
   on the right says what will be blocked and until when. **Aprobar y firmar.**
3. **0:50 · Operations.** As `fiscalia`, **Operaciones**: the ring of cases fills, the bars per
   provider grow as each one confirms, "Tiempo a bloqueo" shows the minutes from detection to the
   first confirmed block. Open a case: the orders, each provider's confirmation, the audit trail.
4. **1:30 · Going after the source.** **Cargar sitios**: paste `http://127.0.0.1:8200/`, the
   pirate's page, and tick "Rastrear también la cuenta de origen". Strack finds the video in the page,
   reads the invisible mark, identifies the subscriber account and tells the platform, which suspends
   it. The pirate switches accounts; each one falls the same way (**Rastreo de origen** shows it live).
5. **2:10 · The client's view.** Sign in as `tvf`: the portal lists the accounts found leaking and
   suspended, with the cut time. **Guía de integración** shows what a platform installs.
6. **2:30 · Close.** Back on **Transparencia**: every block with the judge who ordered it and until
   when it holds; IP blocks end by themselves with the match. Optional, in a terminal:

   ```powershell
   target/release/strack.exe verify --audit var/demo/var/audit.jsonl
   python -X utf8 var/challenge/evaluacion/verificar.py --log var/demo/match-1.jsonl
   ```

## Tips

- At 6x the shift change (minute 50) comes about 8 minutes in: pending work moves to `martin`.
- To show the platform side, open http://127.0.0.1:8100/admin (`personal` / `personal-demo-2026`):
  the suspended accounts and the notices Strack sent. "Reiniciar la demo" there reactivates them.
- `-TwoMatches` shows two matches at once: the operations page lists both, the judge's inbox merges
  them.
