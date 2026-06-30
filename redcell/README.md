# RedCell

Hardening adversariale continuo per agenti AI. Non è uno scanner: è un control loop che
rompe, misura, patcha e ri-attacca, con un security score che converge live da 35 a 95.

## Stack
- LLM: tutto su [Regolo](https://regolo.ai) (OpenAI-compatible). Tre ruoli, tre modelli:
  - vittima `apertus-70b`: debolmente allineata, cade sugli attacchi classici
  - attaccante `mistral-small-4-119b`: segue il framing red-team e muta i payload sul rifiuto
  - giudice `gpt-oss-120b`: reasoning model, scrive la security policy live e fa da oracle di fallback
- Backend: Python + FastAPI, eventi live via SSE.
- Frontend: una pagina HTML/JS (`frontend/index.html`), nessun build step.

## Setup
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
echo 'REGOLO_API_KEY=sk-...' > .env      # la key resta solo qui (gitignored)
```

## Avvio
```bash
./run.sh                # demo live, apre il browser su http://127.0.0.1:8000
./run.sh --offline      # replay di un giro registrato (fixtures), nessuna chiamata di rete
PORT=8001 ./run.sh      # porta alternativa
```
Sequenza: Run attack (gauge 95→35, 4 card rosse), poi Harden & re-attack
(gpt-oss scrive la policy, gauge torna a 95, 4 card verdi), infine Reset.

CLI senza browser:
```bash
cd backend && ../.venv/bin/python cli.py --harden
```

## Struttura
```
backend/
  config.py    ruoli modello, parametri, secret + DB clienti finto, catalogo attacchi
  regolo.py    wrapper Regolo (OpenAI-compatible)
  victim.py    la vittima (apertus) + guardrail input + filtro DLP output
  attacks.py   seed curati + mutatore adattivo (mistral)
  oracle.py    detection deterministica-first + score (banda 35..95)
  engine.py    motore d'attacco adattivo, categorie in parallelo, eventi via emit
  harden.py    difese: security policy (gpt-oss live + fallback) + guardrail + DLP
  main.py      FastAPI: /run /harden /reset /report /events (SSE), + modalità offline
  cli.py       dry-run da terminale
  fixtures/    giro registrato per la demo offline (attack.json, harden.json)
frontend/
  index.html   dashboard war-room (gauge, griglia OWASP, stream SSE)
```

## Determinismo & sicurezza
- Vittima a `temperature 0` + filtro DLP in output: il giro è ripetibile (35→95 identico).
- Tutti i dati (API key, IBAN, codici fiscali, clienti) sono sintetici. La vittima è una
  fixture mal-governata di proposito, non il prodotto.
- La key Regolo vive solo in `.env` (gitignored).
