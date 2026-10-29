# 🔎 Logg-analysator

Finner **mistenkelige innlogginger** i logger – brute force, password spraying, umulig reise
og mer – og lager en **hendelsesrapport på norsk med Claude**, slik en SOC-analytiker ville
skrevet den for IT-ansvarlig i en småbedrift.

*Detects suspicious sign-ins (brute force, password spraying, impossible travel …) in SSH and
sign-in logs, then uses Claude to write an incident report. Text is in Norwegian.*

![Tester](../../actions/workflows/tester.yml/badge.svg)

## Hva den oppdager

| Regel | Alvor | Hva det betyr |
|---|---|---|
| `password_spraying` | Høy | Én IP prøver mange ulike brukernavn |
| `suksess_etter_feil` | Høy | Vellykket innlogging rett etter flere feil – passordet kan være gjettet |
| `umulig_reise` | Høy | Samme bruker logger inn fra to land på kortere tid enn det går an å reise |
| `brute_force` | Middels | Mange feil mot samme bruker fra samme IP innen 10 minutter |
| `utenfor_arbeidstid` | Lav | Admin/root logger inn midt på natten |

## Hvordan det fungerer

```
auth.log / CSV ──► parser ──► felles hendelser ──► deteksjonsregler ──► alarmer ──► Claude ──► rapport
```

- **Parser** (`logg_analysator/parser.py`): leser Linux `auth.log` (sshd) og CSV-eksport av
  innlogginger, for eksempel fra Microsoft Entra ID.
- **Regler** (`logg_analysator/regler.py`): ren Python, tester mønstre i tidsvinduer.
  Terskler og vinduer kan justeres.
- **Rapport** (`logg_analysator/rapport.py`): bare alarmene og bevislinjene sendes til Claude –
  ikke hele loggen. Det holder kostnaden nede og begrenser hvor mye data som deles.

## Kom i gang

```bash
git clone https://github.com/nbrre/logg-analysator.git
cd logg-analysator
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...                  # Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."

python -m logg_analysator eksempler/auth.log
python -m logg_analysator eksempler/innlogginger.csv --uten-ki
streamlit run app.py
```

## Eksempel

```
$ python -m logg_analysator eksempler/auth.log --uten-ki
21 hendelser lest, 4 alarmer.

[HØY] password_spraying: 198.51.100.77 prøvde 6 ulike brukere: admin, git, oracle, postgres, test, ubuntu.
[HØY] suksess_etter_feil: «admin» logget inn fra 203.0.113.99 etter 4 feilede forsøk – passordet kan være gjettet.
[MIDDELS] brute_force: 8 feilede innlogginger mot «root» fra 203.0.113.45 på under 10 min.
[LAV] utenfor_arbeidstid: Privilegert konto «admin» logget inn kl. 23:43.
```

Eksempelloggene er laget for prosjektet og bruker IP-adresser reservert for dokumentasjon
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Tester

```bash
python -m unittest -v
```

## Videre arbeid

- Slå opp IP-adresser mot trusselinformasjon (f.eks. AbuseIPDB)
- Støtte for Windows Event Log (4624/4625) og webserverlogger
- Sende alarmer til Teams/Slack

## Om meg

Laget av **Barre**, bachelor i informasjonsteknologi/informasjonssikkerhet.

Lisens: MIT
