"""Leser innloggingslogger til en felles struktur.

Støtter
- Linux auth.log (sshd: «Failed password» / «Accepted password|publickey»)
- CSV-eksport av innlogginger (f.eks. fra Microsoft Entra ID) med kolonnene
  tidspunkt, bruker, ip, land, resultat
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Hendelse:
    tid: datetime
    bruker: str
    ip: str
    ok: bool
    land: str = ""


SSHD = re.compile(
    r"^(?P<mnd>\w{3})\s+(?P<dag>\d{1,2})\s(?P<kl>\d\d:\d\d:\d\d)\s\S+\ssshd\[\d+\]:\s"
    r"(?P<status>Failed|Accepted)\s\S+\sfor\s(?:invalid user\s)?(?P<bruker>\S+)\sfrom\s(?P<ip>[\d.a-fA-F:]+)"
)


def les_authlog(tekst: str, aar: int = 2026) -> list[Hendelse]:
    ut = []
    for linje in tekst.splitlines():
        m = SSHD.search(linje)
        if not m:
            continue
        tid = datetime.strptime(f"{aar} {m['mnd']} {m['dag']} {m['kl']}", "%Y %b %d %H:%M:%S")
        ut.append(Hendelse(tid, m["bruker"], m["ip"], m["status"] == "Accepted"))
    return ut


def les_csv(tekst: str) -> list[Hendelse]:
    ut = []
    for rad in csv.DictReader(io.StringIO(tekst)):
        rad = {k.strip().lower(): (v or "").strip() for k, v in rad.items()}
        ut.append(Hendelse(
            tid=datetime.fromisoformat(rad["tidspunkt"]),
            bruker=rad["bruker"].lower(),
            ip=rad["ip"],
            ok=rad["resultat"].lower() in ("ok", "success", "suksess", "vellykket"),
            land=rad.get("land", "").upper(),
        ))
    return ut


def les(tekst: str) -> list[Hendelse]:
    forste = tekst.lstrip().splitlines()[0].lower() if tekst.strip() else ""
    hendelser = les_csv(tekst) if forste.startswith("tidspunkt") else les_authlog(tekst)
    return sorted(hendelser, key=lambda h: h.tid)
