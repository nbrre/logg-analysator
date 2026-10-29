"""Deteksjonsregler – samme typer mønstre som et SOC ser etter."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .parser import Hendelse


@dataclass
class Alarm:
    type: str
    alvor: str  # lav / middels / høy
    beskrivelse: str
    bevis: list[str]


def _fmt(h: Hendelse) -> str:
    return f"{h.tid:%Y-%m-%d %H:%M:%S} {'OK ' if h.ok else 'FEIL'} {h.bruker} fra {h.ip}{' (' + h.land + ')' if h.land else ''}"


def brute_force(hendelser: list[Hendelse], grense: int = 5, vindu: timedelta = timedelta(minutes=10)) -> list[Alarm]:
    """Mange feilede forsøk fra samme IP mot samme bruker på kort tid."""
    alarmer, grupper = [], defaultdict(list)
    for h in hendelser:
        if not h.ok:
            grupper[(h.ip, h.bruker)].append(h)
    for (ip, bruker), liste in grupper.items():
        for i in range(len(liste)):
            innen = [h for h in liste[i:] if h.tid - liste[i].tid <= vindu]
            if len(innen) >= grense:
                alarmer.append(Alarm("brute_force", "middels",
                                     f"{len(innen)} feilede innlogginger mot «{bruker}» fra {ip} på under {int(vindu.total_seconds() // 60)} min.",
                                     [_fmt(h) for h in innen[:5]]))
                break
    return alarmer


def password_spraying(hendelser: list[Hendelse], grense: int = 4) -> list[Alarm]:
    """Én IP prøver mange forskjellige brukere."""
    per_ip = defaultdict(set)
    eks = defaultdict(list)
    for h in hendelser:
        if not h.ok:
            per_ip[h.ip].add(h.bruker)
            eks[h.ip].append(h)
    return [Alarm("password_spraying", "høy",
                  f"{ip} prøvde {len(brukere)} ulike brukere: {', '.join(sorted(brukere)[:6])}.",
                  [_fmt(h) for h in eks[ip][:5]])
            for ip, brukere in per_ip.items() if len(brukere) >= grense]


def suksess_etter_feil(hendelser: list[Hendelse], grense: int = 3) -> list[Alarm]:
    """Vellykket innlogging rett etter flere feil – mulig gjettet passord."""
    alarmer, feil = [], defaultdict(list)
    for h in hendelser:
        nokkel = (h.ip, h.bruker)
        if not h.ok:
            feil[nokkel].append(h)
        else:
            if len(feil[nokkel]) >= grense:
                alarmer.append(Alarm("suksess_etter_feil", "høy",
                                     f"«{h.bruker}» logget inn fra {h.ip} etter {len(feil[nokkel])} feilede forsøk – passordet kan være gjettet.",
                                     [_fmt(x) for x in feil[nokkel][-3:]] + [_fmt(h)]))
            feil[nokkel] = []
    return alarmer


def umulig_reise(hendelser: list[Hendelse], vindu: timedelta = timedelta(hours=2)) -> list[Alarm]:
    """Samme bruker logger inn fra to land på kortere tid enn det er mulig å reise."""
    alarmer, siste = [], {}
    for h in hendelser:
        if not (h.ok and h.land):
            continue
        forrige = siste.get(h.bruker)
        if forrige and forrige.land != h.land and h.tid - forrige.tid <= vindu:
            alarmer.append(Alarm("umulig_reise", "høy",
                                 f"«{h.bruker}» logget inn fra {forrige.land} og {h.land} med bare {int((h.tid - forrige.tid).total_seconds() // 60)} min mellom.",
                                 [_fmt(forrige), _fmt(h)]))
        siste[h.bruker] = h
    return alarmer


def utenfor_arbeidstid(hendelser: list[Hendelse], fra: int = 6, til: int = 22, kontoer=("admin", "root", "administrator")) -> list[Alarm]:
    """Vellykket innlogging på privilegerte kontoer midt på natten."""
    treff = [h for h in hendelser if h.ok and h.bruker in kontoer and not (fra <= h.tid.hour < til)]
    return [Alarm("utenfor_arbeidstid", "lav",
                  f"Privilegert konto «{h.bruker}» logget inn kl. {h.tid:%H:%M}.", [_fmt(h)]) for h in treff]


ALLE = [brute_force, password_spraying, suksess_etter_feil, umulig_reise, utenfor_arbeidstid]


def analyser(hendelser: list[Hendelse]) -> list[Alarm]:
    alarmer = [a for regel in ALLE for a in regel(hendelser)]
    rang = {"høy": 0, "middels": 1, "lav": 2}
    return sorted(alarmer, key=lambda a: rang[a.alvor])
