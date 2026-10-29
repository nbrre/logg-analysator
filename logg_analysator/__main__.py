"""Kommandolinje: python -m logg_analysator eksempler/auth.log [--uten-ki]"""
from __future__ import annotations

import argparse
import os

from .parser import les
from .regler import analyser

FARGE = {"høy": "\033[31m", "middels": "\033[33m", "lav": "\033[36m"}
NULL = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="logg_analysator", description="Finn mistenkelige innlogginger i logger.")
    p.add_argument("fil", help="auth.log eller CSV med kolonnene tidspunkt,bruker,ip,land,resultat")
    p.add_argument("--uten-ki", action="store_true", help="Ikke lag KI-rapport.")
    a = p.parse_args(argv)

    hendelser = les(open(a.fil, encoding="utf-8", errors="replace").read())
    alarmer = analyser(hendelser)
    print(f"{len(hendelser)} hendelser lest, {len(alarmer)} alarmer.\n")
    for al in alarmer:
        print(f"{FARGE[al.alvor]}[{al.alvor.upper()}]{NULL} {al.type}: {al.beskrivelse}")
        for b in al.bevis:
            print(f"      {b}")
    if a.uten_ki or not alarmer:
        return 0
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("\n(Ingen ANTHROPIC_API_KEY – hopper over KI-rapporten. Se README.)")
        return 0
    from .rapport import lag_rapport

    print("\n" + "=" * 60 + "\nHENDELSESRAPPORT (Claude)\n" + "=" * 60)
    print(lag_rapport(alarmer, len(hendelser)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
