import pathlib
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace

from logg_analysator.parser import Hendelse, les
from logg_analysator.regler import analyser, brute_force, umulig_reise
from logg_analysator import rapport

EKS = pathlib.Path(__file__).resolve().parent.parent / "eksempler"


class TestParser(unittest.TestCase):
    def test_authlog(self):
        h = les((EKS / "auth.log").read_text())
        self.assertEqual(len(h), 21)
        self.assertTrue(any(x.ok and x.bruker == "admin" for x in h))

    def test_csv(self):
        h = les((EKS / "innlogginger.csv").read_text())
        self.assertEqual(len(h), 6)
        self.assertEqual(h[2].land, "NG")


class TestRegler(unittest.TestCase):
    def test_eksempel_authlog_gir_forventede_alarmer(self):
        typer = {a.type for a in analyser(les((EKS / "auth.log").read_text()))}
        self.assertEqual(typer, {"brute_force", "password_spraying", "suksess_etter_feil", "utenfor_arbeidstid"})

    def test_hoy_alvor_sorteres_forst(self):
        alarmer = analyser(les((EKS / "auth.log").read_text()))
        self.assertEqual(alarmer[0].alvor, "høy")

    def test_brute_force_krever_tidsvindu(self):
        t = datetime(2026, 1, 1, 12)
        spredt = [Hendelse(t + timedelta(hours=i), "root", "203.0.113.1", False) for i in range(6)]
        self.assertEqual(brute_force(spredt), [])

    def test_umulig_reise_ignorerer_samme_land(self):
        t = datetime(2026, 1, 1, 12)
        h = [Hendelse(t, "a", "1", True, "NO"), Hendelse(t + timedelta(minutes=5), "a", "2", True, "NO")]
        self.assertEqual(umulig_reise(h), [])

    def test_vanlig_trafikk_gir_ingen_alarm(self):
        t = datetime(2026, 1, 1, 9)
        h = [Hendelse(t + timedelta(minutes=i), f"bruker{i}", "192.0.2.1", True, "NO") for i in range(5)]
        self.assertEqual(analyser(h), [])


class FalskKlient:
    def __init__(self):
        self.messages = self

    def create(self, **kw):
        self.kw = kw
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="Sammendrag: …")])


class TestRapport(unittest.TestCase):
    def test_rapport_bruker_alarmene(self):
        alarmer = analyser(les((EKS / "auth.log").read_text()))
        k = FalskKlient()
        self.assertTrue(rapport.lag_rapport(alarmer, 21, klient=k).startswith("Sammendrag"))
        self.assertIn('type="password_spraying"', k.kw["messages"][0]["content"])

    def test_ingen_alarmer_spor_ikke_modellen(self):
        self.assertIn("Ingen mistenkelig", rapport.lag_rapport([], 5, klient=None))


if __name__ == "__main__":
    unittest.main()
