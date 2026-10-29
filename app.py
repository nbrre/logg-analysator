"""Nettside for logg-analysatoren. Start med:  streamlit run app.py"""
import os

import streamlit as st

from logg_analysator.parser import les
from logg_analysator.regler import analyser

st.set_page_config(page_title="Logg-analysator", page_icon="🔎")
st.title("🔎 Logg-analysator")
st.write("Last opp en `auth.log` (Linux/SSH) eller en CSV med innlogginger (tidspunkt, bruker, ip, land, resultat).")

fil = st.file_uploader("Loggfil", type=["log", "txt", "csv"])
if fil:
    hendelser = les(fil.getvalue().decode("utf-8", "replace"))
    alarmer = analyser(hendelser)
    st.metric("Hendelser", len(hendelser))
    st.metric("Alarmer", len(alarmer))
    ikon = {"høy": "🔴", "middels": "🟠", "lav": "🔵"}
    for a in alarmer:
        with st.expander(f"{ikon[a.alvor]} {a.type} – {a.beskrivelse}"):
            st.code("\n".join(a.bevis))
    if alarmer and os.getenv("ANTHROPIC_API_KEY") and st.button("Lag hendelsesrapport med Claude", type="primary"):
        from logg_analysator.rapport import lag_rapport

        with st.spinner("Claude skriver rapporten …"):
            st.markdown(lag_rapport(alarmer, len(hendelser)))
