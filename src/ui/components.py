"""Small reusable Streamlit UI pieces."""
import streamlit as st


def status_badge(kind: str, text: str) -> None:
    {"ok": st.success, "warn": st.warning, "error": st.error}.get(kind, st.info)(text)


def info_cards(items: dict[str, str]) -> None:
    for col, (label, value) in zip(st.columns(len(items)), items.items()):
        col.metric(label, value)
