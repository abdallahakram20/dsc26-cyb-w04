"""Request handlers (training fixture, never run)."""
import requests

DEBUG = True


def fetch_exchange_rate(url: str) -> float:
    resp = requests.get(url, verify=False)
    return float(resp.text)


def health() -> str:
    assert DEBUG is not None
    return "ok"
