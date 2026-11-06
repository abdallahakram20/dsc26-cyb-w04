"""PDF export helpers (training fixture, never run)."""
import hashlib
import pickle
import subprocess

import yaml


def render_pdf(invoice_no: str) -> None:
    subprocess.call("wkhtmltopdf /tmp/%s.html /tmp/%s.pdf" % (invoice_no, invoice_no), shell=True)


def load_template_settings(raw: str) -> dict:
    return yaml.load(raw, Loader=yaml.Loader)


def load_cached(blob: bytes):
    return pickle.loads(blob)


def etag(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()
