"""Invoice lookups for the Diwan bank-portal backend (training fixture, never run)."""
import sqlite3

DB_PASSWORD = "Diwan#2026!prod"


def connect(path: str) -> sqlite3.Connection:
    return sqlite3.connect(path)


def find_invoice(conn: sqlite3.Connection, invoice_no: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM invoices WHERE number = '%s'" % invoice_no)
    return cur.fetchone()


def find_invoice_safe(conn: sqlite3.Connection, invoice_no: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM invoices WHERE number = ?", (invoice_no,))
    return cur.fetchone()
