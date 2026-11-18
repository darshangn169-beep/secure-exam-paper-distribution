"""
app.py
------
Secure Exam Paper Distribution System
CNS Mini Project (VTU 7th Sem)

Flow:
  ADMIN uploads a question paper for a specific Exam Center + exam datetime
    1. AES-256 encrypts the PDF                         (confidentiality)
    2. RSA encrypts the AES key with the center's public key   (key exchange)
    3. SHA-256 hashes the original PDF                   (integrity)
    4. Admin signs the hash with their RSA private key   (authenticity)

  EXAM CENTER logs in and sees assigned papers
    - Cannot decrypt before the scheduled exam_datetime  (time-lock access control)
    - On decrypt: RSA-decrypts AES key with own private key, AES-decrypts PDF,
      then verifies the admin's signature. If verification fails -> rejected
      (paper tampered / not authentic), even if decryption "succeeds".
"""

import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, flash
)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from database import init_db, get_db, log_access
import crypto_utils as cu

app = Flask(__name__)
app.secret_key = "cns-mini-project-secret-key-change-me"

UPLOAD_DIR = "uploads"
ENC_DIR = "encrypted"
KEYS_DIR = "keys"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(ENC_DIR, exist_ok=True)


def load_key(entity, kind):
    """kind = 'public' or 'private'"""
    path = os.path.join(KEYS_DIR, f"{entity}_{kind}.pem")
    with open(path, "rb") as f:
        return f.read()


def current_user():
    if "username" not in session:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()
    conn.close()
    return user


# ---------------- AUTH ----------------

@app.route("/")
def index():
    if "username" in session:
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("center_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["entity_key"] = user["entity_key"]
            flash(f"Welcome, {username} ({user['role']})", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- ADMIN ----------------

@app.route("/admin/dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    papers = conn.execute(
        "SELECT * FROM papers WHERE uploaded_by = ? ORDER BY id DESC", (session["username"],)
    ).fetchall()
    centers = conn.execute("SELECT username FROM users WHERE role = 'center'").fetchall()
    conn.close()

    return render_template("admin_dashboard.html", papers=papers, centers=centers)


@app.route("/admin/upload", methods=["POST"])
def admin_upload():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    title = request.form["title"].strip()
    subject = request.form["subject"].strip()
    center_username = request.form["center"]
    exam_datetime = request.form["exam_datetime"]   # e.g. 2026-09-05T10:00
    pdf_file = request.files["paper"]

    if not pdf_file or pdf_file.filename == "":
        flash("Please choose a PDF file", "danger")
        return redirect(url_for("admin_dashboard"))

    filename = secure_filename(pdf_file.filename)
    plaintext = pdf_file.read()

    # 1. AES-256 encrypt the paper
    ciphertext, aes_key, nonce, tag = cu.aes_encrypt(plaintext)

    # 2. RSA encrypt the AES key with the RECEIVING center's public key
    center_pub = load_key(session_entity_for(center_username), "public")
    aes_key_enc = cu.rsa_encrypt(aes_key, center_pub)

    # 3. SHA-256 hash of the ORIGINAL plaintext (integrity reference)
    file_hash_hex = cu.sha256_hexdigest(plaintext)

    # 4. Admin signs the hash of the plaintext with their OWN private key
    admin_priv = load_key("admin", "private")
    signature = cu.sign_data(plaintext, admin_priv)

    # Save encrypted file to disk (uuid4 guarantees no collisions even for
    # uploads happening within the same second)
    import uuid
    enc_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}_{filename}.enc"
    enc_path = os.path.join(ENC_DIR, enc_filename)
    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    conn = get_db()
    conn.execute("""
        INSERT INTO papers
        (title, subject, original_filename, enc_file_path, aes_key_enc, nonce, tag,
         signature, sha256_hash, exam_datetime, uploaded_by, center_username, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        title, subject, filename, enc_path, aes_key_enc, nonce, tag,
        signature, file_hash_hex, exam_datetime, session["username"], center_username,
        datetime.now().isoformat(timespec="seconds")
    ))
    conn.commit()
    conn.close()

    flash(f"Paper '{title}' encrypted (AES-256 + RSA) and dispatched to {center_username}.", "success")
    return redirect(url_for("admin_dashboard"))


def session_entity_for(username):
    conn = get_db()
    row = conn.execute("SELECT entity_key FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row["entity_key"]


# ---------------- EXAM CENTER ----------------

@app.route("/center/dashboard")
def center_dashboard():
    if session.get("role") != "center":
        return redirect(url_for("login"))

    conn = get_db()
    papers = conn.execute(
        "SELECT * FROM papers WHERE center_username = ? ORDER BY id DESC",
        (session["username"],)
    ).fetchall()
    conn.close()

    now = datetime.now()
    paper_status = []
    for p in papers:
        exam_time = datetime.fromisoformat(p["exam_datetime"])
        unlocked = now >= exam_time
        paper_status.append((p, unlocked, exam_time))

    return render_template("center_dashboard.html", paper_status=paper_status, now=now)


@app.route("/center/decrypt/<int:paper_id>")
def center_decrypt(paper_id):
    if session.get("role") != "center":
        return redirect(url_for("login"))

    conn = get_db()
    paper = conn.execute("SELECT * FROM papers WHERE id = ?", (paper_id,)).fetchone()
    conn.close()

    if not paper or paper["center_username"] != session["username"]:
        flash("Paper not found or not assigned to you.", "danger")
        return redirect(url_for("center_dashboard"))

    ts = datetime.now().isoformat(timespec="seconds")

    # ---- TIME-LOCK CHECK ----
    exam_time = datetime.fromisoformat(paper["exam_datetime"])
    if datetime.now() < exam_time:
        reason = f"Locked until {paper['exam_datetime']}"
        log_access(paper_id, session["username"], "decrypt_attempt", "failure", reason, ts)
        flash(f"⛔ Access denied: {reason}", "danger")
        return redirect(url_for("center_dashboard"))

    try:
        # ---- Step 1: RSA-decrypt the AES key using center's OWN private key ----
        center_priv = load_key(session["entity_key"], "private")
        aes_key = cu.rsa_decrypt(paper["aes_key_enc"], center_priv)

        # ---- Step 2: AES-decrypt the paper ----
        with open(paper["enc_file_path"], "rb") as f:
            ciphertext = f.read()
        plaintext = cu.aes_decrypt(ciphertext, aes_key, paper["nonce"], paper["tag"])

        # ---- Step 3: Verify admin's digital signature (authenticity + tamper check) ----
        admin_pub = load_key("admin", "public")
        valid = cu.verify_signature(plaintext, paper["signature"], admin_pub)

        if not valid:
            log_access(paper_id, session["username"], "decrypt_attempt", "failure",
                       "Signature verification FAILED - possible tampering", ts)
            flash("⚠️ SECURITY ALERT: Signature verification failed. File may be tampered. Download blocked.", "danger")
            return redirect(url_for("center_dashboard"))

        # ---- Step 4: Double-check integrity hash matches ----
        computed_hash = cu.sha256_hexdigest(plaintext)
        if computed_hash != paper["sha256_hash"]:
            log_access(paper_id, session["username"], "decrypt_attempt", "failure",
                       "SHA-256 hash mismatch", ts)
            flash("⚠️ Integrity check failed. File corrupted or altered.", "danger")
            return redirect(url_for("center_dashboard"))

        # Success — write decrypted file temporarily and serve it
        out_path = os.path.join(UPLOAD_DIR, f"decrypted_{paper_id}_{paper['original_filename']}")
        with open(out_path, "wb") as f:
            f.write(plaintext)

        log_access(paper_id, session["username"], "decrypt_attempt", "success",
                   "Signature verified, integrity OK", ts)

        return send_file(out_path, as_attachment=True, download_name=paper["original_filename"])

    except Exception as e:
        log_access(paper_id, session["username"], "decrypt_attempt", "failure", str(e), ts)
        flash(f"Decryption failed: {e}", "danger")
        return redirect(url_for("center_dashboard"))


# ---------------- AUDIT LOG (visible to admin) ----------------

@app.route("/admin/logs")
def admin_logs():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_db()
    logs = conn.execute("""
        SELECT access_logs.*, papers.title FROM access_logs
        JOIN papers ON access_logs.paper_id = papers.id
        ORDER BY access_logs.id DESC
    """).fetchall()
    conn.close()
    return render_template("logs.html", logs=logs)


if __name__ == "__main__":
    init_db()
    if not os.path.exists(os.path.join(KEYS_DIR, "admin_private.pem")):
        print("\n[!] No keys found. Run `python keygen.py` first.\n")
    app.run(debug=True, port=5000)
