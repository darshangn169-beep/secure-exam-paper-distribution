# Secure Exam Paper Distribution System
### CNS (Cryptography & Network Security) Mini Project — VTU 7th Sem CSE

A working Flask web app that encrypts and distributes exam question papers
to exam centers using **hybrid encryption (AES + RSA)**, **SHA-256 integrity
checks**, **RSA digital signatures**, and **time-locked access control**.

---

## 1. How it works

**Admin (Question Paper Setter) uploads a paper →**
1. `AES-256 (EAX mode)` encrypts the actual PDF — fast symmetric encryption
   for the bulk data.
2. `RSA-2048` encrypts the AES key using the **receiving exam center's
   public key** — this is the "hybrid encryption" trick real systems use
   (RSA is slow, so it only ever encrypts the small AES key, not the file).
3. `SHA-256` hashes the original PDF for integrity.
4. Admin **signs** the hash with their own RSA **private key** — this proves
   the paper genuinely came from the admin (authenticity) and lets the
   receiver detect tampering.

**Exam Center logs in →**
- Sees assigned papers with a 🔒 Locked / ✅ Unlocked status based on the
  scheduled exam date-time (**time-lock access control** — a center simply
  cannot decrypt before the exam starts, even if it has the file).
- On "Decrypt & Download":
  1. RSA-decrypts the AES key using its **own private key**.
  2. AES-decrypts the paper.
  3. Verifies the admin's signature against a freshly computed SHA-256 hash.
  4. If the signature check fails (file tampered / wrong sender) →
     download is blocked and it's logged as a security failure.
- Every decrypt attempt (success or failure, and why) is written to an
  **audit log** the admin can view.

## 2. Setup

```bash
pip install -r requirements.txt

# One-time: generate RSA keypairs for admin + exam centers
python keygen.py

# Run the app
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

### Demo accounts
| Username | Password    | Role   |
|----------|-------------|--------|
| admin    | admin123    | Admin  |
| center1  | center123   | Center |
| center2  | center123   | Center |

## 3. Demo script (for viva / evaluation)

1. Login as `admin` → upload a PDF, assign it to `center1`, set exam time
   to a few minutes in the future.
2. Login as `center1` → paper shows **Locked** until that time.
3. Wait / or set the exam time to a past time → refresh → now **Unlocked**
   → click Decrypt & Download → get back the original PDF.
4. **Tamper demo:** stop the server, open the file in `encrypted/`, flip a
   byte with a hex editor (or the one-liner below), restart, try to decrypt
   again as the center → it fails with a MAC/signature error instead of
   silently handing over a corrupted paper.
   ```python
   data = bytearray(open("encrypted/<file>.enc","rb").read())
   data[10] ^= 0xFF
   open("encrypted/<file>.enc","wb").write(data)
   ```
5. Login as `admin` → **View Access Logs** → shows every decrypt attempt,
   success/failure, and the reason (locked, bad signature, etc.) — this is
   your audit trail evidence for the report.

## 4. Project structure

```
secure_exam_distribution/
├── app.py              Flask routes (login, upload/encrypt, decrypt, logs)
├── crypto_utils.py      AES / RSA / SHA-256 / signature functions
├── keygen.py             One-time RSA keypair generation for admin + centers
├── database.py           SQLite schema + seed users + audit log helper
├── requirements.txt
├── templates/            HTML pages (Bootstrap-based)
├── static/style.css
├── keys/                 Generated RSA keys (created by keygen.py)
├── encrypted/            Encrypted paper storage (created at runtime)
└── uploads/              Decrypted output lands here temporarily
```

## 5. Why each crypto primitive is there (good for your viva)

| Primitive              | Purpose                                            |
|------------------------|-----------------------------------------------------|
| AES-256 (EAX mode)     | Confidentiality of the paper + built-in tamper check (auth tag) |
| RSA-2048               | Secure key exchange — encrypts the small AES key, not the whole file |
| SHA-256                | Integrity — detects any modification to the paper  |
| RSA Digital Signature  | Authenticity — proves the paper came from the real admin, not an imposter |
| Time-lock check        | Access control — paper unusable before scheduled exam time even if leaked |

## 6. Known limitations (mention honestly in your report — examiners like this)

- Private keys are stored server-side for demo convenience; in a real
  deployment each exam center would hold its own private key offline.
- Flask's built-in dev server / SQLite are fine for a mini-project demo,
  not for production scale.
- No 2FA / OTP layer — could be a "Future Scope" point along with
  blockchain-based audit logging and biometric center authentication.
