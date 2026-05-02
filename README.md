# 🛡️ FraudShield AI+ — Setup & Deploy Guide

## 🚀 Local Run (3 steps)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run server
python app.py

# 3. Open browser
http://localhost:5000
```

## 👤 Demo Accounts

| Role     | Email                      | Password      | Access |
|----------|----------------------------|---------------|--------|
| 👑 Admin  | admin@fraudshield.com      | adminpass123  | Full platform control |
| 🏦 Bank   | bank@fraudshield.com       | bankpass123   | Transaction + Document focus |
| 🔍 Analyst| analyst@fraudshield.com    | analystpass   | All 5 detection modules |

## 📁 File Structure

```
fraudshield/
├── app.py              ← Flask backend (all API routes + ML)
├── style.css           ← Shared CSS (dark/light theme)
├── common.js           ← Shared JS (Auth, theme, chat)
├── index.html          ← Landing page
├── auth.html           ← Login page
├── signup.html         ← Register page
├── dashboard.html      ← Analyst dashboard
├── admin.html          ← Admin panel (role: admin)
├── bank.html           ← Bank dashboard (role: bank)
├── requirements.txt    ← Python packages
├── Procfile            ← Railway/Heroku deploy
└── fraudshield.db      ← SQLite database (auto-created)
```

## 🌐 Deploy on Railway (Free)

1. Go to https://railway.app
2. Click "New Project" → "Deploy from GitHub"
3. Push your code to GitHub first
4. Railway auto-detects Procfile and deploys!

## 🌐 Deploy on Render (Free)

1. Go to https://render.com
2. New Web Service → Connect GitHub
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn app:app`

## 🔐 Security Notes

- Change JWT_SECRET in app.py before production
- Use environment variables for secrets
- Admin role should be assigned manually in DB for production

## 🧠 ML Models

| Module      | Algorithm         | Features                          |
|-------------|-------------------|-----------------------------------|
| Transaction | IsolationForest   | amount, hour, frequency, location |
| Spam        | TF-IDF + LogReg   | text n-grams (1-3 words)          |
| Image       | OpenCV + PIL      | pixel variance + edge density     |
| Document    | PyPDF2 + Metadata | file structure + PDF metadata     |
| Video       | Byte Entropy      | first 8KB byte pattern analysis   |
