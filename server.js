require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const Database = require("better-sqlite3");
const twilio = require("twilio");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "";
const ENC_KEY_HEX = process.env.BANK_ENCRYPTION_KEY || "";
const db = new Database(path.join(__dirname, "balaji-ludo.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount_paise INTEGER NOT NULL,
  holder_enc TEXT NOT NULL,
  account_enc TEXT NOT NULL,
  ifsc_enc TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const withdrawLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });

function requireConfig() {
  if (JWT_SECRET.length < 32) throw new Error("Set JWT_SECRET to a random secret of at least 32 characters in .env");
  if (!/^[a-fA-F0-9]{64}$/.test(ENC_KEY_HEX)) throw new Error("BANK_ENCRYPTION_KEY must be 64 hex characters (32 bytes) in .env");
}
function normalizePhone(phone) {
  const p = String(phone || "").replace(/[^\d+]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(p)) throw new Error("Phone must be in international format, e.g. +919876543210");
  return p;
}
function twilioClient() {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SERVICE_SID) {
    const e = new Error("SMS OTP is not configured. Add Twilio Verify credentials to .env.");
    e.status = 503; throw e;
  }
  return twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
}
function encrypt(text) {
  const key = Buffer.from(ENC_KEY_HEX, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
  return [iv.toString("hex"), cipher.getAuthTag().toString("hex"), encrypted.toString("hex")].join(":");
}
function tokenFor(user) {
  return jwt.sign({ sub: String(user.id), phone: user.phone }, JWT_SECRET, { expiresIn: "12h", issuer: "balaji-ludo" });
}
function requireAuth(req, res, next) {
  try {
    requireConfig();
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: "balaji-ludo" });
    req.user = { id: Number(decoded.sub), phone: decoded.phone };
    next();
  } catch (e) { res.status(401).json({ error: "Login required or session expired." }); }
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "Balaji Ludo starter backend", mode: "starter-demo" }));

app.post("/api/auth/send-otp", authLimiter, async (req, res, next) => {
  try {
    requireConfig();
    const phone = normalizePhone(req.body.phone);
    const client = twilioClient();
    await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verifications.create({ to: phone, channel: "sms" });
    res.json({ ok: true, message: "OTP sent if the number is supported by your Verify service." });
  } catch (e) { next(e); }
});

app.post("/api/auth/verify-otp", authLimiter, async (req, res, next) => {
  try {
    requireConfig();
    const phone = normalizePhone(req.body.phone);
    const code = String(req.body.code || "").trim();
    if (!/^\d{4,8}$/.test(code)) return res.status(400).json({ error: "Enter the OTP you received." });
    const client = twilioClient();
    const check = await client.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID).verificationChecks.create({ to: phone, code });
    if (check.status !== "approved") return res.status(400).json({ error: "OTP is invalid or expired." });
    const insert = db.prepare("INSERT INTO users(phone) VALUES (?) ON CONFLICT(phone) DO NOTHING");
    insert.run(phone);
    const user = db.prepare("SELECT id, phone FROM users WHERE phone = ?").get(phone);
    res.json({ ok: true, token: tokenFor(user), user: { phone: user.phone } });
  } catch (e) { next(e); }
});

app.get("/api/me", requireAuth, (req, res) => {
  const user = db.prepare("SELECT phone, created_at FROM users WHERE id = ?").get(req.user.id);
  res.json({ user });
});

app.get("/api/deposit-info", (_req, res) => {
  res.json({
    upiId: process.env.UPI_ID || "8118878750@mbkns",
    note: "QR/manual UPI payments are not automatically verified or credited to a wallet by this starter."
  });
});

app.post("/api/withdrawals", requireAuth, withdrawLimiter, (req, res, next) => {
  try {
    requireConfig();
    const holder = String(req.body.accountHolder || "").trim();
    const account = String(req.body.accountNumber || "").replace(/\s/g, "");
    const ifsc = String(req.body.ifsc || "").trim().toUpperCase();
    const amount = Number(req.body.amount);
    if (holder.length < 2 || holder.length > 100) return res.status(400).json({ error: "Enter a valid account holder name." });
    if (!/^\d{6,24}$/.test(account)) return res.status(400).json({ error: "Enter a valid bank account number." });
    if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) return res.status(400).json({ error: "Enter a valid IFSC code." });
    if (!Number.isFinite(amount) || amount < 1 || amount > 100000) return res.status(400).json({ error: "Amount must be between ₹1 and ₹100,000 for this starter." });

    const count = db.prepare("SELECT COUNT(*) AS n FROM withdrawals WHERE user_id = ? AND date(created_at) = date('now','localtime')").get(req.user.id).n;
    if (count >= 2) return res.status(429).json({ error: "Daily limit reached: maximum 2 withdrawal requests per day." });

    const stmt = db.prepare(`INSERT INTO withdrawals(user_id, amount_paise, holder_enc, account_enc, ifsc_enc)
      VALUES (?, ?, ?, ?, ?)`);
    const result = stmt.run(req.user.id, Math.round(amount * 100), encrypt(holder), encrypt(account), encrypt(ifsc));
    res.status(201).json({ ok: true, requestId: result.lastInsertRowid, status: "pending", message: "Request recorded for manual review. No money has been transferred." });
  } catch (e) { next(e); }
});

app.get("/api/withdrawals", requireAuth, (req, res) => {
  const rows = db.prepare("SELECT id, amount_paise, status, created_at FROM withdrawals WHERE user_id = ? ORDER BY id DESC LIMIT 20").all(req.user.id);
  res.json({ withdrawals: rows.map(r => ({ id: r.id, amount: (r.amount_paise / 100).toFixed(2), status: r.status, createdAt: r.created_at })) });
});

app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err.message);
  res.status(status).json({ error: status === 500 ? "Server error. Check server configuration." : err.message });
});

try { requireConfig(); } catch (e) { console.warn("Configuration required before auth/withdrawal APIs work:", e.message); }
app.listen(PORT, () => console.log(`Balaji Ludo backend listening on http://localhost:${PORT}`));
