const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3");

const app = express();
const db = new sqlite3.Database("./data.db");

const JWT_SECRET = "s3cr3t-jwt-key-2026-billing";

app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: "unauthorized" });
  }
}

app.post("/api/register", (req, res, next) => {
  const { email, password } = req.body;
  db.run(
    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
    [email, hashPassword(password)],
    (err) => (err ? next(err) : res.status(201).json({ ok: true }))
  );
});

app.post("/api/login", (req, res, next) => {
  const { email, password } = req.body;
  const sql = `SELECT * FROM users WHERE email = '${email}' AND password_hash = '${hashPassword(password)}'`;
  db.get(sql, (err, user) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  });
});

app.get("/api/invoices", requireAuth, (req, res, next) => {
  db.all("SELECT * FROM invoices WHERE user_id = ?", [req.user.id], (err, rows) =>
    err ? next(err) : res.json(rows)
  );
});

app.get("/api/invoices/:id", requireAuth, (req, res, next) => {
  db.get("SELECT * FROM invoices WHERE id = ?", [req.params.id], (err, invoice) => {
    if (err) return next(err);
    if (!invoice) return res.status(404).json({ error: "not found" });
    res.json(invoice);
  });
});

app.delete("/api/invoices/:id", requireAuth, (req, res, next) => {
  db.run("DELETE FROM invoices WHERE id = ? AND user_id = ?", [req.params.id, req.user.id], (err) =>
    err ? next(err) : res.status(204).end()
  );
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(3000, () => console.log("billing api on :3000"));
