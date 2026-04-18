// ──────────────────────────────────────────────
// server.js  –  Expense Tracker API
//               PostgreSQL edition (Render-ready)
//
// WHY NOT SQLITE ON RENDER?
// Render's file system is ephemeral — it resets on every deploy and
// restart. Any SQLite .db file written to disk will be silently wiped.
// PostgreSQL (free on Render) is the correct solution for persistence.
//
// SETUP:
//   1. Create a free PostgreSQL database on Render dashboard
//   2. Copy the "Internal Database URL" into your Web Service's
//      environment variables as:  DATABASE_URL=postgres://...
//   3. npm install express cors bcrypt jsonwebtoken pg
//   4. Deploy — Render injects DATABASE_URL automatically at runtime
// ──────────────────────────────────────────────

const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcrypt");
const jwt     = require("jsonwebtoken");
const { Pool } = require("pg");       // 'pg' is the PostgreSQL client

const app  = express();
const PORT = process.env.PORT || 5000;  // Render sets PORT automatically

// ── Environment config ─────────────────────────
const JWT_SECRET     = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "7d";
const BCRYPT_ROUNDS  = 12;

// Hard-fail on startup if critical env vars are missing.
// It is much better to crash immediately with a clear message than to
// start up and then fail mysteriously on the first authenticated request.
if (!JWT_SECRET) {
  console.error("❌  FATAL: JWT_SECRET environment variable is not set.");
  console.error("    Add it to your Render Web Service → Environment tab.");
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error("❌  FATAL: DATABASE_URL environment variable is not set.");
  console.error("    Create a PostgreSQL database on Render and link it to this service.");
  process.exit(1);
}

// ── PostgreSQL connection pool ─────────────────
// A pool manages multiple connections efficiently.
// `ssl: { rejectUnauthorized: false }` is required for Render's hosted
// PostgreSQL — their certs are valid but self-signed for internal URLs.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max:              10,   // max simultaneous connections in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ── DB helpers ─────────────────────────────────
// Thin wrappers so route handlers look the same as the SQLite version.

async function dbRun(sql, params = []) {
  const result = await pool.query(sql, params);
  return result;
}

async function dbAll(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows;
}

async function dbGet(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows[0];   // undefined if no rows
}

// ── Table initialisation ───────────────────────
// Creates tables if they don't already exist.
// Called once after the pool is confirmed healthy (see initDatabase below).
async function createTables() {
  // Users table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL       PRIMARY KEY,
      username      TEXT         NOT NULL UNIQUE,
      password_hash TEXT         NOT NULL,
      created_at    TIMESTAMPTZ  DEFAULT NOW()
    )
  `);
  console.log("✅  Users table ready");

  // Expenses table with foreign key to users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id         SERIAL       PRIMARY KEY,
      user_id    INTEGER      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
      name       TEXT         NOT NULL,
      amount     NUMERIC      NOT NULL,
      category   TEXT         NOT NULL,
      emoji      TEXT         NOT NULL,
      created_at TIMESTAMPTZ  DEFAULT NOW()
    )
  `);
  console.log("✅  Expenses table ready");
}

// ── Database initialisation with retry ────────
// Render's PostgreSQL sometimes takes a few seconds to accept connections
// immediately after a deploy. We retry up to 5 times with a 2-second gap
// rather than crashing on the first transient failure.
async function initDatabase(retriesLeft = 5, delayMs = 2000) {
  try {
    // Test the connection before trying to create tables
    const client = await pool.connect();
    console.log("📦  Connected to PostgreSQL");
    client.release();

    await createTables();
    console.log("🚀  Database initialised successfully");
  } catch (err) {
    if (retriesLeft === 0) {
      console.error("❌  FATAL: Could not initialise database after multiple retries.");
      console.error("    Last error:", err.message);
      // Don't call process.exit here — let the server keep running so
      // Render's health check can hit GET / and you can read the error
      // in the logs rather than getting a cryptic "Exited with status 1".
      return;
    }
    console.warn(`⚠️   DB init failed (${err.message}). Retrying in ${delayMs / 1000}s… (${retriesLeft} attempts left)`);
    await new Promise(resolve => setTimeout(resolve, delayMs));
    return initDatabase(retriesLeft - 1, delayMs);
  }
}

// ── Middleware ─────────────────────────────────
app.use(cors());
app.use(express.json());

// Request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}]  ${req.method}  ${req.path}`);
  next();
});

// Health check — Render pings this to confirm the service is alive.
// Responds even if the DB isn't ready yet so the deploy doesn't time out.
app.get("/", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(503).json({ status: "ok", database: "unavailable" });
  }
});

// ── Auth middleware ────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header." });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(`  🔍 Token decoded — id: ${decoded.id}, username: "${decoded.username}"`);

    // Verify the user still exists in the database
    const userInDb = await dbGet(
      "SELECT id, username FROM users WHERE id = $1",
      [decoded.id]
    );

    if (!userInDb) {
      console.warn(`  ⚠️  Token valid but user #${decoded.id} not found in database`);
      return res.status(401).json({ error: "User account not found. Please log in again." });
    }

    req.user = userInDb;
    console.log(`  ✅ Auth OK — user #${req.user.id} ("${req.user.username}")`);
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired. Please log in again." });
    }
    console.error("  ❌ JWT verification failed:", err.message);
    return res.status(401).json({ error: "Invalid token." });
  }
}

// ── Helpers ────────────────────────────────────
const CATEGORY_EMOJI = {
  Food:          "🍔",
  Transport:     "🚗",
  Entertainment: "🎬",
  Other:         "📦",
};
const VALID_CATEGORIES = Object.keys(CATEGORY_EMOJI);

function generateToken(user) {
  const payload = { id: user.id, username: user.username };
  console.log("  🪙 Signing token with payload:", payload);
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// ── Auth routes ────────────────────────────────

// POST /api/auth/register
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !username.trim())  return res.status(400).json({ error: "Field 'username' is required." });
  if (!password)                      return res.status(400).json({ error: "Field 'password' is required." });
  if (username.trim().length < 3)     return res.status(400).json({ error: "Username must be at least 3 characters." });
  if (password.length < 6)            return res.status(400).json({ error: "Password must be at least 6 characters." });

  const cleanUsername = username.trim().toLowerCase();

  try {
    const existing = await dbGet(
      "SELECT id FROM users WHERE username = $1",
      [cleanUsername]
    );
    if (existing) return res.status(409).json({ error: "Username already taken." });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // PostgreSQL uses RETURNING to get the inserted row back in one query
    const newUser = await dbGet(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at",
      [cleanUsername, passwordHash]
    );

    const token = generateToken(newUser);
    console.log(`  👤 Registered user: "${newUser.username}" (#${newUser.id})`);
    res.status(201).json({ id: newUser.id, username: newUser.username, token });

  } catch (err) {
    console.error("❌  POST /api/auth/register:", err.message);
    res.status(500).json({ error: "Registration failed." });
  }
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !username.trim()) return res.status(400).json({ error: "Field 'username' is required." });
  if (!password)                     return res.status(400).json({ error: "Field 'password' is required." });

  const cleanUsername = username.trim().toLowerCase();

  try {
    const user = await dbGet(
      "SELECT * FROM users WHERE username = $1",
      [cleanUsername]
    );

    if (!user) return res.status(401).json({ error: "Invalid username or password." });

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: "Invalid username or password." });

    const token = generateToken(user);
    console.log(`  🔑 Logged in: "${user.username}" (#${user.id})`);
    res.json({ id: user.id, username: user.username, token });

  } catch (err) {
    console.error("❌  POST /api/auth/login:", err.message);
    res.status(500).json({ error: "Login failed." });
  }
});

// ── Expense routes ─────────────────────────────

// GET /api/expenses
app.get("/api/expenses", requireAuth, async (req, res) => {
  try {
    const rows = await dbAll(
      "SELECT * FROM expenses WHERE user_id = $1 ORDER BY amount DESC",
      [req.user.id]
    );
    console.log(`  📋 Returning ${rows.length} expenses for user #${req.user.id}`);
    res.json(rows);
  } catch (err) {
    console.error("❌  GET /api/expenses:", err.message);
    res.status(500).json({ error: "Failed to retrieve expenses." });
  }
});

// POST /api/expenses
app.post("/api/expenses", requireAuth, async (req, res) => {
  const { name, amount, category } = req.body;

  if (!name || !name.trim())                          return res.status(400).json({ error: "Field 'name' is required." });
  if (amount == null || amount === "")                return res.status(400).json({ error: "Field 'amount' is required." });
  if (isNaN(Number(amount)) || Number(amount) <= 0)  return res.status(400).json({ error: "Field 'amount' must be a positive number." });
  if (!category || !category.trim())                  return res.status(400).json({ error: "Field 'category' is required." });
  if (!VALID_CATEGORIES.includes(category))           return res.status(400).json({ error: `Field 'category' must be one of: ${VALID_CATEGORIES.join(", ")}.` });

  const cleanName = name.trim();
  const cleanAmt  = Number(amount);
  const emoji     = CATEGORY_EMOJI[category];

  console.log(`  ➕ Creating expense for user: ${req.user.id} ("${req.user.username}")`);
  console.log(`  💾 INSERT — user_id: ${req.user.id}, name: "${cleanName}", amount: ${cleanAmt}, category: "${category}"`);

  try {
    // RETURNING lets us skip a second SELECT to fetch the new row
    const newExpense = await dbGet(
      `INSERT INTO expenses (user_id, name, amount, category, emoji)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [req.user.id, cleanName, cleanAmt, category, emoji]
    );

    console.log(`  ✚ Created expense #${newExpense.id} for user #${req.user.id}`);
    res.status(201).json(newExpense);

  } catch (err) {
    if (err.code === "23503") {   // PostgreSQL foreign key violation code
      console.error(`  ❌ FK violation — user_id ${req.user.id} not in users table`);
      return res.status(400).json({ error: "User not found. Please log out and log in again." });
    }
    console.error("❌  POST /api/expenses:", err.message);
    res.status(500).json({ error: "Failed to create expense." });
  }
});

// DELETE /api/expenses/:id
app.delete("/api/expenses/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Expense ID must be a number." });

  try {
    // RETURNING lets us confirm what was deleted without a prior SELECT
    const deleted = await dbGet(
      "DELETE FROM expenses WHERE id = $1 AND user_id = $2 RETURNING *",
      [id, req.user.id]
    );

    if (!deleted) {
      return res.status(404).json({ error: `Expense with id ${id} not found.` });
    }

    console.log(`  ✖ User #${req.user.id} deleted expense #${id}: "${deleted.name}"`);
    res.json({ success: true, message: "Deleted", deleted });

  } catch (err) {
    console.error(`❌  DELETE /api/expenses/${id}:`, err.message);
    res.status(500).json({ error: "Failed to delete expense." });
  }
});

// ── 404 catch-all ──────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found.` });
});

// ── Graceful shutdown ──────────────────────────
async function shutdown(signal) {
  console.log(`\n${signal} received — closing DB pool…`);
  await pool.end();
  console.log("Pool closed. Goodbye! 👋");
  process.exit(0);
}
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ── Start: listen first, then init DB ─────────
// Render's health check expects the server to accept HTTP connections
// quickly after deploy. We start listening immediately, then connect to
// the database in the background. The health check endpoint (GET /)
// reports database status honestly without blocking startup.
app.listen(PORT, async () => {
  console.log("─────────────────────────────────────────");
  console.log("  🚀  Expense Tracker API  (PostgreSQL)");
  console.log(`  🌐  Listening on port ${PORT}`);
  console.log("─────────────────────────────────────────");
  await initDatabase();
});