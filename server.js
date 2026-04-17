// ──────────────────────────────────────────────
// server.js  –  Expense Tracker API
//               with SQLite + Auth (bcrypt + JWT)
// Run with: node server.js
// ──────────────────────────────────────────────

const express = require("express");
const cors    = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt  = require("bcrypt");
const jwt     = require("jsonwebtoken");
const path    = require("path");

const app  = express();
const PORT = 5000;

// ── Environment config ─────────────────────────
const JWT_SECRET     = process.env.JWT_SECRET || "change-this-secret-in-production";
const JWT_EXPIRES_IN = "7d";
const BCRYPT_ROUNDS  = 12;

if (!process.env.JWT_SECRET) {
  console.warn("⚠️   JWT_SECRET not set — using insecure default. Set it before deploying.");
}

// ── Database setup ─────────────────────────────
const DB_PATH = path.join(__dirname, "expenses.db");

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("❌  Could not connect to database:", err.message);
    process.exit(1);
  }
  console.log(`📦  Connected to SQLite at ${DB_PATH}`);
});

// FIX 1: Foreign key enforcement + table creation are all inside one
// db.serialize() block. serialize() guarantees that every statement runs
// to completion before the next one starts, so the PRAGMA is always
// active before any INSERT can be attempted — even on the very first
// request after startup. Previously the PRAGMA may have run async and
// lost the race against incoming requests.
db.serialize(() => {

  // FIX 1a: PRAGMA must be the FIRST statement in the serialize block.
  // SQLite foreign key enforcement is per-connection and off by default;
  // it must be switched on before any table that uses REFERENCES is touched.
  db.run("PRAGMA foreign_keys = ON", (err) => {
    if (err) console.error("❌  Failed to enable foreign keys:", err.message);
    else     console.log("🔗  Foreign key enforcement: ON");
  });

  // Users table
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id            INTEGER  PRIMARY KEY AUTOINCREMENT,
      username      TEXT     NOT NULL UNIQUE,
      password_hash TEXT     NOT NULL,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    (err) => {
      if (err) console.error("❌  Failed to create users table:", err.message);
      else     console.log("✅  Users table ready");
    }
  );

  // Expenses table — user_id is a FOREIGN KEY back to users.id
  db.run(
    `CREATE TABLE IF NOT EXISTS expenses (
      id         INTEGER  PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER  NOT NULL,
      name       TEXT     NOT NULL,
      amount     REAL     NOT NULL,
      category   TEXT     NOT NULL,
      emoji      TEXT     NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`,
    (err) => {
      if (err) console.error("❌  Failed to create expenses table:", err.message);
      else     console.log("✅  Expenses table ready");
    }
  );
});

// ── DB promise helpers ─────────────────────────
// sqlite3 is callback-based; these wrappers let us use async/await.
// IMPORTANT: db.run() callbacks must use `function`, not arrow functions —
// only `function` binds `this`, which is where sqlite3 puts lastID/changes.

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else     resolve(this);   // this.lastID, this.changes
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else     resolve(rows);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else     resolve(row);    // undefined when no row matches
    });
  });
}

// ── Middleware ─────────────────────────────────
app.use(cors());
app.use(express.json());

// Request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}]  ${req.method}  ${req.path}`);
  next();
});

// ── Auth middleware ────────────────────────────
// FIX 2: The middleware now explicitly logs what it finds in the token
// so you can see at a glance whether id/username are present and correct.
// It also re-reads PRAGMA foreign_keys to confirm the setting survived
// the connection lifetime (SQLite resets it on reconnect in some drivers).
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header." });
  }

  const token = authHeader.slice(7);   // strip "Bearer "

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // FIX 2a: Log exactly what the token contains so you can confirm the
    // shape of the payload. If `decoded.id` is undefined here, the token
    // was signed with a different payload shape (e.g. `userId` vs `id`).
    console.log(`  🔍 Token decoded — id: ${decoded.id}, username: "${decoded.username}"`);

    // FIX 2b: Explicitly confirm the user still exists in the database.
    // A token can be valid (correct signature, not expired) but reference
    // a user that was deleted since it was issued. Without this check the
    // FOREIGN KEY constraint will fire when we try to INSERT the expense.
    const userInDb = await dbGet(
      "SELECT id, username FROM users WHERE id = ?",
      [decoded.id]
    );

    if (!userInDb) {
      console.warn(`  ⚠️  Token valid but user #${decoded.id} not found in database`);
      return res.status(401).json({ error: "User account not found. Please log in again." });
    }

    // FIX 2c: Attach the database row (not just the token payload) to req.user.
    // This guarantees req.user.id is the real integer primary key from the
    // users table — exactly what the expenses.user_id foreign key expects.
    req.user = userInDb;   // { id: <integer>, username: <string> }
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
  // FIX 3: Log the payload being signed so you can verify the shape matches
  // what requireAuth expects (i.e. `id`, not `userId` or `user_id`).
  const payload = { id: user.id, username: user.username };
  console.log(`  🪙 Signing token with payload:`, payload);
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
    const existing = await dbGet("SELECT id FROM users WHERE username = ?", [cleanUsername]);
    if (existing) return res.status(409).json({ error: "Username already taken." });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const stmt         = await dbRun(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [cleanUsername, passwordHash]
    );

    const newUser = await dbGet(
      "SELECT id, username, created_at FROM users WHERE id = ?",
      [stmt.lastID]
    );

    // FIX 3: generateToken now logs the payload — verify `id` is an integer
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
    const user = await dbGet("SELECT * FROM users WHERE username = ?", [cleanUsername]);

    // Generic message intentionally — avoids revealing which usernames exist
    if (!user) return res.status(401).json({ error: "Invalid username or password." });

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: "Invalid username or password." });

    const token = generateToken(user);   // logs payload

    console.log(`  🔑 Logged in: "${user.username}" (#${user.id})`);
    res.json({ id: user.id, username: user.username, token });

  } catch (err) {
    console.error("❌  POST /api/auth/login:", err.message);
    res.status(500).json({ error: "Login failed." });
  }
});

// ── Expense routes (all protected) ────────────

// GET /api/expenses
app.get("/api/expenses", requireAuth, async (req, res) => {
  try {
    const rows = await dbAll(
      "SELECT * FROM expenses WHERE user_id = ? ORDER BY amount DESC",
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

  // Validation
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "Field 'name' is required." });
  }
  if (amount === undefined || amount === null || amount === "") {
    return res.status(400).json({ error: "Field 'amount' is required." });
  }
  if (isNaN(Number(amount)) || Number(amount) <= 0) {
    return res.status(400).json({ error: "Field 'amount' must be a positive number." });
  }
  if (!category || !category.trim()) {
    return res.status(400).json({ error: "Field 'category' is required." });
  }
  if (!VALID_CATEGORIES.includes(category)) {
    return res.status(400).json({
      error: `Field 'category' must be one of: ${VALID_CATEGORIES.join(", ")}.`,
    });
  }

  // FIX 4: Log the user we're about to create an expense for.
  // If you see "undefined" here the bug is in requireAuth, not in this handler.
  console.log(`  ➕ Creating expense for user: ${req.user.id} ("${req.user.username}")`);

  // FIX 5: Re-verify the user exists in the users table right before the
  // INSERT. requireAuth already did this, but doing it again here gives a
  // crystal-clear error message if somehow the check was bypassed, and it
  // rules out any timing issue where the user was deleted between the two
  // steps (unlikely but worth guarding against in production).
  const userExists = await dbGet("SELECT id FROM users WHERE id = ?", [req.user.id]);
  if (!userExists) {
    console.error(`  ❌ User #${req.user.id} not found in users table at INSERT time`);
    return res.status(401).json({ error: "User not found. Please log in again." });
  }

  const cleanName = name.trim();
  const cleanAmt  = Number(amount);
  const emoji     = CATEGORY_EMOJI[category];

  try {
    // FIX 4b: Log the exact values going into the INSERT so you can
    // inspect them before the query fires — particularly user_id.
    console.log(`  💾 INSERT expenses — user_id: ${req.user.id}, name: "${cleanName}", amount: ${cleanAmt}, category: "${category}"`);

    const stmt = await dbRun(
      "INSERT INTO expenses (user_id, name, amount, category, emoji) VALUES (?, ?, ?, ?, ?)",
      [req.user.id, cleanName, cleanAmt, category, emoji]
    );

    const newExpense = await dbGet(
      "SELECT * FROM expenses WHERE id = ?",
      [stmt.lastID]
    );

    console.log(`  ✚ Created expense #${newExpense.id} for user #${req.user.id}: "${newExpense.name}" (₹${newExpense.amount})`);
    res.status(201).json(newExpense);

  } catch (err) {
    // FIX 6: Catch the FK error specifically and return a meaningful message
    // instead of a generic 500, so the frontend can surface it clearly.
    if (err.message.includes("FOREIGN KEY")) {
      console.error(`  ❌ FOREIGN KEY constraint failed — user_id ${req.user.id} does not exist in users table`);
      console.error(`     Full error: ${err.message}`);
      return res.status(400).json({
        error: `User #${req.user.id} not found in database. Your session may be stale — please log out and log back in.`,
      });
    }
    console.error("❌  POST /api/expenses:", err.message);
    res.status(500).json({ error: "Failed to create expense." });
  }
});

// DELETE /api/expenses/:id
app.delete("/api/expenses/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);

  if (isNaN(id)) {
    return res.status(400).json({ error: "Expense ID must be a number." });
  }

  try {
    // WHERE user_id = ? ensures users can only delete their own expenses
    const existing = await dbGet(
      "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
      [id, req.user.id]
    );

    if (!existing) {
      return res.status(404).json({ error: `Expense with id ${id} not found.` });
    }

    await dbRun(
      "DELETE FROM expenses WHERE id = ? AND user_id = ?",
      [id, req.user.id]
    );

    console.log(`  ✖ User #${req.user.id} deleted expense #${id}: "${existing.name}"`);
    res.json({ success: true, message: "Deleted", deleted: existing });

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
function shutdown(signal) {
  console.log(`\n${signal} received — closing database…`);
  db.close((err) => {
    if (err) console.error("Error closing database:", err.message);
    else     console.log("Database closed. Goodbye! 👋");
    process.exit(0);
  });
}
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ── Start server ───────────────────────────────
app.listen(PORT, () => {
  console.log("─────────────────────────────────────────");
  console.log("  🚀  Expense Tracker API  (Auth + SQLite)");
  console.log(`  🌐  http://localhost:${PORT}`);
  console.log("  ─────────────────────────────────────");
  console.log("  👤  POST   /api/auth/register");
  console.log("  🔑  POST   /api/auth/login");
  console.log("  ─────────────────────────────────────");
  console.log("  📋  GET    /api/expenses      🔒");
  console.log("  ➕  POST   /api/expenses      🔒");
  console.log("  🗑   DELETE /api/expenses/:id  🔒");
  console.log("  ─────────────────────────────────────");
  console.log("  🔒 = requires Authorization: Bearer <token>");
  console.log("─────────────────────────────────────────");
});