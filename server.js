// ──────────────────────────────────────────────
// server.js  –  Expense Tracker API (SQLite)
// Run with: node server.js
// ──────────────────────────────────────────────

const express = require("express");
const cors    = require("cors");
const sqlite3 = require("sqlite3").verbose();
const path    = require("path");

const app  = express();
const PORT = 5000;

// ── Database setup ─────────────────────────────
// Creates (or opens) expenses.db in the same directory as server.js.
// sqlite3.Database() will create the file automatically if it doesn't exist.
const DB_PATH = path.join(__dirname, "expenses.db");

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("❌  Could not connect to database:", err.message);
    process.exit(1);                        // No point running without a DB
  }
  console.log(`📦  Connected to SQLite database at ${DB_PATH}`);
});

// Create the expenses table if it doesn't already exist.
// This runs once on startup and is safe to re-run (IF NOT EXISTS).
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS expenses (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      name     TEXT    NOT NULL,
      amount   REAL    NOT NULL,
      category TEXT    NOT NULL,
      emoji    TEXT    NOT NULL
    )`,
    (err) => {
      if (err) {
        console.error("❌  Failed to create table:", err.message);
      } else {
        console.log("✅  Expenses table ready");
      }
    }
  );
});

// ── Middleware ─────────────────────────────────
app.use(cors());
app.use(express.json());

// Request logger — prints timestamp, method, and path for every request
app.use((req, _res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}]  ${req.method}  ${req.path}`);
  next();
});

// ── Helpers ────────────────────────────────────
const CATEGORY_EMOJI = {
  Food:          "🍔",
  Transport:     "🚗",
  Entertainment: "🎬",
  Other:         "📦",
};

const VALID_CATEGORIES = Object.keys(CATEGORY_EMOJI);

// Wraps db.run() in a Promise so we can use async/await in route handlers
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    // `this` inside the callback is the sqlite3 statement context,
    // which gives us `this.lastID` and `this.changes` after the query.
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

// Wraps db.all() in a Promise — returns an array of rows
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Wraps db.get() in a Promise — returns a single row (or undefined)
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// ── Routes ─────────────────────────────────────

// GET /api/expenses
// Returns every row in the expenses table, ordered by amount descending.
app.get("/api/expenses", async (_req, res) => {
  try {
    const rows = await dbAll("SELECT * FROM expenses ORDER BY amount DESC");
    res.json(rows);
  } catch (err) {
    console.error("❌  GET /api/expenses:", err.message);
    res.status(500).json({ error: "Failed to retrieve expenses." });
  }
});

// POST /api/expenses
// Body: { name: string, amount: number, category: string }
// Inserts a new row and returns it (including the auto-generated id).
app.post("/api/expenses", async (req, res) => {
  const { name, amount, category } = req.body;

  // ── Validation ──
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

  const cleanName = name.trim();
  const cleanAmt  = Number(amount);
  const emoji     = CATEGORY_EMOJI[category];

  try {
    // Insert the new row
    const stmt = await dbRun(
      "INSERT INTO expenses (name, amount, category, emoji) VALUES (?, ?, ?, ?)",
      [cleanName, cleanAmt, category, emoji]
    );

    // Fetch the row we just inserted using the auto-generated lastID
    const newExpense = await dbGet(
      "SELECT * FROM expenses WHERE id = ?",
      [stmt.lastID]
    );

    console.log(`  ✚ Created expense #${newExpense.id}: "${newExpense.name}" (₹${newExpense.amount})`);
    res.status(201).json(newExpense);

  } catch (err) {
    console.error("❌  POST /api/expenses:", err.message);
    res.status(500).json({ error: "Failed to create expense." });
  }
});

// DELETE /api/expenses/:id
// Deletes a single row by primary key.
app.delete("/api/expenses/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10);

  if (isNaN(id)) {
    return res.status(400).json({ error: "Expense ID must be a number." });
  }

  try {
    // Check the row actually exists before trying to delete it
    const existing = await dbGet("SELECT * FROM expenses WHERE id = ?", [id]);
    if (!existing) {
      return res.status(404).json({ error: `Expense with id ${id} not found.` });
    }

    // `stmt.changes` tells us how many rows were affected; should be 1 here
    const stmt = await dbRun("DELETE FROM expenses WHERE id = ?", [id]);
    if (stmt.changes === 0) {
      return res.status(404).json({ error: `Expense with id ${id} not found.` });
    }

    console.log(`  ✖ Deleted expense #${id}: "${existing.name}"`);
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
// Close the database connection cleanly when the process is terminated
// (Ctrl-C sends SIGINT; process managers like PM2 send SIGTERM).
function shutdown(signal) {
  console.log(`\n${signal} received — closing database connection…`);
  db.close((err) => {
    if (err) console.error("Error closing database:", err.message);
    else     console.log("Database connection closed. Goodbye! 👋");
    process.exit(0);
  });
}
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ── Start server ───────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("─────────────────────────────────────");
  console.log("  🚀  Expense Tracker API (SQLite)");
  console.log(`  🌐  http://localhost:${PORT}`);
  console.log(`  📋  GET    /api/expenses`);
  console.log(`  ➕  POST   /api/expenses`);
  console.log(`  🗑   DELETE /api/expenses/:id`);
  console.log("─────────────────────────────────────");
});