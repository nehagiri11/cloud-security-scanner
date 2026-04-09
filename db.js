"use strict";

const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const DATA_DIR = process.env.CLOUD_SECURITY_DATA_DIR
    ? process.env.CLOUD_SECURITY_DATA_DIR
    : process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, "CloudSecurityScanner")
        : path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "cloud-security.db");
const LEGACY_HISTORY_FILE = path.join(__dirname, "data", "scan-history.json");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(DB_PATH);

initializeSchema();
seedAdminUser();
migrateLegacyHistory();

function initializeSchema() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            file_name TEXT NOT NULL,
            cloud TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            findings_count INTEGER NOT NULL,
            summary_json TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        );
    `);
}

function seedAdminUser() {
    const existing = db.prepare("SELECT username FROM users WHERE username = ?").get("admin");
    if (!existing) {
        db.prepare(`
            INSERT INTO users (username, password, name, role)
            VALUES (?, ?, ?, ?)
        `).run("admin", "admin123", "Neha Giri", "Security Administrator");
    }
}

function migrateLegacyHistory() {
    const count = db.prepare("SELECT COUNT(*) AS total FROM scan_history").get().total;
    if (count > 0 || !fs.existsSync(LEGACY_HISTORY_FILE)) {
        return;
    }

    try {
        const raw = fs.readFileSync(LEGACY_HISTORY_FILE, "utf8");
        const items = JSON.parse(raw);
        const insert = db.prepare(`
            INSERT INTO scan_history (username, file_name, cloud, risk_score, findings_count, summary_json, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        const insertMany = db.transaction(records => {
            records.forEach(item => {
                insert.run(
                    item.username || "admin",
                    item.fileName || "uploaded-config",
                    item.cloud || "AWS",
                    Number(item.riskScore || 0),
                    Number(item.findingsCount || 0),
                    JSON.stringify(item.summary || {}),
                    item.scannedAt || new Date().toISOString()
                );
            });
        });

        insertMany(items);
    } catch {
        // Ignore migration errors and continue with a fresh database.
    }
}

function findUser(username, password) {
    return db.prepare(`
        SELECT id, username, name, role
        FROM users
        WHERE username = ? AND password = ?
    `).get(username, password);
}

function createUser(user) {
    const existing = db.prepare(`
        SELECT username
        FROM users
        WHERE username = ?
    `).get(user.username);

    if (existing) {
        throw new Error("Username already exists");
    }

    db.prepare(`
        INSERT INTO users (username, password, name, role)
        VALUES (?, ?, ?, ?)
    `).run(user.username, user.password, user.name, user.role || "Security Administrator");

    return getUserByUsername(user.username);
}

function getUserByUsername(username) {
    return db.prepare(`
        SELECT id, username, name, role
        FROM users
        WHERE username = ?
    `).get(username);
}

function addScanHistory(entry) {
    db.prepare(`
        INSERT INTO scan_history (username, file_name, cloud, risk_score, findings_count, summary_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
        entry.username,
        entry.fileName,
        entry.cloud,
        entry.riskScore,
        entry.findingsCount,
        JSON.stringify(entry.summary),
        entry.scannedAt
    );
}

function getScanHistory(username, limit = 10) {
    const rows = db.prepare(`
        SELECT id, username, file_name, cloud, risk_score, findings_count, summary_json, scanned_at
        FROM scan_history
        WHERE username = ?
        ORDER BY datetime(scanned_at) DESC, id DESC
        LIMIT ?
    `).all(username, limit);

    return rows.map(row => ({
        id: row.id,
        username: row.username,
        fileName: row.file_name,
        cloud: row.cloud,
        riskScore: row.risk_score,
        findingsCount: row.findings_count,
        summary: JSON.parse(row.summary_json),
        scannedAt: row.scanned_at
    }));
}

module.exports = {
    DB_PATH,
    findUser,
    createUser,
    getUserByUsername,
    addScanHistory,
    getScanHistory
};
