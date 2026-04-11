"use strict";

const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");

const LEGACY_HISTORY_FILE = path.join(__dirname, "data", "scan-history.json");
const DEFAULT_DB_NAME = "cloud_security_scanner";
const MONGODB_URI = process.env.MONGODB_URI || "";

let client;
let db;
let usersCollection;
let scanHistoryCollection;

async function connectDatabase() {
    if (!MONGODB_URI) {
        throw new Error("MONGODB_URI is not configured. Add your MongoDB Atlas connection string to the environment.");
    }

    if (db) {
        return db;
    }

    client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(resolveDatabaseName(MONGODB_URI));
    usersCollection = db.collection("users");
    scanHistoryCollection = db.collection("scanHistory");

    await Promise.all([
        usersCollection.createIndex({ username: 1 }, { unique: true }),
        scanHistoryCollection.createIndex({ username: 1, scannedAt: -1 })
    ]);

    await seedAdminUser();
    await migrateLegacyHistory();
    await ensurePasswordsHashed();

    return db;
}

function resolveDatabaseName(uri) {
    const match = uri.match(/mongodb(?:\+srv)?:\/\/[^/]+\/([^?]+)/i);
    const name = match && match[1] ? decodeURIComponent(match[1]) : "";
    return name || DEFAULT_DB_NAME;
}

async function seedAdminUser() {
    const existing = await usersCollection.findOne({ username: "admin" });
    if (!existing) {
        await usersCollection.insertOne({
            username: "admin",
            password: hashPassword("admin123"),
            name: "Neha Giri",
            role: "Security Administrator",
            createdAt: new Date().toISOString()
        });
    }
}

async function migrateLegacyHistory() {
    const count = await scanHistoryCollection.countDocuments();
    if (count > 0 || !fs.existsSync(LEGACY_HISTORY_FILE)) {
        return;
    }

    try {
        const raw = fs.readFileSync(LEGACY_HISTORY_FILE, "utf8");
        const items = JSON.parse(raw);
        if (!Array.isArray(items) || !items.length) {
            return;
        }

        await scanHistoryCollection.insertMany(items.map(item => ({
            username: item.username || "admin",
            fileName: item.fileName || "uploaded-config",
            cloud: item.cloud || "AWS",
            riskScore: Number(item.riskScore || 0),
            findingsCount: Number(item.findingsCount || 0),
            summary: item.summary || {},
            scannedAt: item.scannedAt || new Date().toISOString()
        })));
    } catch {
        // Ignore migration errors and continue with a fresh database.
    }
}

async function findUser(username, password) {
    const user = await usersCollection.findOne({ username });
    if (!user) {
        return null;
    }

    if (isPasswordValid(password, user.password)) {
        if (!isHashedPassword(user.password)) {
            await updatePasswordHash(user.username, password);
        }

        return mapUser(user);
    }

    return null;
}

async function createUser(user) {
    const existing = await usersCollection.findOne({ username: user.username });
    if (existing) {
        throw new Error("Username already exists");
    }

    await usersCollection.insertOne({
        username: user.username,
        password: hashPassword(user.password),
        name: user.name,
        role: user.role || "Security Administrator",
        createdAt: new Date().toISOString()
    });

    return getUserByUsername(user.username);
}

async function ensurePasswordsHashed() {
    const users = await usersCollection.find({}, { projection: { username: 1, password: 1 } }).toArray();
    await Promise.all(users.map(user => {
        if (!isHashedPassword(user.password)) {
            return updatePasswordHash(user.username, user.password);
        }
        return null;
    }));
}

async function updatePasswordHash(username, password) {
    await usersCollection.updateOne(
        { username },
        { $set: { password: hashPassword(password) } }
    );
}

function hashPassword(password) {
    return bcrypt.hashSync(password, 10);
}

function isPasswordValid(plainPassword, storedPassword) {
    if (isHashedPassword(storedPassword)) {
        return bcrypt.compareSync(plainPassword, storedPassword);
    }

    return plainPassword === storedPassword;
}

function isHashedPassword(value) {
    return typeof value === "string" && /^\$2[aby]\$\d{2}\$/.test(value);
}

async function getUserByUsername(username) {
    const user = await usersCollection.findOne({ username });
    return user ? mapUser(user) : null;
}

async function addScanHistory(entry) {
    await scanHistoryCollection.insertOne({
        username: entry.username,
        fileName: entry.fileName,
        cloud: entry.cloud,
        riskScore: entry.riskScore,
        findingsCount: entry.findingsCount,
        summary: entry.summary,
        scannedAt: entry.scannedAt
    });
}

async function getScanHistory(username, limit = 10) {
    const rows = await scanHistoryCollection
        .find({ username })
        .sort({ scannedAt: -1, _id: -1 })
        .limit(limit)
        .toArray();

    return rows.map(row => ({
        id: String(row._id),
        username: row.username,
        fileName: row.fileName,
        cloud: row.cloud,
        riskScore: row.riskScore,
        findingsCount: row.findingsCount,
        summary: row.summary || {},
        scannedAt: row.scannedAt
    }));
}

function mapUser(user) {
    return {
        id: String(user._id),
        username: user.username,
        name: user.name,
        role: user.role
    };
}

module.exports = {
    connectDatabase,
    findUser,
    createUser,
    getUserByUsername,
    addScanHistory,
    getScanHistory
};
