"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { scanConfiguration, calculateRiskScore, summarizeFindings } = require("./scanner");
const { findUser, createUser, addScanHistory, getScanHistory } = require("./db");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

const sessions = new Map();

const server = http.createServer(async (req, res) => {
    try {
        if (req.method === "OPTIONS") {
            res.writeHead(204, {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
            });
            res.end();
            return;
        }

        if (req.url.startsWith("/api/")) {
            await handleApi(req, res);
            return;
        }

        serveStatic(req, res);
    } catch (error) {
        sendJson(res, 500, { error: "Internal server error", detail: error.message });
    }
});

server.listen(PORT, () => {
    console.log(`Cloud Security Scanner running at http://localhost:${PORT}`);
});

async function handleApi(req, res) {
    if (req.method === "GET" && req.url === "/api/health") {
        sendJson(res, 200, { status: "ok", service: "cloud-security-scanner" });
        return;
    }

    if (req.method === "POST" && req.url === "/api/login") {
        const body = await readJsonBody(req);
        const user = findUser(body.username, body.password);

        if (!user) {
            sendJson(res, 401, { error: "Invalid username or password" });
            return;
        }

        const token = crypto.randomBytes(24).toString("hex");
        sessions.set(token, { username: user.username, name: user.name, role: user.role });
        sendJson(res, 200, {
            token,
            user: {
                username: user.username,
                name: user.name,
                role: user.role
            }
        });
        return;
    }

    if (req.method === "POST" && req.url === "/api/register") {
        const body = await readJsonBody(req);
        const name = String(body.name || "").trim();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!name || !username || !password) {
            sendJson(res, 400, { error: "Name, username, and password are required" });
            return;
        }

        if (password.length < 6) {
            sendJson(res, 400, { error: "Password must be at least 6 characters long" });
            return;
        }

        try {
            const user = createUser({
                name,
                username,
                password,
                role: "Security Administrator"
            });

            const token = crypto.randomBytes(24).toString("hex");
            sessions.set(token, { username: user.username, name: user.name, role: user.role });
            sendJson(res, 201, {
                token,
                user: {
                    username: user.username,
                    name: user.name,
                    role: user.role
                }
            });
        } catch (error) {
            sendJson(res, 409, { error: error.message || "Registration failed" });
        }
        return;
    }

    if (req.method === "POST" && req.url === "/api/logout") {
        const session = requireSession(req, res);
        if (!session) {
            return;
        }

        sessions.delete(getBearerToken(req));
        sendJson(res, 200, { success: true });
        return;
    }

    if (req.method === "GET" && req.url === "/api/session") {
        const session = requireSession(req, res);
        if (!session) {
            return;
        }

        sendJson(res, 200, { user: session });
        return;
    }

    if (req.method === "GET" && req.url === "/api/history") {
        const session = requireSession(req, res);
        if (!session) {
            return;
        }

        const userHistory = getScanHistory(session.username, 10);
        sendJson(res, 200, { items: userHistory });
        return;
    }

    if (req.method === "POST" && req.url === "/api/scan") {
        const session = requireSession(req, res);
        if (!session) {
            return;
        }

        const body = await readJsonBody(req);
        const findings = scanConfiguration(body.config || {}, body.cloud);
        const riskScore = calculateRiskScore(findings);
        const summary = summarizeFindings(findings);
        const fileName = body.fileName || "uploaded-config";
        const cloud = body.cloud || "AWS";

        const entry = {
            username: session.username,
            fileName,
            cloud,
            riskScore,
            summary,
            findingsCount: findings.filter(item => item.severity !== "Safe").length,
            scannedAt: new Date().toISOString()
        };

        addScanHistory(entry);

        sendJson(res, 200, {
            fileName,
            cloud,
            riskScore,
            summary,
            findings
        });
        return;
    }

    sendJson(res, 404, { error: "API route not found" });
}

function serveStatic(req, res) {
    const requestPath = req.url === "/" ? "/index.html" : req.url.split("?")[0];
    const safePath = path.normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
    let filePath = path.join(PUBLIC_DIR, safePath);

    if (!filePath.startsWith(PUBLIC_DIR)) {
        sendText(res, 403, "Forbidden", "text/plain");
        return;
    }

    if (!fs.existsSync(filePath)) {
        const fallbackPath = path.join(__dirname, safePath);
        if (fallbackPath.startsWith(__dirname) && fs.existsSync(fallbackPath) && fs.statSync(fallbackPath).isFile()) {
            filePath = fallbackPath;
        } else {
            sendText(res, 404, "Not Found", "text/plain");
            return;
        }
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".yaml": "text/yaml; charset=utf-8",
        ".yml": "text/yaml; charset=utf-8"
    }[ext] || "application/octet-stream";

    sendText(res, 200, fs.readFileSync(filePath), contentType);
}
function requireSession(req, res) {
    const token = getBearerToken(req);
    const session = sessions.get(token);

    if (!token || !session) {
        sendJson(res, 401, { error: "Unauthorized" });
        return null;
    }

    return session;
}

function getBearerToken(req) {
    const header = req.headers.authorization || "";
    return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", chunk => {
            body += chunk;
            if (body.length > 2 * 1024 * 1024) {
                reject(new Error("Request body too large"));
                req.destroy();
            }
        });

        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch {
                reject(new Error("Invalid JSON body"));
            }
        });

        req.on("error", reject);
    });
}

function sendJson(res, statusCode, payload) {
    res.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    });
    res.end(JSON.stringify(payload));
}

function sendText(res, statusCode, payload, contentType) {
    res.writeHead(statusCode, {
        "Content-Type": contentType
    });
    res.end(payload);
}
