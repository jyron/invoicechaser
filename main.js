import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { serveDir } from "https://deno.land/std@0.208.0/http/file_server.ts";
import { createClient } from "https://esm.sh/@libsql/client@0.4.0/web";
import {
  encodeBase64,
  decodeBase64,
} from "https://deno.land/std@0.208.0/encoding/base64.ts";

const db = createClient({
  url: Deno.env.get("TURSO_URL") || "",
  authToken: Deno.env.get("TURSO_AUTH_TOKEN") || "",
});

// Environment variables for Google OAuth
const GOOGLE_CLIENT_ID = Deno.env.get("GOOGLE_CLIENT_ID") || "";
const GOOGLE_CLIENT_SECRET = Deno.env.get("GOOGLE_CLIENT_SECRET") || "";
const APP_URL = Deno.env.get("APP_URL") || "http://localhost:8000";
const SESSION_SECRET =
  Deno.env.get("SESSION_SECRET") || "change-this-secret-in-production";

// Initialize database tables
await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        google_id TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
`);

await db.execute(`
    CREATE TABLE IF NOT EXISTS invoices (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        client_email TEXT NOT NULL,
        client_name TEXT NOT NULL,
        amount TEXT NOT NULL,
        invoice_number TEXT NOT NULL,
        your_name TEXT NOT NULL,
        your_email TEXT NOT NULL,
        chase_count INTEGER DEFAULT 1,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        next_chase TEXT NOT NULL,
        last_chase TEXT NOT NULL,
        paid_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

await db.execute(`
    CREATE TABLE IF NOT EXISTS rate_limits (
        id TEXT PRIMARY KEY,
        ip_address TEXT NOT NULL,
        action TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
`);

await db.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

// Try to add user_id column if it doesn't exist (for existing databases)
try {
  await db.execute(
    `ALTER TABLE invoices ADD COLUMN user_id TEXT REFERENCES users(id)`
  );
} catch (e) {
  // Column likely already exists
}

function generateId() {
  return crypto.randomUUID();
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

// Session management
function createSessionToken(sessionId) {
  const data = JSON.stringify({ sessionId, secret: SESSION_SECRET });
  return encodeBase64(new TextEncoder().encode(data));
}

function parseSessionToken(token) {
  try {
    const decoded = new TextDecoder().decode(decodeBase64(token));
    const data = JSON.parse(decoded);
    if (data.secret !== SESSION_SECRET) return null;
    return data.sessionId;
  } catch {
    return null;
  }
}

async function createSession(userId) {
  const sessionId = generateId();
  const now = new Date();
  const expiresAt = addDays(now, 30); // 30 day sessions

  await db.execute({
    sql: `INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
    args: [sessionId, userId, now.toISOString(), expiresAt.toISOString()],
  });

  return createSessionToken(sessionId);
}

async function getSessionUser(req) {
  const cookies = req.headers.get("cookie") || "";
  const match = cookies.match(/session=([^;]+)/);
  if (!match) return null;

  const sessionId = parseSessionToken(match[1]);
  if (!sessionId) return null;

  const result = await db.execute({
    sql: `SELECT users.* FROM users 
          JOIN sessions ON users.id = sessions.user_id 
          WHERE sessions.id = ? AND sessions.expires_at > ?`,
    args: [sessionId, new Date().toISOString()],
  });

  return result.rows[0] || null;
}

async function deleteSession(req) {
  const cookies = req.headers.get("cookie") || "";
  const match = cookies.match(/session=([^;]+)/);
  if (!match) return;

  const sessionId = parseSessionToken(match[1]);
  if (!sessionId) return;

  await db.execute({
    sql: `DELETE FROM sessions WHERE id = ?`,
    args: [sessionId],
  });
}

// Rate limiting for test emails
async function checkRateLimit(ipAddress, action) {
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const result = await db.execute({
    sql: `SELECT COUNT(*) as count FROM rate_limits WHERE ip_address = ? AND action = ? AND created_at > ?`,
    args: [ipAddress, action, oneDayAgo],
  });

  return result.rows[0].count >= 1;
}

async function recordRateLimit(ipAddress, action) {
  await db.execute({
    sql: `INSERT INTO rate_limits (id, ip_address, action, created_at) VALUES (?, ?, ?, ?)`,
    args: [generateId(), ipAddress, action, new Date().toISOString()],
  });
}

// Clean up old rate limit records periodically
async function cleanupRateLimits() {
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  await db.execute({
    sql: `DELETE FROM rate_limits WHERE created_at < ?`,
    args: [oneDayAgo],
  });
}

function generateEmail(invoice) {
  const subjects = [
    `Following up on Invoice ${invoice.invoice_number}`,
    `Friendly reminder: Invoice ${invoice.invoice_number}`,
    `Invoice ${invoice.invoice_number} - Quick follow-up`,
    `Checking in on Invoice ${invoice.invoice_number}`,
    `Invoice ${invoice.invoice_number} still outstanding`,
  ];

  const idx = Math.min(invoice.chase_count - 1, subjects.length - 1);
  const subject = subjects[idx];

  let body;

  if (invoice.chase_count === 1) {
    body = `Hi ${invoice.client_name},

I hope you're doing well. I wanted to follow up on invoice ${invoice.invoice_number} for $${invoice.amount}, which appears to still be outstanding.

I understand things get busy, so I just wanted to send a friendly reminder. Please let me know if you have any questions or if there's anything I can help with to process this payment.

Thanks so much,
${invoice.your_name}`;
  } else if (invoice.chase_count === 2) {
    body = `Hi ${invoice.client_name},

Just wanted to check in again on invoice ${invoice.invoice_number} for $${invoice.amount}. I sent a note a few days ago but wanted to make sure it didn't slip through the cracks.

If there are any issues with the invoice or payment, I'm happy to help sort them out.

Best,
${invoice.your_name}`;
  } else if (invoice.chase_count === 3) {
    body = `Hi ${invoice.client_name},

I'm following up once more on invoice ${invoice.invoice_number} for $${invoice.amount}. This is the third time I've reached out, so I want to make sure everything is okay on your end.

If there's a problem with the invoice or you need different payment terms, please let me know and we can work something out.

Thanks,
${invoice.your_name}`;
  } else {
    body = `Hi ${invoice.client_name},

I've reached out several times now about invoice ${invoice.invoice_number} for $${invoice.amount} and haven't heard back. I'd really appreciate an update on when I can expect payment.

If there's an issue I'm not aware of, please let me know so we can resolve it.

Thank you,
${invoice.your_name}`;
  }

  return { subject, body };
}

async function sendEmail(invoice) {
  const { subject, body } = generateEmail(invoice);

  const resendApiKey = Deno.env.get("RESEND_API_KEY");
  const fromEmail = Deno.env.get("FROM_EMAIL") || "onboarding@resend.dev";

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: `${invoice.your_name} <${fromEmail}>`,
      to: invoice.client_email,
      reply_to: invoice.your_email,
      subject: subject,
      text: body,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to send email: ${err}`);
  }

  console.log(
    `Email sent to ${invoice.client_email} for invoice ${invoice.invoice_number} (chase #${invoice.chase_count})`
  );
}

async function sendTestEmail(email) {
  const resendApiKey = Deno.env.get("RESEND_API_KEY");
  const fromEmail = Deno.env.get("FROM_EMAIL") || "onboarding@resend.dev";

  const subject = "Invoice Chaser - Sample Follow-up Email";
  const body = `Hi there,

This is a sample follow-up email from Invoice Chaser!

When you use Invoice Chaser, your clients will receive professionally written emails like this one, reminding them about outstanding invoices.

Here's what a real follow-up might look like:

---

Hi [Client Name],

I hope you're doing well. I wanted to follow up on invoice INV-001 for $5,000, which appears to still be outstanding.

I understand things get busy, so I just wanted to send a friendly reminder. Please let me know if you have any questions or if there's anything I can help with to process this payment.

Thanks so much,
[Your Name]

---

Ready to get paid? Sign up at ${APP_URL} and start chasing those invoices!

Best,
The Invoice Chaser Team`;

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: `Invoice Chaser <${fromEmail}>`,
      to: email,
      subject: subject,
      text: body,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to send test email: ${err}`);
  }

  console.log(`Test email sent to ${email}`);
}

async function getInvoices(userId) {
  const result = await db.execute({
    sql: "SELECT * FROM invoices WHERE status = 'active' AND user_id = ?",
    args: [userId],
  });
  return result.rows;
}

async function createInvoice(data, userId) {
  const now = new Date();
  const nextChase = addDays(now, 3);

  const invoice = {
    id: generateId(),
    user_id: userId,
    client_email: data.clientEmail,
    client_name: data.clientName,
    amount: data.amount,
    invoice_number: data.invoiceNumber,
    your_name: data.yourName,
    your_email: data.yourEmail,
    chase_count: 1,
    status: "active",
    created_at: now.toISOString(),
    next_chase: nextChase.toISOString(),
    last_chase: now.toISOString(),
  };

  await sendEmail(invoice);

  await db.execute({
    sql: `INSERT INTO invoices (id, user_id, client_email, client_name, amount, invoice_number, 
              your_name, your_email, chase_count, status, created_at, next_chase, last_chase)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      invoice.id,
      invoice.user_id,
      invoice.client_email,
      invoice.client_name,
      invoice.amount,
      invoice.invoice_number,
      invoice.your_name,
      invoice.your_email,
      invoice.chase_count,
      invoice.status,
      invoice.created_at,
      invoice.next_chase,
      invoice.last_chase,
    ],
  });

  return invoice;
}

async function markPaid(id, userId) {
  const paidAt = new Date().toISOString();
  await db.execute({
    sql: "UPDATE invoices SET status = 'paid', paid_at = ? WHERE id = ? AND user_id = ?",
    args: [paidAt, id, userId],
  });
}

async function stopChasing(id, userId) {
  await db.execute({
    sql: "UPDATE invoices SET status = 'stopped' WHERE id = ? AND user_id = ?",
    args: [id, userId],
  });
}

async function deleteInvoice(id, userId) {
  await db.execute({
    sql: "DELETE FROM invoices WHERE id = ? AND user_id = ?",
    args: [id, userId],
  });
}

async function runChaseCheck() {
  console.log("Running chase check...");

  const result = await db.execute(
    "SELECT * FROM invoices WHERE status = 'active'"
  );
  const now = new Date();
  let emailsSent = 0;

  for (const invoice of result.rows) {
    const nextChase = new Date(invoice.next_chase);

    if (now >= nextChase) {
      const updated = { ...invoice, chase_count: invoice.chase_count + 1 };

      try {
        await sendEmail(updated);

        const newNextChase = addDays(now, 3).toISOString();
        const newLastChase = now.toISOString();

        await db.execute({
          sql: "UPDATE invoices SET chase_count = ?, next_chase = ?, last_chase = ? WHERE id = ?",
          args: [updated.chase_count, newNextChase, newLastChase, invoice.id],
        });

        emailsSent++;
      } catch (err) {
        console.error(`Failed to send chase email: ${err.message}`);
      }
    }
  }

  console.log(`Chase check complete. Sent ${emailsSent} emails.`);
  return emailsSent;
}

// Google OAuth functions
function getGoogleAuthUrl() {
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${APP_URL}/api/auth/google/callback`,
    response_type: "code",
    scope: "openid email profile",
    access_type: "offline",
    prompt: "consent",
  });

  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

async function exchangeCodeForTokens(code) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: `${APP_URL}/api/auth/google/callback`,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Token exchange failed: ${err}`);
  }

  return res.json();
}

async function getGoogleUserInfo(accessToken) {
  const res = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    throw new Error("Failed to get user info");
  }

  return res.json();
}

async function findOrCreateUser(googleUser) {
  // Check if user exists
  const existing = await db.execute({
    sql: "SELECT * FROM users WHERE google_id = ?",
    args: [googleUser.id],
  });

  if (existing.rows.length > 0) {
    return existing.rows[0];
  }

  // Create new user
  const userId = generateId();
  const now = new Date().toISOString();

  await db.execute({
    sql: `INSERT INTO users (id, google_id, email, name, created_at) VALUES (?, ?, ?, ?, ?)`,
    args: [userId, googleUser.id, googleUser.email, googleUser.name, now],
  });

  const result = await db.execute({
    sql: "SELECT * FROM users WHERE id = ?",
    args: [userId],
  });

  return result.rows[0];
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function redirectResponse(url, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: { Location: url, ...headers },
  });
}

function getClientIP(req) {
  // Try various headers for proxied requests
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  const realIP = req.headers.get("x-real-ip");
  if (realIP) {
    return realIP;
  }
  // Fall back to a default for local development
  return "127.0.0.1";
}

async function handler(req) {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // Clean up old rate limits occasionally
  if (Math.random() < 0.01) {
    cleanupRateLimits().catch(console.error);
  }

  // =====================
  // Auth Routes
  // =====================

  // Redirect to Google OAuth
  if (path === "/api/auth/google" && method === "GET") {
    const authUrl = getGoogleAuthUrl();
    return redirectResponse(authUrl);
  }

  // Handle OAuth callback
  if (path === "/api/auth/google/callback" && method === "GET") {
    const code = url.searchParams.get("code");
    const error = url.searchParams.get("error");

    if (error || !code) {
      return redirectResponse("/?error=auth_failed");
    }

    try {
      const tokens = await exchangeCodeForTokens(code);
      const googleUser = await getGoogleUserInfo(tokens.access_token);
      const user = await findOrCreateUser(googleUser);
      const sessionToken = await createSession(user.id);

      return redirectResponse("/dashboard.html", {
        "Set-Cookie": `session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${
          30 * 24 * 60 * 60
        }`,
      });
    } catch (err) {
      console.error("OAuth error:", err);
      return redirectResponse("/?error=auth_failed");
    }
  }

  // Logout
  if (path === "/api/auth/logout" && method === "POST") {
    await deleteSession(req);
    return jsonResponse({ success: true }, 200, {
      "Set-Cookie": "session=; Path=/; HttpOnly; Max-Age=0",
    });
  }

  // Check auth status
  if (path === "/api/auth/me" && method === "GET") {
    const user = await getSessionUser(req);
    if (!user) {
      return jsonResponse({ authenticated: false }, 200);
    }
    return jsonResponse({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  }

  // =====================
  // Test Email Route (Rate Limited)
  // =====================

  if (path === "/api/test-email" && method === "POST") {
    try {
      const data = await req.json();

      // Honeypot check - if this field is filled, it's a bot
      if (data.website) {
        // Silently fail for bots
        return jsonResponse({ success: true });
      }

      if (!data.email) {
        return jsonResponse({ error: "Email is required" }, 400);
      }

      // Basic email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(data.email)) {
        return jsonResponse({ error: "Invalid email address" }, 400);
      }

      const clientIP = getClientIP(req);

      // Check rate limit
      const isLimited = await checkRateLimit(clientIP, "test_email");
      if (isLimited) {
        return jsonResponse(
          {
            error:
              "You've already sent a test email today. Please try again tomorrow.",
          },
          429
        );
      }

      // Send test email
      await sendTestEmail(data.email);

      // Record the rate limit
      await recordRateLimit(clientIP, "test_email");

      return jsonResponse({ success: true });
    } catch (err) {
      console.error("Test email error:", err);
      return jsonResponse({ error: "Failed to send test email" }, 500);
    }
  }

  // =====================
  // Protected Invoice Routes
  // =====================

  if (path === "/api/invoices" && method === "GET") {
    const user = await getSessionUser(req);
    if (!user) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const invoices = await getInvoices(user.id);
    return jsonResponse(invoices);
  }

  if (path === "/api/invoices" && method === "POST") {
    const user = await getSessionUser(req);
    if (!user) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    try {
      const data = await req.json();

      if (
        !data.clientEmail ||
        !data.clientName ||
        !data.amount ||
        !data.invoiceNumber ||
        !data.yourName ||
        !data.yourEmail
      ) {
        return jsonResponse({ error: "Missing required fields" }, 400);
      }

      const invoice = await createInvoice(data, user.id);
      return jsonResponse(invoice, 201);
    } catch (err) {
      console.error(err);
      return jsonResponse({ error: "Failed to create invoice" }, 500);
    }
  }

  if (path.match(/^\/api\/invoices\/[\w-]+\/paid$/) && method === "POST") {
    const user = await getSessionUser(req);
    if (!user) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const id = path.split("/")[3];
    await markPaid(id, user.id);
    return jsonResponse({ status: "paid" });
  }

  if (path.match(/^\/api\/invoices\/[\w-]+\/stop$/) && method === "POST") {
    const user = await getSessionUser(req);
    if (!user) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const id = path.split("/")[3];
    await stopChasing(id, user.id);
    return jsonResponse({ status: "stopped" });
  }

  if (path.match(/^\/api\/invoices\/[\w-]+$/) && method === "DELETE") {
    const user = await getSessionUser(req);
    if (!user) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const id = path.split("/")[3];
    await deleteInvoice(id, user.id);
    return jsonResponse({ success: true });
  }

  // =====================
  // Admin/Cron Routes
  // =====================

  if (path === "/api/cron/chase" && (method === "GET" || method === "POST")) {
    const count = await runChaseCheck();
    return jsonResponse({ emailsSent: count });
  }

  if (path === "/api/health" && method === "GET") {
    const result = await db.execute(
      "SELECT COUNT(*) as count FROM invoices WHERE status = 'active'"
    );
    return jsonResponse({ status: "ok", invoiceCount: result.rows[0].count });
  }

  // =====================
  // Static Files
  // =====================

  return serveDir(req, {
    fsRoot: "public",
    urlRoot: "",
    showIndex: true,
  });
}

serve(handler, { port: 8000 });
