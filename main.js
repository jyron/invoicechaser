import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { serveDir } from "https://deno.land/std@0.208.0/http/file_server.ts";
import { createClient } from "https://esm.sh/@libsql/client@0.4.0/web";

const db = createClient({
  url: Deno.env.get("TURSO_URL") || "",
  authToken: Deno.env.get("TURSO_AUTH_TOKEN") || "",
});

await db.execute(`
    CREATE TABLE IF NOT EXISTS invoices (
        id TEXT PRIMARY KEY,
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
        paid_at TEXT
    )
`);

function generateId() {
  return crypto.randomUUID();
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
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

I hope you're doing well. I wanted to follow up on invoice ${invoice.invoice_number} for ${invoice.amount}, which appears to still be outstanding.

I understand things get busy, so I just wanted to send a friendly reminder. Please let me know if you have any questions or if there's anything I can help with to process this payment.

Thanks so much,
${invoice.your_name}`;
  } else if (invoice.chase_count === 2) {
    body = `Hi ${invoice.client_name},

Just wanted to check in again on invoice ${invoice.invoice_number} for ${invoice.amount}. I sent a note a few days ago but wanted to make sure it didn't slip through the cracks.

If there are any issues with the invoice or payment, I'm happy to help sort them out.

Best,
${invoice.your_name}`;
  } else if (invoice.chase_count === 3) {
    body = `Hi ${invoice.client_name},

I'm following up once more on invoice ${invoice.invoice_number} for ${invoice.amount}. This is the third time I've reached out, so I want to make sure everything is okay on your end.

If there's a problem with the invoice or you need different payment terms, please let me know and we can work something out.

Thanks,
${invoice.your_name}`;
  } else {
    body = `Hi ${invoice.client_name},

I've reached out several times now about invoice ${invoice.invoice_number} for ${invoice.amount} and haven't heard back. I'd really appreciate an update on when I can expect payment.

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

async function getInvoices() {
  const result = await db.execute(
    "SELECT * FROM invoices WHERE status = 'active'"
  );
  return result.rows;
}

async function createInvoice(data) {
  const now = new Date();
  const nextChase = addDays(now, 3);

  const invoice = {
    id: generateId(),
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
    sql: `INSERT INTO invoices (id, client_email, client_name, amount, invoice_number, 
              your_name, your_email, chase_count, status, created_at, next_chase, last_chase)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      invoice.id,
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

async function markPaid(id) {
  const paidAt = new Date().toISOString();
  await db.execute({
    sql: "UPDATE invoices SET status = 'paid', paid_at = ? WHERE id = ?",
    args: [paidAt, id],
  });
}

async function stopChasing(id) {
  await db.execute({
    sql: "UPDATE invoices SET status = 'stopped' WHERE id = ?",
    args: [id],
  });
}

async function deleteInvoice(id) {
  await db.execute({
    sql: "DELETE FROM invoices WHERE id = ?",
    args: [id],
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

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function handler(req) {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // API routes
  if (path === "/api/invoices" && method === "GET") {
    const invoices = await getInvoices();
    return jsonResponse(invoices);
  }

  if (path === "/api/invoices" && method === "POST") {
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

      const invoice = await createInvoice(data);
      return jsonResponse(invoice, 201);
    } catch (err) {
      console.error(err);
      return jsonResponse({ error: "Failed to create invoice" }, 500);
    }
  }

  if (path.match(/^\/api\/invoices\/[\w-]+\/paid$/) && method === "POST") {
    const id = path.split("/")[3];
    await markPaid(id);
    return jsonResponse({ status: "paid" });
  }

  if (path.match(/^\/api\/invoices\/[\w-]+\/stop$/) && method === "POST") {
    const id = path.split("/")[3];
    await stopChasing(id);
    return jsonResponse({ status: "stopped" });
  }

  if (path.match(/^\/api\/invoices\/[\w-]+$/) && method === "DELETE") {
    const id = path.split("/")[3];
    await deleteInvoice(id);
    return jsonResponse({ success: true });
  }

  if (path === "/api/cron/chase" && (method === "GET" || method === "POST")) {
    const count = await runChaseCheck();
    return jsonResponse({ emailsSent: count });
  }

  if (path === "/api/health" && method === "GET") {
    const invoices = await getInvoices();
    return jsonResponse({ status: "ok", invoiceCount: invoices.length });
  }

  // Serve static files
  return serveDir(req, {
    fsRoot: "public",
    urlRoot: "",
    showIndex: true,
  });
}

console.log("Invoice Chaser running on http://localhost:8000");
serve(handler, { port: 8000 });
