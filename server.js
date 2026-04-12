require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const QRCode = require("qrcode");
const { createClient } = require("@supabase/supabase-js");
const { Resend } = require("resend");
const Jimp = require("jimp");
const path = require("path");

const app = express();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const resend = new Resend(process.env.RESEND_API_KEY);

const TICKET_BASE_PATH = path.join(__dirname, "ingresso_base.png");

// QR position inside the white box (image is 800x1280)
const QR_X = 559;
const QR_Y = 424;
const QR_SIZE = 176;

// ══════════════════════════════════════════════
// FIX #1: Serve admin HTML from Express
// This eliminates CORS issues from opening as file://
// ══════════════════════════════════════════════
app.use(express.static(path.join(__dirname, "public")));

app.use("/webhook/square", express.raw({ type: "application/json" }));
app.use(express.json());

// ══════════════════════════════════════════════
// FIX #2: Tighter CORS — restrict to known origin
// ══════════════════════════════════════════════
app.use(function (req, res, next) {
  var origin = process.env.ADMIN_ORIGIN || "*";
  res.header("Access-Control-Allow-Origin", origin);
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ══════════════════════════════════════════════
// FIX #3: Simple rate limiter (in-memory)
// Prevents brute-force on admin endpoints
// ══════════════════════════════════════════════
var rateLimitMap = {};
function rateLimit(windowMs, maxRequests) {
  return function (req, res, next) {
    var ip = req.ip || req.connection.remoteAddress;
    var now = Date.now();
    if (!rateLimitMap[ip]) rateLimitMap[ip] = [];
    rateLimitMap[ip] = rateLimitMap[ip].filter(function (t) {
      return t > now - windowMs;
    });
    if (rateLimitMap[ip].length >= maxRequests) {
      return res.status(429).json({ error: "Too many requests" });
    }
    rateLimitMap[ip].push(now);
    next();
  };
}

// Clean rate limit map every 5 minutes
setInterval(function () {
  var now = Date.now();
  Object.keys(rateLimitMap).forEach(function (ip) {
    rateLimitMap[ip] = rateLimitMap[ip].filter(function (t) {
      return t > now - 60000;
    });
    if (rateLimitMap[ip].length === 0) delete rateLimitMap[ip];
  });
}, 300000);

function requireAdmin(req, res, next) {
  var token = req.headers.authorization
    ? req.headers.authorization.replace("Bearer ", "").trim()
    : "";
  if (token !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ══════════════════════════════════════════════
// FIX #4: Webhook signature verification
// Prevents anyone from faking purchases
// ══════════════════════════════════════════════
function verifySquareSignature(req) {
  var sigKey = process.env.SQUARE_WEBHOOK_SIGNATURE_KEY;
  var webhookUrl = process.env.SQUARE_WEBHOOK_URL;
  if (!sigKey || !webhookUrl) return false;

  var signature = req.headers["x-square-hmacsha256-signature"];
  if (!signature) return false;

  var body = req.body.toString();
  var hmac = crypto
    .createHmac("sha256", sigKey)
    .update(webhookUrl + body)
    .digest("base64");

  return hmac === signature;
}

async function generateTicketImage(ticketId, qrPayload) {
  var qrBuffer = await QRCode.toBuffer(qrPayload, {
    width: QR_SIZE,
    margin: 1,
    color: { dark: "#000000", light: "#FFFFFF" },
    errorCorrectionLevel: "H",
  });
  var base = await Jimp.read(TICKET_BASE_PATH);
  var qrImg = await Jimp.read(qrBuffer);
  base.composite(qrImg, QR_X, QR_Y);
  var resultBuffer = await base.getBufferAsync(Jimp.MIME_PNG);
  return resultBuffer.toString("base64");
}

// ══════════════════════════════════════════════
// WEBHOOK — now with signature verification
// ══════════════════════════════════════════════
app.post("/webhook/square", async function (req, res) {
  try {
    // FIX #4: Verify webhook signature
    if (!verifySquareSignature(req)) {
      console.warn("Webhook signature verification failed");
      return res.status(401).json({ error: "Invalid signature" });
    }

    var event = JSON.parse(req.body.toString());
    console.log("Square event: " + event.type);
    if (event.type !== "payment.completed") {
      return res.status(200).json({ received: true });
    }
    var payment = event.data.object.payment;
    var orderId = payment.order_id;
    var orderData = await fetchSquareOrder(orderId);
    if (!orderData) return res.status(200).json({ received: true });

    // FIX #5: Process ALL line items, not just the first
    var items = extractAllOrderItems(orderData);

    if (!items.buyerEmail) {
      console.warn("No buyer email found for order: " + orderId);
      return res.status(200).json({ received: true });
    }

    var ticketCount = 0;
    for (var i = 0; i < items.totalQuantity; i++) {
      await createAndSendTicket({
        email: items.buyerEmail,
        name: items.buyerName,
        eventId: items.eventId,
        orderId: orderId,
        paymentId: payment.id,
        ticketIndex: i + 1,
        totalTickets: items.totalQuantity,
      });
      ticketCount++;
    }
    console.log(
      "Processed " + ticketCount + " tickets for order " + orderId
    );
    res.status(200).json({ received: true, tickets: ticketCount });
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

async function createAndSendTicket(opts) {
  var ticketId =
    "CYC-" +
    Date.now() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase();

  var eventResult = await supabase
    .from("events")
    .select("*")
    .eq("id", opts.eventId)
    .single();
  var ev = eventResult.data;
  var eventName = ev ? ev.name : "Cyclone Brazil";
  var eventDate = ev ? ev.date : "Em breve";
  var eventVenue = ev ? ev.venue : "A confirmar";

  var qrPayload = JSON.stringify({
    ticketId: ticketId,
    eventId: opts.eventId,
  });
  var ticketBase64 = await generateTicketImage(ticketId, qrPayload);

  var dbResult = await supabase.from("tickets").insert({
    id: ticketId,
    event_id: opts.eventId,
    order_id: opts.orderId,
    payment_id: opts.paymentId,
    buyer_email: opts.email,
    buyer_name: opts.name,
    status: "valid",
    checked_in: false,
    checked_in_at: null,
    ticket_index: opts.ticketIndex,
    total_tickets: opts.totalTickets,
    qr_data: qrPayload,
    created_at: new Date().toISOString(),
  });
  if (dbResult.error) throw dbResult.error;

  // FIX #6: Wrap email send in try/catch so a Resend failure
  // doesn't crash the whole ticket creation
  try {
    await sendTicketEmail({
      to: opts.email,
      name: opts.name,
      ticketId: ticketId,
      eventName: eventName,
      eventDate: eventDate,
      eventVenue: eventVenue,
      ticketBase64: ticketBase64,
      ticketIndex: opts.ticketIndex,
      totalTickets: opts.totalTickets,
    });
    console.log("Ticket sent: " + ticketId + " -> " + opts.email);
  } catch (emailErr) {
    console.error(
      "Email failed for " + ticketId + " but ticket was created:",
      emailErr.message
    );
  }

  return ticketId;
}

async function sendTicketEmail(opts) {
  var firstName = opts.name ? opts.name.split(" ")[0] : "Convidado";
  var multi =
    opts.totalTickets > 1
      ? "Ingresso " + opts.ticketIndex + " de " + opts.totalTickets
      : "";
  var html =
    "<!DOCTYPE html><html><head><meta charset='UTF-8'></head><body style='margin:0;padding:0;background:#0a0a0a;font-family:Helvetica,Arial,sans-serif;'>" +
    "<table width='100%' cellpadding='0' cellspacing='0' style='background:#0a0a0a;padding:32px 16px;'><tr><td align='center'>" +
    "<table width='500' cellpadding='0' cellspacing='0' style='max-width:500px;width:100%;'>" +
    "<tr><td style='background:linear-gradient(135deg,#c8102e,#8b0000);border-radius:16px 16px 0 0;padding:32px;text-align:center;'>" +
    "<p style='margin:0 0 6px;color:rgba(255,255,255,0.6);font-size:10px;letter-spacing:4px;text-transform:uppercase;'>Cyclone Brazil</p>" +
    "<h1 style='margin:0;color:#fff;font-size:26px;font-weight:900;'>" +
    opts.eventName +
    "</h1>" +
    "<p style='margin:8px 0 0;color:rgba(255,255,255,0.85);font-size:13px;'>" +
    opts.eventDate +
    " &middot; " +
    opts.eventVenue +
    "</p>" +
    "</td></tr>" +
    "<tr><td style='background:#161616;padding:36px;text-align:center;'>" +
    "<h2 style='color:#fff;font-size:20px;margin:0 0 6px;'>Ola, " +
    firstName +
    "!</h2>" +
    "<p style='color:#999;font-size:13px;margin:0 0 24px;'>Seu ingresso esta confirmado. Apresente o QR code na entrada.</p>" +
    (multi
      ? "<p style='color:#c8102e;font-weight:bold;font-size:13px;margin:0 0 16px;'>" +
        multi +
        "</p>"
      : "") +
    "<img src='data:image/png;base64," +
    opts.ticketBase64 +
    "' width='400' style='max-width:100%;border-radius:12px;display:block;margin:0 auto 24px;' alt='Ingresso' />" +
    "<p style='color:#555;font-size:10px;letter-spacing:3px;text-transform:uppercase;margin:0 0 4px;'>Codigo do Ingresso</p>" +
    "<p style='color:#c8102e;font-size:16px;font-weight:800;letter-spacing:2px;font-family:monospace;margin:0 0 28px;'>" +
    opts.ticketId +
    "</p>" +
    "<p style='color:#555;font-size:11px;margin:0;'>Nao compartilhe este ingresso. Cada QR code e de uso unico.<br>" +
    "Duvidas? <a href='mailto:info@cyclonebraziltickets.com' style='color:#c8102e;'>info@cyclonebraziltickets.com</a></p>" +
    "</td></tr>" +
    "<tr><td style='background:#111;border-radius:0 0 16px 16px;padding:16px;text-align:center;'>" +
    "<p style='color:#444;font-size:11px;margin:0;'>cyclonebraziltickets.com</p>" +
    "</td></tr></table></td></tr></table></body></html>";

  await resend.emails.send({
    from: "Cyclone Brazil <tickets@cyclonebraziltickets.com>",
    to: opts.to,
    subject: "Seu Ingresso - " + opts.eventName,
    html: html,
  });
}

// ══════════════════════════════════════════════
// CHECK-IN — with input validation
// ══════════════════════════════════════════════
app.post(
  "/api/checkin",
  requireAdmin,
  rateLimit(60000, 60),
  async function (req, res) {
    var qrData = req.body.qrData;
    if (!qrData || typeof qrData !== "string") {
      return res.status(400).json({ error: "qrData required" });
    }

    // FIX #7: Better input validation
    if (qrData.length > 500) {
      return res.status(400).json({ valid: false, reason: "QR data too long" });
    }

    var parsed;
    try {
      parsed = JSON.parse(qrData);
    } catch (e) {
      return res.status(400).json({ valid: false, reason: "QR invalido" });
    }

    var ticketId = parsed.ticketId;
    if (!ticketId || !ticketId.startsWith("CYC-")) {
      return res
        .status(400)
        .json({ valid: false, reason: "Formato de ingresso invalido" });
    }

    var result = await supabase
      .from("tickets")
      .select("*")
      .eq("id", ticketId)
      .single();
    var ticket = result.data;
    if (!ticket)
      return res
        .status(404)
        .json({ valid: false, reason: "Ingresso nao encontrado" });
    if (ticket.status !== "valid")
      return res
        .status(200)
        .json({ valid: false, reason: "Ingresso invalido", ticket: ticket });
    if (ticket.checked_in)
      return res.status(200).json({
        valid: false,
        reason: "Ingresso ja utilizado",
        checkedInAt: ticket.checked_in_at,
        ticket: ticket,
      });

    await supabase
      .from("tickets")
      .update({ checked_in: true, checked_in_at: new Date().toISOString() })
      .eq("id", ticketId);
    res.json({ valid: true, ticket: ticket });
  }
);

app.get("/api/tickets", requireAdmin, async function (req, res) {
  var query = supabase
    .from("tickets")
    .select("*")
    .order("created_at", { ascending: false });
  if (req.query.event_id) query = query.eq("event_id", req.query.event_id);
  var result = await query;
  if (result.error) return res.status(500).json({ error: result.error });
  res.json(result.data);
});

app.get("/api/events", requireAdmin, async function (req, res) {
  var result = await supabase
    .from("events")
    .select("*")
    .order("date", { ascending: true });
  if (result.error) return res.status(500).json({ error: result.error });
  res.json(result.data);
});

// FIX #8: Input validation on event creation
app.post("/api/events", requireAdmin, async function (req, res) {
  var b = req.body;
  if (!b.name || typeof b.name !== "string" || b.name.trim().length === 0) {
    return res.status(400).json({ error: "Event name is required" });
  }
  var result = await supabase
    .from("events")
    .insert({
      name: b.name.trim(),
      date: b.date || null,
      venue: b.venue || null,
      description: b.description || null,
      square_catalog_id: b.square_catalog_id || null,
    })
    .select()
    .single();
  if (result.error) return res.status(500).json({ error: result.error });
  res.json(result.data);
});

app.post("/api/tickets/:id/resend", requireAdmin, async function (req, res) {
  var ticketIdParam = req.params.id;
  if (!ticketIdParam || !ticketIdParam.startsWith("CYC-")) {
    return res.status(400).json({ error: "Invalid ticket ID" });
  }

  var tr = await supabase
    .from("tickets")
    .select("*")
    .eq("id", ticketIdParam)
    .single();
  var ticket = tr.data;
  if (!ticket) return res.status(404).json({ error: "Not found" });

  var er = await supabase
    .from("events")
    .select("*")
    .eq("id", ticket.event_id)
    .single();
  var ev = er.data;

  var ticketBase64 = await generateTicketImage(ticket.id, ticket.qr_data);
  await sendTicketEmail({
    to: ticket.buyer_email,
    name: ticket.buyer_name,
    ticketId: ticket.id,
    eventName: ev ? ev.name : "Cyclone Brazil",
    eventDate: ev ? ev.date : "",
    eventVenue: ev ? ev.venue : "",
    ticketBase64: ticketBase64,
    ticketIndex: ticket.ticket_index || 1,
    totalTickets: ticket.total_tickets || 1,
  });
  res.json({ sent: true });
});

// ══════════════════════════════════════════════
// FIX #9: Health check endpoint for Railway
// ══════════════════════════════════════════════
app.get("/api/health", function (req, res) {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ══════════════════════════════════════════════
// Square API helpers
// ══════════════════════════════════════════════
async function fetchSquareOrder(orderId) {
  var token = process.env.SQUARE_ACCESS_TOKEN;
  if (!token) return null;
  try {
    var resp = await fetch(
      "https://connect.squareup.com/v2/orders/" + orderId,
      {
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json",
          "Square-Version": "2024-01-17",
        },
      }
    );
    if (!resp.ok) {
      console.error("Square API error: " + resp.status);
      return null;
    }
    var json = await resp.json();
    return json.order;
  } catch (e) {
    console.error("Square fetch error:", e.message);
    return null;
  }
}

// FIX #5: Extract ALL line items, sum total quantity
function extractAllOrderItems(order) {
  var email = null;
  var name = "Convidado";

  if (order.fulfillments && order.fulfillments[0]) {
    var rec = order.fulfillments[0].pickup_details
      ? order.fulfillments[0].pickup_details.recipient
      : null;
    if (rec) {
      email = rec.email_address || null;
      name = rec.display_name || name;
    }
  }
  if (!email && order.customer) {
    email = order.customer.email_address || null;
    name =
      (
        (order.customer.given_name || "") +
        " " +
        (order.customer.family_name || "")
      ).trim() || "Convidado";
  }

  // Sum quantity across ALL line items
  var totalQuantity = 0;
  if (order.line_items && order.line_items.length > 0) {
    for (var i = 0; i < order.line_items.length; i++) {
      totalQuantity += parseInt(order.line_items[i].quantity || "1", 10);
    }
  } else {
    totalQuantity = 1;
  }

  var eventId = process.env.DEFAULT_EVENT_ID || "1";

  return {
    buyerEmail: email,
    buyerName: name,
    eventId: eventId,
    totalQuantity: totalQuantity,
  };
}

var PORT = process.env.PORT || 3001;
app.listen(PORT, function () {
  console.log("Cyclone Brazil Tickets running on port " + PORT);
  console.log("Admin panel: http://localhost:" + PORT + "/admin-checkin.html");
});
