/**
 * Provisioning API — handles Stripe webhooks and customer lifecycle.
 * Creates R2 bucket, deploys Worker, creates DNS TXT on signup.
 * Tears down on cancellation.
 *
 * Stripe webhook events:
 *   checkout.session.completed → provision new mailbox
 *   customer.subscription.deleted → tear down mailbox
 */

interface ProvisionEnv {
  STRIPE_WEBHOOK_SECRET: string;
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CF_ZONE_ID: string;  // openfused.net
  DNS_DOMAIN: string;  // openfused.net
  DISPATCH_NAMESPACE: string; // openfused-mailboxes
}

interface StripeEvent {
  type: string;
  data: {
    object: {
      id: string;
      customer: string;
      metadata?: { agent_name?: string; endpoint?: string };
      subscription?: string;
    };
  };
}

export default {
  async fetch(request: Request, env: ProvisionEnv): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env);
    }

    if (url.pathname === "/health") {
      return new Response("ok");
    }

    return new Response("Not found", { status: 404 });
  },
};

async function handleWebhook(request: Request, env: ProvisionEnv): Promise<Response> {
  const body = await request.text();

  // Verify Stripe webhook signature (HMAC-SHA256)
  const sig = request.headers.get("stripe-signature");
  if (!sig || !env.STRIPE_WEBHOOK_SECRET) {
    return new Response("Missing signature", { status: 401 });
  }

  const verified = await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!verified) {
    return new Response("Invalid signature", { status: 403 });
  }

  let event: StripeEvent;
  try {
    event = JSON.parse(body);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  switch (event.type) {
    case "checkout.session.completed":
      return await provisionMailbox(event, env);
    case "customer.subscription.deleted":
      return await teardownMailbox(event, env);
    default:
      return new Response("OK", { status: 200 });
  }
}

async function provisionMailbox(event: StripeEvent, env: ProvisionEnv): Promise<Response> {
  const name = event.data.object.metadata?.agent_name;
  if (!name) return new Response("Missing agent_name in metadata", { status: 400 });

  const safeName = name.toLowerCase().replace(/[^a-z0-9_-]/g, "");

  // Reject reserved names, empty names, and names that are too short/long
  const RESERVED = new Set(["www", "registry", "inbox", "api", "mail", "admin", "support", "openfuse", "openfused", "app", "dashboard", "billing"]);
  if (!safeName || safeName.length < 2 || safeName.length > 32 || RESERVED.has(safeName)) {
    return new Response(JSON.stringify({ error: "Invalid or reserved name" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const bucketName = `openfused-${safeName}`;
  const headers = {
    "Authorization": `Bearer ${env.CF_API_TOKEN}`,
    "Content-Type": "application/json",
  };

  // 1. Create R2 bucket
  await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/r2/buckets`, {
    method: "POST",
    headers,
    body: JSON.stringify({ name: bucketName }),
  });

  // 2. Initialize store — write default PROFILE.md and .mesh.json
  // (R2 API doesn't support direct object creation from Workers easily,
  //  so the customer's first `openfuse register` call will populate these)

  // 3. Create DNS TXT record
  const endpoint = `https://${safeName}.openfused.dev`;
  await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      type: "TXT",
      name: `_openfuse.${safeName}.${env.DNS_DOMAIN}`,
      content: `v=of1 e=${endpoint}`,
      ttl: 300,
    }),
  });

  // 4. Deploy customer Worker to dispatch namespace
  // TODO: use Workers for Platforms API to upload the mailbox template
  // bound to the customer's R2 bucket

  return new Response(JSON.stringify({ ok: true, name: safeName, endpoint }), {
    status: 201,
    headers: { "Content-Type": "application/json" },
  });
}

async function teardownMailbox(event: StripeEvent, env: ProvisionEnv): Promise<Response> {
  const name = event.data.object.metadata?.agent_name;
  if (!name) return new Response("OK", { status: 200 });

  const safeName = name.replace(/[^a-zA-Z0-9_-]/g, "");
  const headers = {
    "Authorization": `Bearer ${env.CF_API_TOKEN}`,
    "Content-Type": "application/json",
  };

  // 1. Delete DNS TXT record
  const dnsResp = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?type=TXT&name=_openfuse.${safeName}.${env.DNS_DOMAIN}`,
    { headers }
  );
  const dnsData = await dnsResp.json() as { result?: { id: string }[] };
  if (dnsData.result && dnsData.result.length > 0) {
    await fetch(
      `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${dnsData.result[0].id}`,
      { method: "DELETE", headers }
    );
  }

  // 2. Remove Worker from dispatch namespace
  // TODO: Workers for Platforms API delete

  // 3. R2 bucket — keep for 30 days (grace period), then delete
  // TODO: schedule deletion

  return new Response(JSON.stringify({ ok: true, name: safeName, status: "deprovisioned" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// --- Stripe signature verification ---
// Stripe signs webhooks with HMAC-SHA256 using the webhook secret.
// Format: t={timestamp},v1={signature}
async function verifyStripeSignature(body: string, sigHeader: string, secret: string): Promise<boolean> {
  try {
    const parts: Record<string, string> = {};
    for (const item of sigHeader.split(",")) {
      const [key, value] = item.split("=", 2);
      parts[key.trim()] = value;
    }

    const timestamp = parts["t"];
    const expectedSig = parts["v1"];
    if (!timestamp || !expectedSig) return false;

    // Verify timestamp is within 5 minutes (prevents replay)
    const age = Math.abs(Date.now() / 1000 - parseInt(timestamp));
    if (age > 300) return false;

    // Compute expected signature
    const payload = `${timestamp}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
    const computed = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");

    // Constant-time comparison — prevents timing-based signature brute-force
    if (computed.length !== expectedSig.length) return false;
    const a = new TextEncoder().encode(computed);
    const b = new TextEncoder().encode(expectedSig);
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  } catch {
    return false;
  }
}
