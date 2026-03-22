/**
 * Dispatch Worker — routes {name}.openfused.dev to customer Workers.
 * Uses Workers for Platforms dispatch namespace to find the right Worker.
 * If no customer Worker exists, returns 404.
 *
 * Deploy this as a single Worker on *.openfused.dev wildcard route.
 * It extracts the subdomain and dispatches to the named Worker in the namespace.
 */

interface Env {
  DISPATCHER: DispatchNamespace;
}

interface DispatchNamespace {
  get(name: string): { fetch: typeof fetch };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const hostname = url.hostname;

    // Extract subdomain: carlos.openfused.dev → carlos
    const parts = hostname.split(".");
    if (parts.length < 3) {
      return new Response("Not found", { status: 404 });
    }
    const subdomain = parts[0];

    // Skip known subdomains that aren't customer mailboxes
    if (["www", "registry", "inbox", "api"].includes(subdomain)) {
      return new Response("Not found", { status: 404 });
    }

    // Dispatch to customer Worker
    try {
      const worker = env.DISPATCHER.get(subdomain);
      return await worker.fetch(request);
    } catch {
      return new Response(
        JSON.stringify({ error: `Mailbox '${subdomain}' not found` }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }
  },
};
