// A tiny stand-in for a Shopify app backend, for trying the probe locally.
// node examples/demo-app-server.mjs            -> vulnerable on :3456
// SECURE=1 node examples/demo-app-server.mjs   -> fixed
import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

const SECRET = process.env.SHOPIFY_API_SECRET ?? "demo-secret";
const SECURE = process.env.SECURE === "1";
const PORT = Number(process.env.PORT ?? 3456);
const DATA = {
  "shopify-app-audit-probe.myshopify.com": { reviews: 12, email: "owner@probe.example" },
  "shopify-app-audit-other.myshopify.com": { reviews: 40, email: "owner@other.example" },
};

const safeEqual = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function validWebhook(raw, header) {
  if (!header) return false;
  return safeEqual(createHmac("sha256", SECRET).update(raw).digest("base64"), header);
}

function validProxy(searchParams) {
  const params = Object.fromEntries(searchParams);
  const { signature = "", ...rest } = params;
  const message = Object.keys(rest).sort().map((k) => `${k}=${rest[k]}`).join("");
  return safeEqual(createHmac("sha256", SECRET).update(message).digest("hex"), signature);
}

export function createDemoServer({ secure = SECURE } = {}) {
  return createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks).toString("utf8");
    const shop = url.searchParams.get("shop") ?? "";

    if (url.pathname.startsWith("/webhooks") && req.method === "POST") {
      if (secure && !validWebhook(raw, req.headers["x-shopify-hmac-sha256"])) return res.writeHead(401).end();
      return res.writeHead(200).end();
    }
    if (url.pathname.startsWith("/proxy")) {
      if (secure && !validProxy(url.searchParams)) return res.writeHead(401).end();
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify(DATA[shop] ?? {}));
    }
    if (url.pathname.startsWith("/app")) {
      if (secure) {
        res.writeHead(200, {
          "content-type": "text/html",
          "content-security-policy": `frame-ancestors https://admin.shopify.com https://${shop};`,
          "strict-transport-security": "max-age=31536000",
        });
        return res.end("<html><head><title>Authenticate</title></head><body>app bridge bootstrap</body></html>");
      }
      res.writeHead(200, { "content-type": "application/json", "content-security-policy": "frame-ancestors *" });
      return res.end(JSON.stringify(DATA[shop] ?? {}));
    }
    res.writeHead(404).end();
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  createDemoServer().listen(PORT, () =>
    console.log(`demo app (${SECURE ? "secure" : "vulnerable"}) on http://localhost:${PORT}`),
  );
}
