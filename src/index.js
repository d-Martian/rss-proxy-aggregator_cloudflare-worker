const ALLOWED_TARGET_HOSTS = new Set([
  "xmrchain.net",
  "localmonero.co",
  "agoradesk.com",
  "monero.observer",
  "revuo-xmr.com",
  "feeds.fireside.fm",
  "moneroresearch.info",
  "www.themoneromoon.com",
  "bounties.monero.social",
  "ccs.getmonero.org",
  "monerochan.news",
  "forum.monerochan.news",
  "bitejo.com",
  "moneromarket.io",
  "acceptedhere.io",
  "monerica.com",
  "tg.i-c-a.su",
  "www.reddit.com",
  "nitter.net",
]);

const ALLOWED_ORIGINS = new Set([
  "https://d-martian.github.io",
  "https://xmrdance.trade",
  "https://www.xmrdance.trade",
  "https://xmrdance.trade",
  "http://localhost:8787",
  "http://127.0.0.1:8787",
  "http://localhost:8000",
  "http://127.0.0.1:8000",
  "https://rss.xmrdance.workers.dev",
]);

function getAllowedOrigin(origin) {
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    return origin;
  }
  return "https://xmrdance.trade";
}

function buildCorsHeaders(origin) {
  const allowOrigin = getAllowedOrigin(origin);

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,HEAD,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,If-Modified-Since,If-None-Match",
    "Access-Control-Expose-Headers": "Content-Type,Content-Length,ETag,Last-Modified,Cache-Control",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(data, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers,
  });
}

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin") || "";
    const corsHeaders = buildCorsHeaders(origin);
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return json(
        { error: "Method not allowed" },
        { status: 405, headers: corsHeaders },
      );
    }

    if (url.pathname === "/health") {
      return json(
        {
          ok: true,
          service: "rss-proxy",
          time: new Date().toISOString(),
        },
        { headers: corsHeaders },
      );
    }

    if (url.pathname !== "/" && url.pathname !== "/proxy") {
      return json(
        {
          error: "Not found",
          usage: "/proxy?url=https%3A%2F%2Fexample.com%2Ffeed.xml",
        },
        { status: 404, headers: corsHeaders },
      );
    }

    const targetParam = url.searchParams.get("url");
    if (!targetParam) {
      return json(
        { error: "Missing url query parameter" },
        { status: 400, headers: corsHeaders },
      );
    }

    let target;
    try {
      target = new URL(targetParam);
    } catch {
      return json(
        { error: "Invalid url parameter" },
        { status: 400, headers: corsHeaders },
      );
    }

    if (target.protocol !== "https:") {
      return json(
        { error: "Only https:// URLs are allowed" },
        { status: 400, headers: corsHeaders },
      );
    }

    if (!ALLOWED_TARGET_HOSTS.has(target.hostname)) {
      return json(
        { error: `Host not allowed: ${target.hostname}` },
        { status: 403, headers: corsHeaders },
      );
    }

    const upstreamHeaders = new Headers();

    const accept = request.headers.get("Accept");
    if (accept) upstreamHeaders.set("Accept", accept);

    const ifNoneMatch = request.headers.get("If-None-Match");
    const ifModifiedSince = request.headers.get("If-Modified-Since");
    if (ifNoneMatch) upstreamHeaders.set("If-None-Match", ifNoneMatch);
    if (ifModifiedSince) upstreamHeaders.set("If-Modified-Since", ifModifiedSince);

    let upstream;
    try {
      upstream = await fetch(target.toString(), {
        method: request.method,
        headers: upstreamHeaders,
        redirect: "follow",
        cf: {
          cacheEverything: true,
          cacheTtlByStatus: {
            "200-299": 900,
            "404": 60,
            "500-599": 0,
          },
        },
      });
    } catch (error) {
      return json(
        {
          error: "Upstream fetch failed",
          detail: error instanceof Error ? error.message : String(error),
        },
        { status: 502, headers: corsHeaders },
      );
    }

    const headers = new Headers(upstream.headers);

    headers.set("Access-Control-Allow-Origin", corsHeaders["Access-Control-Allow-Origin"]);
    headers.set("Access-Control-Allow-Methods", corsHeaders["Access-Control-Allow-Methods"]);
    headers.set("Access-Control-Allow-Headers", corsHeaders["Access-Control-Allow-Headers"]);
    headers.set("Access-Control-Expose-Headers", corsHeaders["Access-Control-Expose-Headers"]);
    headers.set("Access-Control-Max-Age", corsHeaders["Access-Control-Max-Age"]);
    headers.set("Vary", "Origin");

    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Cache-Control", "public, max-age=300, s-maxage=900, stale-while-revalidate=86400");

    headers.delete("Set-Cookie");
    headers.delete("set-cookie");
    headers.delete("Content-Security-Policy");
    headers.delete("X-Frame-Options");

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  },
};
