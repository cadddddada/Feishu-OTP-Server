// Edge Function: KV 代理（供 Python 云函数读写 KV 存储）
// 路由: /api/kv（由文件路径 edge-functions/api/kv/index.js 决定）
// KV 绑定: 命名空间 TOTP_SERVER，绑定变量名 KV_NAMESPACE（运行时作为全局对象注入）
// 鉴权: 请求头 X-KV-Proxy-Token 必须等于环境变量 KV_PROXY_TOKEN，否则拒绝
//
// 协议:
//   GET    /api/kv?key=<key>      读取，成功返回原始文本(200)，不存在返回 404
//   PUT    /api/kv                写入，body: {"key": "...", "value": "..."}
//   DELETE /api/kv?key=<key>      删除

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

export async function onRequest({ request, env }) {
  const token = request.headers.get("x-kv-proxy-token") || "";
  if (!env.KV_PROXY_TOKEN || token !== env.KV_PROXY_TOKEN) {
    return json({ ok: false, error: "forbidden" }, 403);
  }

  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  try {
    if (method === "GET") {
      const key = url.searchParams.get("key");
      if (!key) {
        return json({ ok: false, error: "missing key" }, 400);
      }
      const value = await KV_NAMESPACE.get(key);
      if (value === null || value === undefined) {
        return json({ ok: false, error: "not found" }, 404);
      }
      return new Response(value, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    if (method === "PUT") {
      const body = await request.json().catch(() => ({}));
      const key = body && body.key;
      const value = body && body.value;
      if (!key || typeof value !== "string") {
        return json({ ok: false, error: "invalid body" }, 400);
      }
      await KV_NAMESPACE.put(key, value);
      return json({ ok: true });
    }

    if (method === "DELETE") {
      const key = url.searchParams.get("key");
      if (!key) {
        return json({ ok: false, error: "missing key" }, 400);
      }
      await KV_NAMESPACE.delete(key);
      return json({ ok: true });
    }

    return json({ ok: false, error: "method not allowed" }, 405);
  } catch (e) {
    return json({ ok: false, error: String((e && e.message) || e) }, 500);
  }
}
