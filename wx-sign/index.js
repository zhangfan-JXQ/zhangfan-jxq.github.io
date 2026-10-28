/**
 * 微信 JS-SDK 分享签名服务
 *
 * 启动：
 *   WX_APP_ID=xxx WX_APP_SECRET=xxx ALLOWED_ORIGINS=https://your-domain.com node index.js
 *
 * 前端调用：
 *   GET https://sign.your-domain.com/wx-sign?url=<当前页面完整 URL，不含 #>
 *   返回 { appId, timestamp, nonceStr, signature }
 */
const express = require("express");
const crypto = require("crypto");

const APP_ID = process.env.WX_APP_ID || "";
const APP_SECRET = process.env.WX_APP_SECRET || "";
const PORT = process.env.PORT || 3000;

// 允许调用签名的页面域名，防止签名接口被他人盗用
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// access_token / jsapi_ticket 缓存（微信有效期 7200s，提前 200s 刷新）
const cache = {
  accessToken: { value: "", expiresAt: 0 },
  jsapiTicket: { value: "", expiresAt: 0 }
};

const sha1 = (str) =>
  crypto.createHash("sha1").update(str, "utf8").digest("hex");

const randomStr = () =>
  crypto.randomBytes(8).toString("hex").slice(0, 16);

async function getJson(url) {
  const res = await fetch(url);
  const data = await res.json();
  if (data.errcode) {
    throw new Error(`微信接口返回错误 ${data.errcode}: ${data.errmsg}`);
  }
  return data;
}

async function getAccessToken() {
  if (cache.accessToken.value && Date.now() < cache.accessToken.expiresAt) {
    return cache.accessToken.value;
  }
  const data = await getJson(
    `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${APP_ID}&secret=${APP_SECRET}`
  );
  cache.accessToken.value = data.access_token;
  cache.accessToken.expiresAt = Date.now() + (data.expires_in - 200) * 1000;
  return data.access_token;
}

async function getJsapiTicket() {
  if (cache.jsapiTicket.value && Date.now() < cache.jsapiTicket.expiresAt) {
    return cache.jsapiTicket.value;
  }
  const token = await getAccessToken();
  const data = await getJson(
    `https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=${token}&type=jsapi`
  );
  cache.jsapiTicket.value = data.ticket;
  cache.jsapiTicket.expiresAt = Date.now() + (data.expires_in - 200) * 1000;
  return data.ticket;
}

const app = express();

app.get("/wx-sign", async (req, res) => {
  res.set("Access-Control-Allow-Origin", req.get("origin") || "*");
  res.set("Vary", "Origin");

  const pageUrl = String(req.query.url || "");
  if (!pageUrl) {
    return res.status(400).json({ error: "缺少 url 参数" });
  }

  // 校验请求来源域名，避免签名接口被任意站点盗用
  if (ALLOWED_ORIGINS.length) {
    const origin = req.get("origin") || "";
    let host = "";
    try {
      host = new URL(pageUrl).host;
    } catch (_) {
      return res.status(400).json({ error: "url 参数非法" });
    }
    const ok =
      ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes(host);
    if (!ok) {
      return res.status(403).json({ error: "域名未授权" });
    }
  }

  try {
    const ticket = await getJsapiTicket();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonceStr = randomStr();
    const raw = `jsapi_ticket=${ticket}&noncestr=${nonceStr}&timestamp=${timestamp}&url=${pageUrl.split("#")[0]}`;

    res.json({
      appId: APP_ID,
      timestamp,
      nonceStr,
      signature: sha1(raw)
    });
  } catch (error) {
    console.error("签名失败:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`微信签名服务已启动: http://localhost:${PORT}`);
  console.log(`APP_ID: ${APP_ID ? "已配置" : "未配置"}`);
});
