/**
 * ZEEHO（极核/春风动力）每日自动签到 + 补签盲盒 · 青龙面板版（脱敏修改版）
 *
 * 移植自 Scriptable 小组件脚本（ZEEHO.pretty.js）与快捷指令 ZEEHO自动签到R.2.1，
 * 业务接口、请求头与签名算法与 App 完全一致：
 *   sign = md5(sha1("server_name=SMART" + "appId=<APP_ID>&nonce=<uuid>&timestamp=<ms>" + APP_SECRET))
 *
 * ── 与原版差异（脱敏）──────────────────────────────────
 *   1. APP_ID / APP_SECRET 改为从环境变量读取（ZEEHO_APP_ID / ZEEHO_APP_SECRET）
 *      缺失时直接抛错退出，避免误把空值当作签名材料。
 *   2. User-Agent 中原硬编码的设备指纹 UUID 改为：
 *        优先取环境变量 ZEEHO_DEVICE_ID；未配置则每次运行随机生成。
 *      避免长期固定设备指纹被服务端风控画像。
 *
 * ── 功能 ────────────────────────────────────────────────
 *   1. 每日自动签到（fetchUserInfo → getSignInfo → doSign）
 *   2. 连签满 30 天自动领取补签盲盒（claimBoxPrize，默认关闭，见 CLAIM_BOX_ENABLED）
 *
 * ── 使用方法 ─────────────────────────────────────────────
 * 1. 青龙面板 -> 脚本管理 -> 新建 zeeho_sign_safe.js，粘贴本文件
 * 2. 环境变量添加（共 4 个）：
 *    - ZEEHO_APP_ID        原脚本里的 APP_ID
 *    - ZEEHO_APP_SECRET    原脚本里的 APP_SECRET（40 位 hex）
 *    - ZEEHO_AUTH_TOKEN    ZEEHO App 抓包得到的 authorization
 *                          中 "Bearer " 之后的那段 UUID（不含 Bearer、空格与换行）。
 *                          多账号用 & 或换行分隔，例如：
 *                          11111111-aaaa-2222-bbbb-333333333333&44444444-cccc-5555-dddd-666666666666
 *    - ZEEHO_DEVICE_ID（可选）固定设备指纹 UUID；不配置则每次随机
 * 3. 定时任务示例（每天 08:30 签到）：
 *      30 8 * * * task zeeho_sign_safe.js
 * 4. 连签满 30 天想领盲盒：把下方 CLAIM_BOX_ENABLED 改为 true 即可
 *    （未满 30 天会返回 code=40005"不存在的盲盒"，属正常，无需理会）
 *
 * ── 声明 ────────────────────────────────────────────────
 * 仅供学习交流与个人使用，请勿泄露 APP_ID/APP_SECRET/令牌等敏感凭证。
 */

'use strict';

const https = require('https');
const crypto = require('crypto');

// ====== 常量（敏感值改为从环境变量读取） ======
const APP_ID = process.env.ZEEHO_APP_ID || '';
const APP_SECRET = process.env.ZEEHO_APP_SECRET || '';
if (!APP_ID || !APP_SECRET) {
  throw new Error('未配置 ZEEHO_APP_ID / ZEEHO_APP_SECRET 环境变量，脚本退出。');
}

const BASE_URL = 'https://h5.zeehoev.com';
const BASE_INFO_PATH = '/cfmotoservermine/baseInfo?server_name=SMART';
const SIGNIN_PATH = '/cfmotoservermine/signin?server_name=SMART';
// 设备指纹：优先用环境变量，未配置则每次运行随机生成（避免长期固定指纹被风控）
const DEVICE_ID = process.env.ZEEHO_DEVICE_ID || uuid();
const USER_AGENT =
  'Mozilla/5.0 (Linux; Android 14; PA2353) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36' +
  `MOBILE|iOS|18.7.2|ZEEHO_APP|2.6.6|iPhone|iPhone15|1179*2556|${DEVICE_ID}|WiFi|iOS`;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TIMEOUT = 15000;

// ====== 工具函数 ======

/** UUID v4（优先 crypto.randomUUID，低版本 Node 降级手写） */
function uuid() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** 生成签名参数对：Cfmoto-X-Param 与 Cfmoto-X-Sign */
function makeSign() {
  const param = `appId=${APP_ID}&nonce=${uuid()}&timestamp=${Date.now()}`;
  const toSign = 'server_name=SMART' + param + APP_SECRET;
  const sha1Hex = crypto.createHash('sha1').update(toSign, 'utf8').digest('hex');
  const sign = crypto.createHash('md5').update(sha1Hex, 'utf8').digest('hex');
  return { param, sign };
}

/** 公共请求头（对应原脚本三个接口的公共部分） */
function buildHeaders(authToken, param, sign) {
  return {
    Accept: 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    Authorization: `Bearer ${authToken}`,
    'Cfmoto-X-Param': param,
    'Cfmoto-X-Sign': sign,
    'Cfmoto-X-Sign-Type': '0',
    Connection: 'keep-alive',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'User-Agent': USER_AGENT,
  };
}

/** 极简 https 请求（零依赖），返回解析后的 JSON 或原始字符串 */
function request(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers, timeout: TIMEOUT }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** 统一校验业务响应（原脚本判定 code === "10000"） */
function assertOk(res, action) {
  if (res && res.code === '10000') return;
  const detail = res && (res.msg || res.message) ? res.msg || res.message : JSON.stringify(res);
  throw new Error(`${action}失败：${detail}`);
}

/** 固定按东八区计算"今天"（YYYY-MM-DD），避免部署机时区影响 */
function beijingToday() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}

// ====== 业务接口（对应原脚本 fetchUserInfo / getSignInfo / doSign） ======

/** 带签名的通用请求：签到与社区任务共用。GET 不带体；POST 无体时补 Content-Length: 0；有 body 时按 JSON 发送 */
async function signedRequest(method, path, authToken, { userId, body, extraHeaders } = {}) {
  const { param, sign } = makeSign();
  const headers = {
    ...buildHeaders(authToken, param, sign),
    ...(userId !== undefined ? { user_id: userId } : {}),
    ...(body !== undefined
      ? { 'Content-Type': 'application/json;charset=UTF-8', 'Content-Length': Buffer.byteLength(body) }
      : method === 'POST'
        ? { 'Content-Length': '0' }
        : {}),
    ...extraHeaders,
  };
  return request(`${BASE_URL}${path}`, { method, headers, body });
}

/** GET 用户信息 -> { id, avatar, nickName } */
async function fetchUserInfo(authToken) {
  const res = await signedRequest('GET', BASE_INFO_PATH, authToken, {
    extraHeaders: {
      // 原脚本仅用户信息接口携带的指纹头
      'Zeeho-User-Agent': USER_AGENT,
      'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
      'sec-ch-ua-mobile': '?1',
      'sec-ch-ua-platform': '"Android"',
    },
  });
  assertOk(res, '获取用户信息');
  return { id: res.data.id, avatar: res.data.avatar, nickName: res.data.nickName };
}

/** GET 签到状态 -> { updateTime, lastTime, continueDays } */
async function getSignInfo(authToken, userId) {
  const res = await signedRequest('GET', SIGNIN_PATH, authToken, { userId });
  assertOk(res, '查询签到状态');
  return {
    updateTime: res.data.updateTime,
    lastTime: res.data.lastTime,
    continueDays: res.data.continueDays,
  };
}

/** POST 执行签到（无请求体）-> "签到成功" / "已签到" / "未知" / "签到失败" */
async function doSign(authToken, userId) {
  const res = await signedRequest('POST', SIGNIN_PATH, authToken, { userId });
  if (res && res.code === '10000') {
    if (res.data.signInStatus === 0) return '签到成功';
    if (res.data.signInStatus === 1) return '已签到';
    return '未知';
  }
  return '签到失败';
}

// ====== 签到盲盒（第30天发放）：还原自快捷指令 ZEEHO自动签到R.2.1 ======
// 接口：GET /cfmotoservermine/signin/supplementPrize?supplementDate=<prizeDate>
// 签名：signatureParam = "appId=<APP_ID>&nonce=<uuid>&timestamp=<秒>"
//       toSign        = "supplementDate=" + prizeDate + signatureParam + APP_SECRET
//       sign          = md5(sha1(toSign))          （与签到同型，前缀多 supplementDate）
// 响应：{ code, message, prizesName }，code="10000" 为领取成功
// ⚠️ 盲盒在「连续签到第30天」才发放，平时调用会返回 code=40005"不存在的盲盒"。
//    默认 enabled=false，待连签满30天再打开即可。

const CLAIM_BOX_ENABLED = false;

/** 连续签到满 30 天时领取补签盲盒（供外部在连签满30天后调用） */
async function claimBoxPrize(authToken, user) {
  const prizeDate = beijingToday(); // supplementDate 取当前日期 YYYY-MM-DD
  const signatureParam = `appId=${APP_ID}&nonce=${uuid()}&timestamp=${Date.now()}`;
  const toSign = `supplementDate=${prizeDate}` + signatureParam + APP_SECRET;
  // 与 makeSign 同型：md5(sha1(...))，但待签串前缀含 supplementDate
  const sha1Hex = crypto.createHash('sha1').update(toSign, 'utf8').digest('hex');
  const sign = crypto.createHash('md5').update(sha1Hex, 'utf8').digest('hex');
  const url = `${BASE_URL}/cfmotoservermine/signin/supplementPrize?supplementDate=${prizeDate}`;
  const headers = {
    ...buildHeaders(authToken, signatureParam, sign),
    user_id: user.id,
    'Content-Length': '0',
  };
  const res = await request(url, { method: 'GET', headers });
  if (res && res.code === '10000') return `盲盒领取成功：${res.prizesName || ''}`;
  return `盲盒未领取（${res ? res.code + ' ' + (res.message || '') : '无响应'}）`;
}

// ====== 社区任务：点赞 / 发帖 / 分享 / 删帖 ======
// ⚠️ 这四个接口未包含在原逆向脚本中，公开渠道也没有文档，需要先对 App 抓包：
//    打开抓包工具(reqable/Charles/stream) -> 打开 ZEEHO App 依次执行对应操作 ->
//    抄下 请求方法 + 路径 + 请求体 JSON，填到下面 TODO 处并把 enabled 改为 true。
// ⚠️ 风险提示：自动发帖+删帖属于刷任务行为，内容过于规律可能触发官方风控，请自行评估。
// ⚠️ 注意：删帖通常需要帖子 id（来自发帖响应），接口补齐后建议改成"发帖->取id->删除"的专用函数，
//    而不是用这个通用配置表硬编码 id。

const COMMUNITY_TASKS = {
  // 点赞（进入任意帖子点一次赞）
  like: { enabled: false, method: 'POST', path: '/TODO_点赞接口', body: {} },
  // 首次发帖（发布一条新帖，标题/内容按抓包到的字段名填）
  post: { enabled: false, method: 'POST', path: '/TODO_发帖接口', body: { title: 'TODO', content: 'TODO' } },
  // 分享（仅当 App 分享时产生上报请求才可脚本化；纯前端调起系统分享面板则无法实现）
  share: { enabled: false, method: 'POST', path: '/TODO_分享上报接口', body: {} },
  // 删除帖子（DELETE 或 POST 以抓包为准）
  del: { enabled: false, method: 'DELETE', path: '/TODO_删帖接口' },
};

/** 依次执行已启用的社区任务，返回结果行（未配置的记为跳过） */
async function runCommunityTasks(authToken, user, tag) {
  const lines = [];
  for (const [name, t] of Object.entries(COMMUNITY_TASKS)) {
    if (!t.enabled) continue;
    if (t.path.includes('TODO')) {
      lines.push(`[${name}] 接口未配置，已跳过`);
      continue;
    }
    try {
      const body = t.body !== undefined && t.body !== null ? JSON.stringify(t.body) : undefined;
      const res = await signedRequest(t.method, t.path, authToken, { userId: user.id, body });
      console.log(`[${tag}] ${name} 响应：`, JSON.stringify(res));
      const ok = res && res.code === '10000';
      lines.push(`[${name}] ${ok ? '成功' : `失败 ${JSON.stringify(res).slice(0, 150)}`}`);
    } catch (e) {
      lines.push(`[${name}] 异常：${e.message}`);
    }
  }
  if (!lines.length) console.log(`[${tag}] 未启用社区任务（点赞/发帖/分享/删帖）`);
  return lines;
}

// ====== 青龙通知（优先 QLAPI，其次 sendNotify，最后仅打印日志） ======

async function notify(title, content) {
  try {
    if (typeof QLAPI !== 'undefined' && typeof QLAPI.notify === 'function') {
      await QLAPI.notify(title, content);
      return;
    }
  } catch (e) { /* ignore */ }
  const notifyPaths = ['./sendNotify', '/ql/scripts/sendNotify.js', '/ql/data/scripts/sendNotify.js'];
  for (const p of notifyPaths) {
    try {
      const mod = require(p);
      const sendNotify = mod.sendNotify || mod;
      if (typeof sendNotify === 'function') {
        await sendNotify(title, content);
        return;
      }
    } catch (e) { /* ignore */ }
  }
  console.log(`（未找到青龙通知模块，仅打印）${title}\n${content}`);
}

// ====== 单账号主流程（对应原脚本 bootstrap） ======

async function signAccount(token, tag) {
  if (!UUID_RE.test(token)) throw new Error('令牌格式错误（应为 UUID）');
  const user = await fetchUserInfo(token);
  console.log(`[${tag}] 用户：${user.nickName}`);
  const info = await getSignInfo(token, user.id);
  const lastDate = (info.lastTime || '').slice(0, 10);
  let status;
  if (lastDate === beijingToday()) {
    status = `今日已签到 ✔ 连签 ${info.continueDays} 天（${info.lastTime}）`;
  } else {
    status = `${await doSign(token, user.id)}，连签 ${info.continueDays} 天`;
  }
  console.log(`[${tag}] ${status}`);
  const lines = [`【${tag} ${user.nickName}】${status}`];
  // 连签满30天发放盲盒，仅在开启开关时领取（未满30天会返回 code=40005，无需理会）
  if (CLAIM_BOX_ENABLED) {
    const box = await claimBoxPrize(token, user);
    lines.push(`[盲盒] ${box}`);
  }
  lines.push(...(await runCommunityTasks(token, user, tag)));
  const m = lines.join('\n');
  console.log(m);
  return m;
}

// ====== 入口 ======

(async () => {
  const raw = process.env.ZEEHO_AUTH_TOKEN || '';
  const tokens = raw.split(/[\n&]/).map((s) => s.trim()).filter(Boolean);
  if (!tokens.length) {
    console.log('未配置环境变量 ZEEHO_AUTH_TOKEN，脚本退出。');
    return;
  }
  const messages = [];
  for (let i = 0; i < tokens.length; i++) {
    const tag = `账号${i + 1}`;
    try {
      messages.push(await signAccount(tokens[i], tag));
    } catch (e) {
      const m = `【${tag}】执行失败：${e.message}`;
      console.log(m);
      messages.push(m);
    }
  }
  await notify('ZEEHO 签到结果', messages.join('\n\n'));
})();
