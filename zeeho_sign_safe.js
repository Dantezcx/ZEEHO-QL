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

const CLAIM_BOX_ENABLED = true;

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
// ✅ 四个接口已在 2026-09-02 通过对开源仓库 mlink798/ZEEHO 的逆向确认并实测通过。
//    走 tapi.zeehoev.com 网关（独立于 h5 签到网关），前缀 /v1.0/social/cfmotoserversocial/，
//    签名与签到不同：待签串 = bodyStr(query) + param + APP_SECRET，且 Authorization 带 Bearer 前缀。
// ⚠️ 风险提示：自动发帖+删帖属刷任务行为，内容过于规律可能触发官方风控，请自行评估。

const SOCIAL_BASE = 'https://tapi.zeehoev.com/v1.0/social/cfmotoserversocial';

/** 社区接口开关：开启 post/like/share（打卡核心环）；del 保持关闭（删帖30121权限） */
const COMMUNITY_ENABLED = {
  like: true, // 点赞
  post: true, // 发帖
  share: true, // 分享
  del: false, // 删除（清理自己发的测试帖）
};

/** 互动后领取分享积分（adjustByShare，走 /v1.0/mine/ 网关）：分享成功后调用，让积分入账 */
const CLAIM_POINTS_ENABLED = true;
const MINE_BASE = 'https://tapi.zeehoev.com/v1.0/mine/cfmotoservermine';

/** 社区常量 */
const TS = () => Date.now();
const NONCE = () => TS() + Math.random().toString(36).slice(2, 18);

/** 社区专用签名：md5(sha1(签名体 + param + APP_SECRET))；签名体 POST 取 bodyStr、GET 取 query */
function makeSignApp(signBody) {
  const param = `appId=${APP_ID}&nonce=${NONCE()}&timestamp=${TS()}`;
  const toSign = signBody + param + APP_SECRET;
  const sign = crypto.createHash('md5').update(crypto.createHash('sha1').update(toSign, 'utf8').digest('hex'), 'utf8').digest('hex');
  return { param, sign };
}

/** 社区请求（走 tapi 网关）：GET 用 params 拼 query 并参与签名；POST/DELETE 用 body 参与签名；Authorization 带 Bearer
 *  默认 base 为社交前缀；传 base 可指向 mine 等其它网关域 */
async function socialRequest(method, path, authToken, { body, params, extraHeaders, base = SOCIAL_BASE } = {}) {
  const bodyStr = body !== undefined ? JSON.stringify(body) : undefined;
  const query = params ? Object.keys(params).map((k) => `${k}=${params[k]}`).join('&') : '';
  const fullPath = query ? `${path}?${query}` : path;
  const signBody = bodyStr !== undefined ? bodyStr : query;
  const { param, sign } = makeSignApp(signBody);
  const headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    Authorization: `Bearer ${authToken}`,
    'User-Agent': USER_AGENT,
    'Cfmoto-X-Param': param,
    'Cfmoto-X-Sign': sign,
    'Cfmoto-X-Sign-Type': '0',
    ...extraHeaders,
  };
  if (bodyStr !== undefined) headers['Content-Length'] = Buffer.byteLength(bodyStr);
  return request(`${base}${fullPath}`, { method, headers, body: bodyStr });
}

/** 从各接口响应里递归取帖子 id（mlink798 解析法：优先 tuuid/uuid/postId 等） */
function socialPostId(data) {
  if (!data) return null;
  if (typeof data === 'string' || typeof data === 'number') return String(data);
  if (Array.isArray(data)) return socialPostId(data[0]);
  const direct = data.uuid || data.tuuid || data.postId || data.postid || data.articleId || data.articleID || data.id || data.dataId || data.tid;
  if (direct) return String(direct);
  for (const key of ['records', 'list', 'rows', 'data', 'result']) {
    const postId = socialPostId(data[key]);
    if (postId) return postId;
  }
  return null;
}

/** 读取自己的动态列表（mineArticleInfo），找到最近一条，返回其 tuuid（帖子 id） */
async function socialMinePostId(authToken, userId) {
  const res = await socialRequest('GET', '/community/mineArticleInfo', authToken, {
    params: { userId, page: 1, pageSize: 10 },
  });
  return socialPostId(res && res.data);
}

/** 分享积分确认（adjustByShare，走 /v1.0/mine/ 网关）：分享成功后调用，让分享积分入账 */
async function mineAdjustByShare(authToken) {
  const res = await socialRequest('GET', '/integral/adjustByShare', authToken, { base: MINE_BASE });
  return res && res.code === '10000';
}

/** 查询当前总积分（GET /v1.0/mine/cfmotoservermine/setting/{userId}），失败返回 null */
async function fetchTotalScore(authToken, userId) {
  try {
    const res = await socialRequest('GET', `/setting/${userId}`, authToken, { base: MINE_BASE });
    return res && res.code === '10000' ? res.data.score : null;
  } catch (e) {
    return null;
  }
}

/** 社区任务闭环：发帖 -> 取 id -> 点赞 -> 分享 -> 删除（按开关依次执行） */
async function runCommunityTasks(authToken, user, tag) {
  const lines = [];
  const anyOn = Object.values(COMMUNITY_ENABLED).some(Boolean);
  if (!anyOn) {
    console.log(`[${tag}] 社区任务前 4 项未启用（接口已备好，见 COMMUNITY_ENABLED）`);
    return lines;
  }

  // 1) 发帖：POST commonArticle，body = { postcontent }，成功返回 code=10000 但无 id
  if (COMMUNITY_ENABLED.post) {
    try {
      const res = await socialRequest('POST', '/commonArticle', authToken, { body: { postcontent: '开心的一天' } });
      const ok = res && res.code === '10000';
      lines.push(`[发帖] ${ok ? '成功' : `失败 ${JSON.stringify(res).slice(0, 120)}`}`);
    } catch (e) {
      lines.push(`[发帖] 异常：${e.message}`);
    }
  }

  // 2) 取自己的帖子 id（发帖接口不回 id，需读列表），判断有无可操作的帖子
  let postId = null;
  try {
    postId = await socialMinePostId(authToken, user.id);
  } catch (e) {
    console.log(`[${tag}] 读取列表失败：${e.message}`);
  }
  if (!postId) {
    lines.push('[互动] 未取得帖子 id，跳过点赞/分享/删除');
    return lines;
  }
  lines.push(`[互动] 帖子 id=${postId}`);

  // 3) 点赞：POST socialCommu/likeFavoriteInfo，body = { postId, kindFlag:"0" }
  if (COMMUNITY_ENABLED.like) {
    try {
      const res = await socialRequest('POST', '/socialCommu/likeFavoriteInfo', authToken, { body: { postId: String(postId), kindFlag: '0' } });
      lines.push(`[点赞] ${res && res.code === '10000' ? '成功' : `失败 ${JSON.stringify(res).slice(0, 120)}`}`);
    } catch (e) {
      lines.push(`[点赞] 异常：${e.message}`);
    }
  }

  // 4) 分享：PUT article/share/{postId}（无 body）
  if (COMMUNITY_ENABLED.share) {
    try {
      const res = await socialRequest('PUT', `/article/share/${postId}`, authToken);
      const ok = res && res.code === '10000';
      lines.push(`[分享] ${ok ? '成功' : `失败 ${JSON.stringify(res).slice(0, 120)}`}`);
      // 分享成功后确认积分，让分享积分入账（与 mlink798 一致）
      if (ok && CLAIM_POINTS_ENABLED) {
        const ok2 = await mineAdjustByShare(authToken);
        lines.push(`[分享积分] ${ok2 ? '已入账' : '触发失败'}`);
      }
    } catch (e) {
      lines.push(`[分享] 异常：${e.message}`);
    }
  }

  // 5) 删除（清理自己发的测试帖）：DELETE commonArticle/deleteArticle?articleId=&postType=1
  if (COMMUNITY_ENABLED.del) {
    try {
      const res = await socialRequest('DELETE', `/commonArticle/deleteArticle?articleId=${postId}&postType=1`, authToken);
      lines.push(`[删除] ${res && res.code === '10000' ? '成功' : `失败 ${JSON.stringify(res).slice(0, 120)}`}`);
    } catch (e) {
      lines.push(`[删除] 异常：${e.message}`);
    }
  }

  // 6) 查询当前总积分（每次跑完最后输出）
  const score = await fetchTotalScore(authToken, user.id);
  lines.push(score !== null ? `[当前总积分] ${score}` : '[当前总积分] 查询失败');

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
