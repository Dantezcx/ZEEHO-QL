# ZEEHO 青龙面板签到脚本

> 青龙面板（QingLong）上运行的 ZEEHO（春风动力）App 每日自动签到脚本，零依赖纯 Node.js 实现。
>
> 接口、签名算法与 ZEEHO App 完全一致：`sign = md5(sha1("server_name=SMART" + param + APP_SECRET))`。

---

## 功能

- 每日自动签到（查询签到状态 → 未签则补签）
- 连续签到满 30 天可自动领取补签盲盒（默认关闭，需手动开启）
- 多账号支持（环境变量用 `&` 或换行分隔）
- 社区任务占位接口（点赞 / 发帖 / 分享 / 删帖，需自行抓包补全路径）
- 青龙通知（自动适配 QLAPI / sendNotify）

---

## 凭证获取（关键前提）

脚本需要 3 个凭证，**全部由你自行获取，仓库不含任何密钥**：

| 变量名 | 来源 | 获取方式 |
|--------|------|----------|
| `ZEEHO_APP_ID` | App 签名参数 | 抓包 ZEEHO App 任意接口请求头 `Cfmoto-X-Param` 里的 `appId=xxx&...` 段，或反编译 App |
| `ZEEHO_APP_SECRET` | App 签名密钥 | **只能通过反编译 ZEEHO App 获取**（不在网络流量里出现）。无逆向能力者需向有此密钥的人索取 |
| `ZEEHO_AUTH_TOKEN` | 用户登录态 | 抓包 ZEEHO App 任意接口请求头 `Authorization: Bearer <token>` 中 Bearer 之后那段 UUID |
| `ZEEHO_DEVICE_ID`（可选） | 设备指纹 UUID | 不配则每次运行随机生成；想固定指纹可填一个标准 UUID |

### 抓包步骤（拿 AUTH_TOKEN）

1. 手机装抓包工具：iOS 用 **Stream**，Android 用 **Reqable** / **Charles**
2. 抓包工具装好根证书并信任（Stream 自带，Charles 需手动装）
3. ZEEHO App 登录账号后随便点一下页面（如打开"我的"页）
4. 在抓包历史里找到任一访问 `h5.zeehoev.com` 的请求
5. 复制 `Authorization` 头里 `Bearer ` 后面那段 UUID 字符串

### 反编译步骤（拿 APP_SECRET，门槛较高）

> APP_SECRET 不出现在网络请求里，是 App 本地用于计算签名的密钥，必须从 App 二进制里挖出来。

1. 用 [jadx](https://github.com/skylot/jadx) 或 [apktool](https://apktool.org/) 反编译 ZEEHO.apk
2. 在反编译产物里全局搜索字符串 `appId=` 或 `Cfmoto-X-Sign`，定位签名构造函数
3. 跟踪到 `md5(sha1(server_name=SMART + param + APP_SECRET))` 处，APP_SECRET 即附近硬编码的 40 位 hex 字符串
4. APP_ID 在同一函数附近，8 位字母数字

> 不想反编译？那就用不了这个脚本——这是脱敏分享的代价。

---

## 安装

### 1. 放脚本

把 [zeeho_sign_safe.js](zeeho_sign_safe.js) 上传到青龙面板「脚本管理」，或直接粘贴新建。

### 2. 配环境变量

青龙面板 → 环境变量 → 新建，添加 3 条（多账号场景见下方"多账号"）：

```
ZEEHO_APP_ID        = 你的 APP_ID
ZEEHO_APP_SECRET    = 你的 APP_SECRET（40 位 hex）
ZEEHO_AUTH_TOKEN    = 你的 Bearer UUID
# 可选：
ZEEHO_DEVICE_ID     = 固定设备指纹 UUID
```

### 3. 加定时任务

青龙面板 → 定时任务 → 新建：

| 字段 | 值 |
|------|----|
| 名称 | ZEEHO 每日签到 |
| 命令 | `task zeeho_sign_safe.js` |
| 定时规则 | `30 8 * * *`（每天 08:30） |

保存后可点"运行"立即测试一次。

---

## 多账号

`ZEEHO_AUTH_TOKEN` 用 `&` 或换行分隔多个 token：

```
11111111-aaaa-2222-bbbb-333333333333&44444444-cccc-5555-dddd-666666666666
```

`ZEEHO_APP_ID` / `ZEEHO_APP_SECRET` 是 App 通用密钥，**所有账号共用同一对**，不用配多份。

---

## 可选功能

### 连签满 30 天领盲盒

[zeeho_sign_safe.js](zeeho_sign_safe.js#L100) 顶部把 `CLAIM_BOX_ENABLED` 改为 `true`：

```js
const CLAIM_BOX_ENABLED = true;
```

未满 30 天调用会返回 `code=40005 "不存在的盲盒"`，属正常现象，无需处理。

### 社区任务（点赞/发帖/分享/删帖）

脚本预留了 4 个社区任务占位接口（[zeeho_sign_safe.js#L130](zeeho_sign_safe.js) 起），**默认全部关闭**，需要你自行抓包补全：

1. 抓包 ZEEHO App 在社区里依次执行"点赞 / 发帖 / 分享 / 删帖"
2. 把每个接口的 `method` + `path` + `body` JSON 抄进 `COMMUNITY_TASKS` 对应字段
3. 把对应任务的 `enabled` 改为 `true`

> 风险提示：自动发帖+删帖属于刷任务行为，内容过于规律可能触发官方风控，请自行评估。
> 删帖接口通常需要帖子 id（来自发帖响应），建议改成"发帖→取 id→删除"专用函数而非硬编码。

---

## 验证

运行后查看青龙日志，正常应输出类似：

```
[账号1] 用户：你的昵称
[账号1] 签到成功，连签 X 天
【账号1 你的昵称】签到成功，连签 X 天
```

如果报错：

| 错误 | 原因 |
|------|------|
| `未配置 ZEEHO_APP_ID / ZEEHO_APP_SECRET` | 环境变量没加 |
| `令牌格式错误（应为 UUID）` | `ZEEHO_AUTH_TOKEN` 复制时带了 `Bearer ` 前缀或空格 |
| `获取用户信息失败：xxx` | token 过期或被风控，需重新抓包 |
| `签到失败：xxx` | 多半是 IP 触发风控（短时间内请求过多），换 IP / 等冷却后重试 |

---

## 风险提示

- **凭证不要外传**：`ZEEHO_APP_SECRET` 是 ZEEHO App 的通用签名密钥，大规模泄露后官方可能换密钥/加风控，**影响包括你在内的所有用户**
- **频率温和**：脚本本身只发 3 个请求（用户信息/签到状态/签到），不会触发风控；但同一 IP 短时间内多次手动运行仍可能被 WAF 拦截
- **token 时效**：`ZEEHO_AUTH_TOKEN` 是登录态，会过期，过期后需重新抓包获取
- **本脚本仅供学习交流与个人使用**，请尊重 ZEEHO 服务条款

---

## 签名算法（脚本内部已实现，无需手动处理）

```
param   = "appId=" + APP_ID + "&nonce=" + uuid + "&timestamp=" + Date.now()
toSign  = "server_name=SMART" + param + APP_SECRET
sign    = md5( sha1( toSign ) )              // 嵌套双哈希

请求头：
  Cfmoto-X-Param      : param
  Cfmoto-X-Sign       : sign
  Cfmoto-X-Sign-Type  : "0"
  Authorization       : "Bearer " + ZEEHO_AUTH_TOKEN
  user_id             : <从 baseInfo 接口拿到的用户 id>
```

补签盲盒接口签名在 `toSign` 前缀多拼一段 `supplementDate=<日期>`，其余同型。

---

## FAQ

**Q：为什么仓库里没有 APP_SECRET？**
A：它是 ZEEHO App 的通用密钥，泄露后官方可能反制所有用户。脱敏分享是为了让脚本能长期可用。需自行反编译 App 获取。

**Q：跑了一段时间突然失败怎么办？**
A：先看日志报错。token 过期（最常见）→ 重新抓包；IP 被风控 → 换网络/等冷却；App 升级换了密钥 → 重新反编译。

**Q：支持 Scriptable（iOS 桌面组件）吗？**
A：本仓库只放青龙版。Scriptable 版（`ZEEHO.pretty.js`）的逆向分析见仓库历史记录，本仓库不分享该文件。

**Q：社区任务怎么补？**
A：见上方"可选功能 → 社区任务"，必须自己抓包，每个 ZEEHO App 版本的接口路径可能不同。

---

## 声明

本项目为 ZEEHO App 接口的个人逆向产物，仅供学习交流与个人使用。请勿：
- 将 `APP_SECRET` 等敏感凭证上传到任何公开渠道
- 用于商业用途或批量注册/薅羊毛等违反服务条款的行为
- 传播修改后的版本用于规避官方风控

使用本脚本产生的一切后果由使用者自行承担。
