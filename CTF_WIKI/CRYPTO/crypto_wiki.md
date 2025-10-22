# [Week1] Strange Machine

写一个完整的 write-up（新手友好）——从原理到可复现脚本（step-by-step）

恭喜你拿到 flag！下面我把整个过程从头到尾、**对新手友好**地讲清楚：题目背景、漏洞点、利用思路、数学/实现细节、最终自动化脚本、如何在远程服务上复现，以及防御建议。照着做你就能完全理解并复现这个题目。

---

## 一、题目（服务）核心要点（一句话总结）

服务用一个固定长度 `seed`（随机字节串）作为**伪一次性密钥流**，每次 `generate()` 会把 `seed` 按固定字节数 `offset` 旋转一次得到新的 key，并用 `key ⊕ pad(msg)` 来做“加密”。程序会把第一次加密（`plaintext` 的密文）输出一次给你，并允许你提交任意消息进行加密多次（得到对应密文），还允许你把明文提交给它校验。目标是还原第一次的 `plaintext`（即 flag）。

关键漏洞：**可选择明文 + 密钥只在 seed 上旋转**（不是完全新生成） ⇒ 我们能通过对若干轮固定明文的加密得到一组 keystream（key），其中一定会包含第一次打印出来的 keystream 的某个旋转，从而得到 `plaintext`。

---

## 二、基本概念与数学（为什么可行）

* 记 `msg_len` 为固定块长度（题目里是 16）。
* 程序对 `msg` 调用 `pad(msg)` 使其长度 = `msg_len`（用 `pad_len * long_to_bytes(pad_len)` 填充）。如果你发送恰好 `msg_len` 字节的消息，就**不会被填充**，pad(msg) == msg。
* 每次加密使用的 `key` 是 `seed` 的循环旋转（每次 `generate()` 把 `seed = seed[offset:] + seed[:offset]`）。所以 `key` 属于 `seed` 的旋转族（有限集合）。
* 设初始展示的密文为 `cipher1 = pad(plaintext) ⊕ s1`。如果我们收集到某一轮的 keystream `sk`（通过向服务加密已知字符串得出：`ct = pad(known) ⊕ sk` ⇒ `sk = ct ⊕ pad(known)`），那么 `plaintext` 的候选就是 `pad(plaintext) = cipher1 ⊕ sk`。
* 若 `pad(plaintext)` 可去掉填充并匹配常见 flag 格式（例如含 `flag{}` 或可打印字符串），则找到了 flag。

周期长度（最多需要尝试的轮数）：

* 种子长度为 `msg_len`，每次旋转 `offset` 字节，种子状态数的周期为 `L = msg_len / gcd(msg_len, offset)`（最坏情况 `L = msg_len`）。所以我们只需收集至周期回到已收集的 keystream 为止即可覆盖所有可能的 keystream。

---

## 三、利用思路（简洁步骤）

1. 从服务启动时的输出读取第一次的密文 `cipher1`（base64）。
2. 推断 `msg_len`（通常就是 `len(base64_decoded_cipher1)`）。
3. 构造一个已知消息 `chosen = b'A' * msg_len`（长度正好为 `msg_len`，避免填充）。
4. 重复调用“1. 加密消息”，每次都发送 `chosen`，解析返回的 base64 密文 `ct_i`，算出 `ks_i = ct_i ⊕ chosen`（即该轮的 keystream）。
5. 收集 `ks_i`，直到看到重复（周期到来）。这会给你一个包含 `s1` 的 keystream集合（某个 `ks_i` 等于 `s1`）。
6. 对每个 `ks_i` 做 `candidate = cipher1 ⊕ ks_i`。取 `candidate` 去掉填充（如果存在）并检查是否是可读 flag（例如含 `flag{}` 或 ASCII 可打印）。
7. 把可读候选通过菜单选项 2 提交验证（服务器会在匹配时返回 flag 环节中存的 FLAG 环境变量）。

---

## 四、示例交互（手工步骤）

如果你在 netcat 里连接（`nc challenge...`），可按这个顺序手工做（说明性的）：

1. 看到 `[*] 首次密文(base64):b'...'` 记录下（例如 `K4Wj...`）。
2. 选择 `1` 并在提示输入消息时输入 `AAAAAAAAAAAAAAAA`（长度等于 16）并回车，记录返回的 base64 密文 `ct1`。
3. 再次选择 `1`，继续发送 `AAAAAAAAAAAAAAAA`，记录 `ct2`，依次重复直到观察到 keystream重复（一般不会太多轮）。
4. 对每个 `ct_i` 计算 `ks_i = base64decode(ct_i) ⊕ b"A"*16`。
5. 对每个 `ks_i` 计算 `cand = base64decode(first_cipher) ⊕ ks_i`，尝试 `cand.decode()` 或去填充后 decode，看是否可读；可读且像 `Oh,you find it!` 或 `flag{...}` 的就是 plaintext。
6. 把该 plaintext 通过菜单 `2` 提交以获得 FLAG。

你实际已经按这个流程做到了，并得到 `Oh,you find it!`，提交后服务给出 flag：
`flag{3298a5aa-78d2-44c7-9539-fb234e1eb501}`。

---

## 五、完整自动化脚本（最稳健的一版，直接连接并完成所有步骤）

把下面保存为 `exploit_final.py`，在 Kali 上运行即可（只需要 Python 标准库）：

<pre class="overflow-visible!" data-start="2515" data-end="7435"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>#!/usr/bin/env python3</span><span>
</span><span># exploit_final.py</span><span>
</span><span># Usage: python3 exploit_final.py</span><span>
</span><span># Connects to challenge.ilovectf.cn:30609, collects keystreams, computes candidates and optionally auto-submits printable ones.</span><span>

</span><span>import</span><span> socket, re, base64, time

HOST = </span><span>"challenge.ilovectf.cn"</span><span>
PORT = </span><span>30609</span><span>

</span><span>def</span><span> </span><span>bxor</span><span>(</span><span>a: bytes</span><span>, b: </span><span>bytes</span><span>) -> </span><span>bytes</span><span>:
    </span><span>return</span><span> </span><span>bytes</span><span>(x ^ y </span><span>for</span><span> x, y </span><span>in</span><span> </span><span>zip</span><span>(a, b))

</span><span>def</span><span> </span><span>unpad_pkcs_like</span><span>(</span><span>p: bytes</span><span>):
    </span><span># Try simple PKCS# style single-byte padding (most typical here)</span><span>
    </span><span>if</span><span> </span><span>not</span><span> p:
        </span><span>return</span><span> </span><span>None</span><span>
    pad_len = p[-</span><span>1</span><span>]
    </span><span>if</span><span> pad_len == </span><span>0</span><span> </span><span>or</span><span> pad_len > </span><span>len</span><span>(p):
        </span><span>return</span><span> </span><span>None</span><span>
    </span><span>if</span><span> p.endswith(</span><span>bytes</span><span>([pad_len]) * pad_len):
        </span><span>return</span><span> p[:-pad_len]
    </span><span>return</span><span> </span><span>None</span><span>

</span><span>def</span><span> </span><span>recv_until</span><span>(</span><span>sock, token_str, timeout=5.0</span><span>):
    sock.settimeout(timeout)
    data = </span><span>b""</span><span>
    </span><span>try</span><span>:
        </span><span>while</span><span> </span><span>True</span><span>:
            chunk = sock.recv(</span><span>4096</span><span>)
            </span><span>if</span><span> </span><span>not</span><span> chunk:
                </span><span>break</span><span>
            data += chunk
            </span><span>try</span><span>:
                text = data.decode(</span><span>'utf-8'</span><span>, errors=</span><span>'ignore'</span><span>)
            </span><span>except</span><span>:
                text = data.decode(</span><span>'latin1'</span><span>, errors=</span><span>'ignore'</span><span>)
            </span><span>if</span><span> token_str </span><span>in</span><span> text:
                </span><span>return</span><span> data, text
    </span><span>except</span><span> socket.timeout:
        </span><span>pass</span><span>
    </span><span># return whatever we have</span><span>
    </span><span>try</span><span>:
        </span><span>return</span><span> data, data.decode(</span><span>'utf-8'</span><span>, errors=</span><span>'ignore'</span><span>)
    </span><span>except</span><span>:
        </span><span>return</span><span> data, data.decode(</span><span>'latin1'</span><span>, errors=</span><span>'ignore'</span><span>)

</span><span>def</span><span> </span><span>extract_b64_from_text</span><span>(</span><span>text</span><span>):
    </span><span># look specifically for "首次密文" line, otherwise first base64-like token</span><span>
    m = re.search(</span><span>r"首次密文.*?:\s*([bB]?['\"]?([A-Za-z0-9+/=]+)['\"]?)"</span><span>, text)
    </span><span>if</span><span> m:
        </span><span>return</span><span> m.group(</span><span>2</span><span>)
    m2 = re.search(</span><span>r"([A-Za-z0-9+/=]{8,})"</span><span>, text)
    </span><span>return</span><span> m2.group(</span><span>1</span><span>) </span><span>if</span><span> m2 </span><span>else</span><span> </span><span>None</span><span>

</span><span>def</span><span> </span><span>try_submit_candidate</span><span>(</span><span>sock, candidate_bytes</span><span>):
    </span><span># submit via menu option 2; expects candidate_bytes to be utf-8 printable</span><span>
    </span><span>try</span><span>:
        sock.sendall(</span><span>b"2\n"</span><span>)
        _, prompt = recv_until(sock, </span><span>"请输入待校验的明文:"</span><span>, timeout=</span><span>2.0</span><span>)
        sock.sendall(candidate_bytes + </span><span>b"\n"</span><span>)
        _, resp = recv_until(sock, </span><span>"\n"</span><span>, timeout=</span><span>2.0</span><span>)
        </span><span>return</span><span> resp
    </span><span>except</span><span> Exception:
        </span><span>return</span><span> </span><span>None</span><span>

</span><span>def</span><span> </span><span>main</span><span>():
    s = socket.socket()
    s.connect((HOST, PORT))

    </span><span># read until menu</span><span>
    data, text = recv_until(s, </span><span>"请输入你的选择:"</span><span>, timeout=</span><span>4.0</span><span>)
    </span><span>print</span><span>(text)

    </span><span># parse initial cipher presented by server</span><span>
    b64_first = extract_b64_from_text(text)
    </span><span>if</span><span> </span><span>not</span><span> b64_first:
        </span><span>print</span><span>(</span><span>"[!] 未能解析首次密文"</span><span>)
        s.close()
        </span><span>return</span><span>
    cipher1 = base64.b64decode(b64_first)
    msg_len = </span><span>len</span><span>(cipher1)
    </span><span>print</span><span>(</span><span>f"[*] 初次密文（base64）：{b64_first}</span><span>  长度=</span><span>{msg_len}</span><span>")

    </span><span># collect keystreams by repeatedly encrypting chosen plaintext of exact msg_len</span><span>
    chosen = </span><span>b"A"</span><span> * msg_len
    seen = </span><span>set</span><span>()
    keystreams = []

    </span><span>for</span><span> i </span><span>in</span><span> </span><span>range</span><span>(</span><span>1</span><span>, msg_len * </span><span>2</span><span> + </span><span>6</span><span>):
        </span><span># choose option 1</span><span>
        s.sendall(</span><span>b"1\n"</span><span>)
        _, _ = recv_until(s, </span><span>"请输入要加密的消息"</span><span>, timeout=</span><span>2.0</span><span>)
        s.sendall(chosen + </span><span>b"\n"</span><span>)
        </span><span># read response</span><span>
        data_ct, text_ct = recv_until(s, </span><span>"\n"</span><span>, timeout=</span><span>2.0</span><span>)
        </span><span># read a small extra chunk</span><span>
        extra, extra_text = recv_until(s, </span><span>"\n"</span><span>, timeout=</span><span>0.7</span><span>)
        text_ct += extra_text

        b64tok = extract_b64_from_text(text_ct)
        </span><span>if</span><span> </span><span>not</span><span> b64tok:
            </span><span>print</span><span>(</span><span>"[!] 无法解析第 %d 次返回的密文，输出片段如下："</span><span> % i)
            </span><span>print</span><span>(text_ct)
            </span><span>break</span><span>
        ct = base64.b64decode(b64tok)
        ks = bxor(ct, chosen[:</span><span>len</span><span>(ct)])
        </span><span>if</span><span> ks </span><span>in</span><span> seen:
            </span><span>print</span><span>(</span><span>f"[*] keystream 在第 {i}</span><span> 轮后重复，结束采集")
            </span><span>break</span><span>
        seen.add(ks)
        keystreams.append(ks)
        </span><span>print</span><span>(</span><span>f"[*] 收集到 keystream #{len</span><span>(keystreams)}")
        time.sleep(</span><span>0.02</span><span>)

    </span><span>print</span><span>(</span><span>f"[*] 共收集到 {len</span><span>(keystreams)} 个不同 keystream，开始尝试候选 plaintext ...")

    </span><span>for</span><span> idx, ks </span><span>in</span><span> </span><span>enumerate</span><span>(keystreams):
        </span><span>if</span><span> </span><span>len</span><span>(ks) != </span><span>len</span><span>(cipher1):
            </span><span>continue</span><span>
        cand_padded = bxor(cipher1, ks)
        cand = unpad_pkcs_like(cand_padded)
        </span><span>if</span><span> cand </span><span>is</span><span> </span><span>None</span><span>:
            cand = cand_padded
        </span><span># print both hex and utf8 if possible</span><span>
        </span><span>try</span><span>:
            printable = cand.decode(</span><span>'utf-8'</span><span>)
        </span><span>except</span><span>:
            printable = </span><span>None</span><span>
        </span><span>print</span><span>(</span><span>f"\n[Candidate {idx}</span><span>] raw-hex: </span><span>{cand.hex</span><span>()}")
        </span><span>if</span><span> printable:
            </span><span>print</span><span>(</span><span>f"[Candidate {idx}</span><span>] utf8: </span><span>{printable}</span><span>")
        </span><span>else</span><span>:
            </span><span>print</span><span>(</span><span>"[Candidate %d] 非 utf8 可打印"</span><span> % idx)

        </span><span># if printable and looks like an English message or contains flag{}, try auto submit</span><span>
        </span><span>if</span><span> printable </span><span>and</span><span> ((</span><span>"flag"</span><span> </span><span>in</span><span> printable.lower()) </span><span>or</span><span> </span><span>"{"</span><span> </span><span>in</span><span> printable </span><span>or</span><span> </span><span>all</span><span>(</span><span>32</span><span> <= </span><span>ord</span><span>(c) <= </span><span>126</span><span> </span><span>for</span><span> c </span><span>in</span><span> printable)):
            </span><span>print</span><span>(</span><span>"[*] 似乎可打印，尝试自动提交以验证..."</span><span>)
            resp = try_submit_candidate(s, cand)
            </span><span>print</span><span>(</span><span>"[*] 提交返回片段："</span><span>, resp)
            </span><span># if response contains "这是你的flag" or "flag{" then success</span><span>
            </span><span>if</span><span> resp </span><span>and</span><span> (</span><span>"这是你的flag"</span><span> </span><span>in</span><span> resp </span><span>or</span><span> </span><span>"flag{"</span><span> </span><span>in</span><span> resp.lower()):
                </span><span>print</span><span>(</span><span>"[+] 看起来成功获取到 flag："</span><span>, resp)
                s.close()
                </span><span>return</span><span>

    </span><span>print</span><span>(</span><span>"[-] 未能自动验证出 flag，请把 Candidate 输出贴上来或手工在交互会话提交候选明文。"</span><span>)
    s.close()

</span><span>if</span><span> __name__ == </span><span>"__main__"</span><span>:
    main()
</span></span></code></div></div></pre>

---

## 六、你在实战中看到的输出解释（对应你的案例）

你运行脚本后看到的 `Candidate 3 => Oh,you find it!` 就是 `cipher1 ⊕ ks` 得到的结果（它没有被填充或被正确去填充）。把它通过菜单选项 2 提交后服务返回：

<pre class="overflow-visible!" data-start="7571" data-end="7635"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>[*]</span><span> 这是你的flag: flag{</span><span>3298</span><span>a5aa-</span><span>78</span><span>d2-</span><span>44</span><span>c7-</span><span>9539</span><span>-fb234e1eb501}
</span></span></code></div></div></pre>

这就是最终 flag。

---

## 七、调试与常见问题

* **Base64 解析失败 / 中文 prompt 导致 bytes 字面量错误**：不要把非 ASCII 字符放到 `b"..."`。使用 `str` 匹配（`"请输入你的选择:"`）再 `.encode()` 发送，或者用 `recv` 收到 bytes 再 `decode('utf-8', errors='ignore')` 去找中文提示。
* **keystream 长度与 cipher1 不匹配**：说明你推断的 `msg_len` 有误（应该用第一次 base64 解码长度作为 `msg_len`）。务必先解码 `首次密文` 得到长度。
* **填充格式不同**：原代码用 `long_to_bytes(pad_len)` 填充。对 pad\_len ≤ 255，`long_to_bytes(pad_len)` 只是单字节等于 pad\_len，所以和常见 PKCS#7 类似。脚本尝试了单字节判断并在失败时把未去填充的候选也当做可能的完整明文（很多题目 plaintext 恰好等于块长度不需要填充）。
* **网络交互不同步**：脚本中 `recv_until` 使用 `errors='ignore'` 解码，且有小 sleep，足够大多数题目。若远程有速度限制可增大 timeout。

---

## 八、防御建议（给出题目作者的正确修复方式）

这道题的主要弱点是 **可用的 keystream 被重复利用且只做简单循环变换**。正确做法包括：

1. **不要复用密钥流**：每次加密都用真正的随机 IV/nonce 或对称算法（比如 AES-GCM），或者使用流密码时用真正不可预测的 nonce 并且在每次操作时不暴露 keystream。
2. **使用认证加密**（AEAD，例如 AES-GCM、ChaCha20-Poly1305）来同时保证保密性与完整性，避免 “明文预测/选择明文攻击”。
3. **不要把密文或状态原样打印给未经认证的用户**（敏感输出的泄露会放大攻击面）。
4. **校验接口不要直接比较原始明文**：如果需要校验某些密文对应关系，应使用 MAC/签名或独立的认证机制，避免给出可以利用的“oracle”。
5. **若使用自定义构造（例如种子旋转），在设计前请先做专业安全评估** —— 轮转密钥几乎总是危险的，除非用严格证明的构造与不可预测的初始随机化并且没有 oracle。

---

## 九、总结（一步到位的 checklist）

如果你想复现或向队友演示，按以下顺序做就行：

1. 连接服务 `nc challenge...`，记录首次密文（base64）。
2. 解 base64 得到 `cipher1`，记下其长度 `msg_len`。
3. 发 `1` 然后发 `A*msg_len` 多次，记录返回的每个 base64 密文，计算出对应 keystream（`ct ⊕ A*msg_len`）。
4. 对每个 keystream 做 `candidate = cipher1 ⊕ keystream`，去填充并解码，找出可读候选。
5. 用菜单 `2` 把可读候选提交、拿到 flag。

好 — 我把这个题的**原理**拆得非常清楚、一步步讲明白（不会再假设你懂哪一步）。目标是让你理解为什么我们能只用“可选明文加密”就把首次被打印的明文（flag）还原出来，以及每一步的数学理由、边界条件和防御措施。

# 一、核心结论（一句话）

服务用一个固定的随机 `seed` 做密钥流，每次只把 `seed`**按固定偏移量循环旋转**后当作本轮 key，然后用 `key XOR pad(msg)` 给出密文；因为你可以提交任意明文进行加密，你能得到若干轮的 **key（keystream）**，其中必然包含首次打印密文所用的某个 key 的一个旋转。把首次打印的密文与某一轮得到的 keystream 异或，就能恢复首次的明文（并去掉填充），因此可以拿到 flag。

---

# 二、符号与服务行为（把代码映射到数学）

* 记 `msg_len` = 固定块长度（题里是 16）。
* 程序对 `msg` 调用 `pad(msg)`，结果长度恒为 `msg_len`。（实现用 `pad_len * long_to_bytes(pad_len)` 填充；当 `len(msg)==msg_len` 时不填充。）
* 初始随机字节串 `seed`（长度 `msg_len`）被存着。每次 `Key.generate()` 执行：
  <pre class="overflow-visible!" data-start="575" data-end="655"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>seed</span><span> = seed[</span><span>off</span><span>set:] + seed[:</span><span>off</span><span>set]   </span><span># 循环旋转 offset 字节</span><span>
  </span><span>key</span><span> = seed
  </span></span></code></div></div></pre>
* 加密过程：
  <pre class="overflow-visible!" data-start="666" data-end="705"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>cipher</span><span> = xor(pad(msg), key)
  </span></span></code></div></div></pre>
* 服务在一开始把 `cipher1 = xor(pad(plaintext), s1)` （第一次的密文）打印一次给你。之后你可以多次调用加密接口得到不同轮次的 `ct_i = xor(pad(msg_i), s_i)`。

---

# 三、攻击的数学推导（最关键）

设：

* `C1 = cipher1 = pad(P) ⊕ s1`（你已知 `C1`）
* 在你第 `i` 次调用，加密已知消息 `M` 得到 `CT_i = pad(M) ⊕ s_i`（你能得到 `CT_i`）

因此你能求出本轮 keystream：

<pre class="overflow-visible!" data-start="970" data-end="997"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>s_i</span><span> = CT_i ⊕ pad(M)
</span></span></code></div></div></pre>

把这个 `s_i` 与 `C1` 异或：

<pre class="overflow-visible!" data-start="1019" data-end="1079"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>C1</span><span> ⊕ s_i = (pad(P) ⊕ s1) ⊕ s_i = pad(P) ⊕ (s1 ⊕ s_i)
</span></span></code></div></div></pre>

如果 `s_i == s1`（也就是你收集到的某轮 keystream 恰好等于首次的 keystream），那么

<pre class="overflow-visible!" data-start="1138" data-end="1179"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>C1</span><span> ⊕ s_i = pad(P)   </span><span># 直接得到被填充过的明文</span><span>
</span></span></code></div></div></pre>

对 `pad(P)` 去填充（用题目中 pad 的规则）就能还原 `P`（即 flag）。

为什么能得到 `s1`？因为 `s_i` 是 `seed` 被循环旋转若干次后的状态集合；只要你采集了完整的旋转周期，你就必然采到 `s1` 的那个旋转（或者 `s1` 本身，取决于 `offset` 和初始 `seed` 的相对位置）。

---

# 四、如何选择 `M`（已知明文）才方便恢复 keystream

最好选择能确保 `pad(M)` 很简单、已知并易于处理的 `M`。两种常见选择：

1. `M = b"A" * msg_len`（长度正好是 `msg_len`）
   * 因为 `len(M) == msg_len`，`pad(M) == M`（没有填充）。
   * 那么 `s_i = CT_i ⊕ M`，操作简单且不会引入填充的复杂性。
2. 也可用其它任意已知 `M`，但要确保你能算出 `pad(M)` 的确切字节表示。

因此攻击时通常用 `A*msg_len`，每次调用加密并记录返回的 `CT`，立刻计算 `ks = CT ⊕ (A*msg_len)` 得到该轮 keystream。

---

# 五、周期与查询次数上界

`seed` 长度为 `msg_len`，每次 rotate `offset` 字节。循环状态数（周期长度）为：

<pre class="overflow-visible!" data-start="1773" data-end="1815"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>L</span><span> = msg_len / gcd(msg_len, </span><span>off</span><span>set)
</span></span></code></div></div></pre>

最坏情况 `gcd=1`，`L = msg_len`。所以只需最多查询 `L` 次（通常 ≤ `msg_len`）就能见到完整的 keystream循环并必然得到 `s1`。实践中我们检测到 keystream重复就停止采集。

---

# 六、关于填充（为什么要去填充）

服务用 `pad_len * long_to_bytes(pad_len)`。`long_to_bytes(k)` 会把整数 `k` 变成最小长度的大端字节串。当 `k <= 255` 时，它就是单字节 `b'\x{k}'`。因此对于常见情况（flag 较短，`pad_len` ≤ 255），填充等价于单字节重复 `pad_len` 次，和 PKCS#7 类似。

攻击流程中有两种可能：

* `len(plaintext) < msg_len`：`cipher1 XOR s1` 得到的是 `pad(plaintext)`，需去除填充（检查最后字节 `v` 是否 `1 ≤ v ≤ msg_len` 且最后 `v` 个字节均为 `v`）。
* `len(plaintext) == msg_len`：没有填充，直接得到明文。

注意：题中作者用了 `long_to_bytes`；对 pad\_len ≤255 行为与 PKCS#7 相同。脚本中做了单字节填充检测和回退。

---

# 七、实际操作流程（简明步骤）

1. 连接服务，记录首次密文 `C1`（base64 解码后长度 = `msg_len`）。
2. 构造 `M = b"A" * msg_len`。
3. 循环：
   * 在菜单选 `1` 并发送 `M`；
   * 得到返回的 `CT`（base64 解码）；
   * 计算 `ks = CT ⊕ M`，保存 `ks`；
   * 如果 `ks` 已出现过，说明循环到头了，停止采集。
4. 对保存的每个 `ks` 计算 `candidate_padded = C1 ⊕ ks`，尝试去填充并解码：
   * 若去填充后是 ASCII readable 或包含 `flag{}`，那就是 plaintext。
5. 可将该 plaintext 通过菜单 `2` 提交验证（服务会在正确时输出 FLAG 环境变量）。

---

# 八、为什么不是“破解随机数”而是“利用重复 keystream”

关键点：我们**不需要**恢复初始 `seed` 的具体字节或 `offset` 的值。我们只需要某一次 `s_i` 恰好与 `s1` 相同（或等价位置），而 `s_i` 是可以直接从服务返回的密文和已知的 `pad(M)` 计算出的。也就是说，服务**把 keystream 的输出（异或后的密文）暴露给了用户**，所以用户能“读出”keystream 本身（通过已知明文），这是根本问题。这和经典的 OTP（一次性密码本）被重用的漏洞是同一个类别：**同一 keystream被重复使用会导致可恢复明文**。

---

# 九、举个数字化小例子（便于记忆）

* 设 `msg_len = 4`（简化），seed 初始 `s = b'\x01\x02\x03\x04'`，offset = 1。
* 轮次 keystream：
  s1 = 01 02 03 04
  s2 = 02 03 04 01
  s3 = 03 04 01 02
  s4 = 04 01 02 03
  然后回到 s1。
* 首次打印的密文： `C1 = pad(P) ⊕ s1` （你知道 `C1`）。
* 你发送 `M = b'AAAA'`（ASCII 0x41），得到 `CT2 = 41 41 41 41 ⊕ s2`，所以 `ks2 = CT2 ⊕ 41... = s2`。
  如果 `s2 == s1`（某轮恰好），`C1 ⊕ s2 = pad(P)` ⇒ 得到 pad(P)。在实际情况你会收集到 s1 的那个旋转（上面集合包含 s1）。

---

# 十、常见陷阱与注意事项

* **不要把非 ASCII 中文放进 bytes 字面量**（你在脚本中遇到的问题）。用 `str` 匹配再 `.encode()`。
* **解析首次密文**时要确保用你从服务读取到的那一行（有时服务每次连接会生成不同的 seed）。
* **keystream 长度必须与 C1 长度一致**（都是 msg\_len）。若不一致说明你解析有误或选择的 `M` 被截断/服务行为不同。
* **填充格式**若非常规（比如 `long_to_bytes` 对超过 255 的 pad\_len 行为不同），需要写更通用的去填充逻辑。但通常 flag 小，pad\_len≤255。
* **如果 plaintext 本身恰好是 msg\_len 长**，则直接解出，无需去填充判断。

---

# 十一、防御（作者角度）

* 不要复用 keystream：每次加密使用独立随机 key/nonce 或用 AEAD（例如 AES-GCM/ChaCha20-Poly1305）。
* 如果必须用流式密钥，**不要把 keystream 任何形式暴露给用户**（即不要允许用户提交明文并查看对应密文，或至少不要让用户任意选择明文）。
* 使用认证加密（MAC/签名）防止 oracle 利用。

---

# 十二、总结（复述要点）

* 原因：密钥是 `seed` 的循环旋转，且服务允许对已知明文请求密文 ⇒ 你能直接读出多轮的 keystream。
* 攻击：用已知明文（长度等于块）得到 keystream，异或首次密文得到 `pad(plaintext)`，去填充得到 plaintext（flag）。
* 查询代价：最多 `L = msg_len / gcd(msg_len, offset)` 次，加密 oracle 足够即可。

# [Week1] Basic Number theory

太棒了——你给的 flag 已经核对无误。下面我会把这道题的 **完整 write‑up（WP）** 给你：从数学原理到逐行解题脚本，再到为什么会泄露、边界情况和防御建议。尽量把每一步都讲清楚、容易理解——即便你自称“不懂密码学”，看完能把原理读懂、复现并学会下次自己做。

# 题目回顾（简短）

程序给出两个素数 `p, q`，以及两个值

<pre class="overflow-visible!" data-start="171" data-end="232"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>gift1</span><span> = m^((p+</span><span>1</span><span>)//</span><span>2</span><span>) mod p
</span><span>gift2</span><span> = m^((q+</span><span>1</span><span>)//</span><span>2</span><span>) mod q
</span></span></code></div></div></pre>

其中 `m = bytes_to_long(flag)`，目标是从 `p, q, gift1, gift2` 恢复 `flag`。最终答案是：

<pre class="overflow-visible!" data-start="305" data-end="350"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>flag{Th3_c0rner5t0ne_0f_C2ypt0gr</span><span>@phy</span><span>}
</span></span></code></div></div></pre>

# 一条直观结论（关键观察）

对奇素数 `prime`：

<pre class="overflow-visible!" data-start="381" data-end="463"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>gift(m, prime) = m^{(prime+</span><span>1</span><span>)/</span><span>2</span><span>} </span><span>mod</span><span> prime = m * m^{(prime</span><span>-1</span><span>)/</span><span>2</span><span>} </span><span>mod</span><span> prime
</span></span></code></div></div></pre>

由**欧拉准则 / Legendre 符号**，若 `gcd(m, prime) = 1`，则

<pre class="overflow-visible!" data-start="512" data-end="571"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>m^{(prime</span><span>-1</span><span>)/</span><span>2</span><span>} ≡ (m|prime) ∈ {+</span><span>1</span><span>, </span><span>-1</span><span>}  (</span><span>mod</span><span> prime)
</span></span></code></div></div></pre>

因此

<pre class="overflow-visible!" data-start="575" data-end="616"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>gift</span><span>(m, prime) ≡ ± m  (mod prime)
</span></span></code></div></div></pre>

也就是说 `gift` 只是把 `m` 或 `-m`（关于模 `prime`）泄露出来。知道两个模 `p` 和 `q` 下的 ±m，你可以用 **中国剩余定理（CRT）** 把 `m (mod p*q)` 恢复出来；如果原始 `m` 小于 `N = p*q`，那么恢复结果就是原始 `m`。这就是题目的漏洞点与解法核心。

---

# 数学细节（一步步来）

## 1. 欧拉准则和 Legendre 符号（核心）

设 `p` 是奇素数，`a` 与 `p` 互素，则欧拉准则是：

ap−12≡(ap)(modp),a^{\\frac{p-1}{2}} \\equiv \\left(\\frac{a}{p}\\right) \\pmod p,**a**2**p**−**1****≡**(**p**a****)**(**mod**p**)**,**右边是 **Legendre 符号**，值为 `+1`（如果 `a` 在模 `p` 下是平方剩余）或 `-1`（非平方剩余）。

所以

m(p+1)/2=m∗m(p−1)/2≡m∗(±1)≡±m(modp).m^{(p+1)/2} = m \* m^{(p-1)/2} \\equiv m \* (\\pm 1) \\equiv \\pm m \\pmod p.**m**(**p**+**1**)**/2**=**m**∗**m**(**p**−**1**)**/2**≡**m**∗**(**±**1**)**≡**±**m**(**mod**p**)**.注意若 `p | m`（即 `m ≡ 0 (mod p)`）则 `gift = 0`，这在本题中不成立（flag 经过 bytes\_to\_long 通常不会正好等于 p 的倍数）。

## 2. 四种可能性

因为对 `p` 和 `q` 各有 ± 的不确定性，我们得到四组同余：

* m≡  gift1(modp)m \\equiv  \\;  gift1 \\pmod p**m**≡**g**i**f**t**1**(**mod**p**)** 或 m≡−gift1(modp)m \\equiv -gift1 \\pmod p**m**≡**−**g**i**f**t**1**(**mod**p**)
* m≡  gift2(modq)m \\equiv  \\;  gift2 \\pmod q**m**≡**g**i**f**t**2**(**mod**q**)** 或 m≡−gift2(modq)m \\equiv -gift2 \\pmod q**m**≡**−**g**i**f**t**2**(**mod**q**)

把两边组合（2 × 2 = 4 种组合），对每一种用 CRT 求解可得 4 个不同的 `m` 候选（实际上是模 `N = p*q` 的四个解）。

## 3. 中国剩余定理（CRT）

给定

x≡a(modp),x≡b(modq)x \\equiv a \\pmod p,\\quad x \\equiv b \\pmod q**x**≡**a**(**mod**p**)**,**x**≡**b**(**mod**q**)**且 `p`、`q` 互素，CRT 给出唯一的 `x (mod N)`。实现上常用：

* 找到 `inv = p^{-1} mod q`（`pow(p, -1, q)`）
* 然后

x=a+(b−a)∗inv∗p(modN)x = a + (b-a) \* inv \* p \\pmod{N}**x**=**a**+**(**b**−**a**)**∗**in**v**∗**p**(**mod**N**)这会返回 `0 ≤ x < N` 的解。若原始 `m < N`，则这个 `x` 就是原始 `m`。

---

# 解题流程（思路概括）

1. 读取 `p,q,gift1,gift2`。
2. 遍历 `sign_p ∈ {+1,-1}` 与 `sign_q ∈ {+1,-1}`：
   * 构造 `a = sign_p * gift1 mod p`，`b = sign_q * gift2 mod q`。
   * 用 CRT 求 `x`，得到候选 `m = x`（0 ≤ x < p\*q）。
3. 将每个候选转回 bytes（`long_to_bytes`），看哪个是可读 ASCII 且以 `flag{` 开头；那就是结果。

---

# 完整可复现 Python 脚本

<pre class="overflow-visible!" data-start="1960" data-end="3353"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span># 复现脚本：用给定的 p,q,gift1,gift2 恢复 flag</span><span>
</span><span>from</span><span> typing </span><span>import</span><span> </span><span>Tuple</span><span>

p = </span><span>71380997427449345634700552609577271052193856747526826598031269184817312570231</span><span>
q = </span><span>65531748297495117965939047069388412545623909154912018722160805504300279801251</span><span>
gift1 = </span><span>40365143212042701723922505647865230754866250738391105510918441288000789123995</span><span>
gift2 = </span><span>10698628345523517254945893573969253712072344217500232111817321788145975103342</span><span>

</span><span>def</span><span> </span><span>long_to_bytes</span><span>(</span><span>n: int</span><span>) -> </span><span>bytes</span><span>:
    </span><span>if</span><span> n == </span><span>0</span><span>:
        </span><span>return</span><span> </span><span>b'\x00'</span><span>
    s = </span><span>bytearray</span><span>()
    </span><span>while</span><span> n:
        s.append(n & </span><span>0xff</span><span>)
        n >>= </span><span>8</span><span>
    </span><span>return</span><span> </span><span>bytes</span><span>(</span><span>reversed</span><span>(s))

</span><span>def</span><span> </span><span>crt</span><span>(</span><span>a1: int</span><span>, m1: </span><span>int</span><span>, a2: </span><span>int</span><span>, m2: </span><span>int</span><span>) -> </span><span>int</span><span>:
    </span><span>"""Return x s.t. x ≡ a1 (mod m1) and x ≡ a2 (mod m2), 0 <= x < m1*m2"""</span><span>
    </span><span># inverse of m1 modulo m2</span><span>
    inv = </span><span>pow</span><span>(m1, -</span><span>1</span><span>, m2)
    M = m1 * m2
    x = (a1 + (a2 - a1) * inv * m1) % M
    </span><span>return</span><span> x

candidates = []
</span><span>for</span><span> a </span><span>in</span><span> (gift1, (-gift1) % p):
    </span><span>for</span><span> b </span><span>in</span><span> (gift2, (-gift2) % q):
        x = crt(a, p, b, q)
        candidates.append(x)

</span><span>for</span><span> i, m </span><span>in</span><span> </span><span>enumerate</span><span>(candidates, </span><span>1</span><span>):
    b = long_to_bytes(m)
    </span><span>try</span><span>:
        s = b.decode(</span><span>'utf-8'</span><span>)
    </span><span>except</span><span> UnicodeDecodeError:
        s = </span><span>None</span><span>
    </span><span>print</span><span>(</span><span>f"Candidate #{i}</span><span>: </span><span>{len</span><span>(b)} bytes; starts with flag{{?}} </span><span>{b.startswith(b'flag{'</span><span>)}")
    </span><span>if</span><span> s:
        </span><span>print</span><span>(</span><span>"  UTF-8 decode:"</span><span>, s)
    </span><span>else</span><span>:
        </span><span>print</span><span>(</span><span>"  (not valid UTF-8)"</span><span>)

</span><span># 你会在输出中看到一条以 flag{ 开头的候选：</span><span>
</span><span># flag{Th3_c0rner5t0ne_0f_C2ypt0gr@phy}</span><span>
</span></span></code></div></div></pre>

这就是我之前运行的脚本的完整版（把 `long_to_bytes` 和 `crt` 都写清）。

---

# 为什么能唯一恢复（关于 m 与 N 的大小关系）

CRT 给出的是 `m mod N`（`N = p*q`）。如果原始 `m < N`，那么这个模类代表的唯一非负整数就是原始 `m`。因此题目隐含的安全漏洞：原始 `m`（flag 的整数表示）必须小于 `N` 才能被唯一恢复——这在真实的 RSA/混合设定中通常是成立的（flag/消息比模数小）。

在这道题里：

* `p`、`q` 各 256-bit，因此 `N` 大约 512-bit。
* flag bytes 长度约 37 bytes ≈ 296 bits，显然 `m < N`，因此 CRT 的解就是原始 `m`。

---

# 边界情况与注意点

1. **如果 m 与某个 prime 不互素（p | m）**：`m ≡ 0 (mod p)`，那么 `gift = 0`。这种情况会使 ± 的判断变得简单（直接 0），但通常 flag 不会正好等于素数的倍数。
2. **如果原始 m ≥ N**：CRT 只能恢复 `m mod N`，你无法从仅这两个同余恢复完整的原始大整数（会有模 N 的不确定性）。题目设计通常保证 `m < N`。
3. **签名/泄露的模式**：任何泄露 `±m (mod p)` 的操作都危险，尤其当你提供两个不同素模下的 ±m 时，组合后很容易恢复。这里 `m^{(p+1)/2}` 正是这样的危险泄露。

---

# 为什么这是一个“漏洞”？（安全教训）

* `gift(m, p) = m^{(p+1)/2}` 对每个模只泄露了 `m` 的符号信息（±），但两个模合起来足以把整个 `m` 恢复（CRT）。因此，除非你严格控制模数数量或消息长度，否则这种操作会泄露原文。
* 类似问题在现实中：给出 `m^d mod p` 对于不同 `p`、`q` 的不当组合、或泄露与私钥相关的幂运算，都可能导致信息泄露。
* 总结安全要点：
  * 不要泄露看似“部分信息”的算术变换，它们可能与其他信息合并后被还原。
  * 任何只要能得到模不同素数下的相同原文的线索，都可能被 CRT 合并。

---

# 如何学习这些原理（学习路径建议）

（短而实用）

1. **基础数论**
   * 模运算、同余、欧拉函数、费马小定理。
   * 学习 Legendre 符号、二次互反律（了解平方剩余/非剩余的概念）。
2. **计算数论 / 算法**
   * 扩展欧几里得算法（求逆元）、快速幂、CRT 的实现。
3. **基础密码学**
   * RSA 的数学基础，为什么模数和消息长度重要。
   * 常见攻击向量（CRT 恢复、暴力、模幂泄露）。
4. **实践**
   * 在本地复写题目脚本（像上面那样），改动输入实验不同情况。
   * 做 CTF crypto 题（逐步积累直觉）。

入门书（不强制网络搜索）：任何一本好的离散数学 / 数论或现代密码学入门书都可以；课程、讲义、在线教程亦可。

---

# 小结（精简）

* `gift(m, prime) = m^{(prime+1)/2} mod prime ≡ ±m (mod prime)`（欧拉准则）
* 得到两个模 `p`、`q` 下的 ±m → 组合 4 种情况 → 对每种用 CRT 求解 → 找到一个候选解转换回 bytes，发现以 `flag{` 开头 → 即为原始 flag。
* 已给出并验证的答案：
  **flag{Th3\_c0rner5t0ne\_0f\_C2ypt0gr@phy}**

## CTF 题目：Beyond Hex

### 题目信息

题目文件内容示例：

<pre class="overflow-visible!" data-start="121" data-end="205"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>807</span><span>G6F429C7FA2200F46525G1350AB20G339D2GB7D8
[</span><span>Week1</span><span>] beyondHex
质疑，理解，成为！CTF题目
</span></span></code></div></div></pre>

要求解出隐藏的 `flag{...}`。

---

## 1️⃣ 题目分析

1. **观察字符串特点**：
   * 字符串中有数字 `0-9`，字母 `A-F`，以及 `G`、`B`。
   * 常规 Hex（十六进制）只允许 `0-9A-F`。
   * 出现 `G`、`B`，说明不是普通 Hex，需要“超越 Hex”。
2. **题目名称提示**：
   * **beyondHex** → 不只是 Hex，要跳出常规解法。
   * “[Week1]” → 这是基础题，通常方法不复杂。
3. **可能的解码方法**：
   * 自定义进制编码（类似 base-17，因为 `0-9A-G` 一共有 17 个字符）。
   * 将整个字符串视为一个大整数，再转为字节流得到 ASCII 信息。

---

## 2️⃣ 解题思路

1. **定义字符映射**
   把 `0-9` 当作 0\~9，`A=10, B=11, …, G=16`。
2. **将字符串视为一个大整数**
   * 假设字符串是 base-17 编码。
   * 从左到右依次计算数值：
     <pre class="overflow-visible!" data-start="719" data-end="809"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>val</span><span> = </span><span>0</span><span>
     </span><span>for</span><span> ch </span><span>in</span><span> string:
         </span><span>val</span><span> = </span><span>val</span><span> * </span><span>17</span><span> + digit_value(ch)
     </span></span></code></div></div></pre>
3. **转换成字节**
   * 将大整数 `val` 转成字节序列（big-endian）。
   * 然后用 UTF-8 或 ASCII 解码。

---

## 3️⃣ Python 实现

<pre class="overflow-visible!" data-start="913" data-end="1210"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span># 输入字符串</span><span>
s = </span><span>"807G6F429C7FA2200F46525G1350AB20G339D2GB7D8"</span><span>

</span><span># base-17 字符映射</span><span>
digits = {c:i </span><span>for</span><span> i,c </span><span>in</span><span> </span><span>enumerate</span><span>(</span><span>"0123456789ABCDEFG"</span><span>)}

</span><span># 计算大整数</span><span>
val = </span><span>0</span><span>
</span><span>for</span><span> ch </span><span>in</span><span> s:
    val = val*</span><span>17</span><span> + digits[ch]

</span><span># 转成字节</span><span>
b = val.to_bytes((val.bit_length()+</span><span>7</span><span>)//</span><span>8</span><span>, </span><span>'big'</span><span>)

</span><span># 打印 flag</span><span>
</span><span>print</span><span>(b.decode(</span><span>'utf-8'</span><span>))
</span></span></code></div></div></pre>

---

## 4️⃣ 结果

输出：

<pre class="overflow-visible!" data-start="1233" data-end="1263"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>flag{welc0me_t0_?</span><span>CTF</span><span>!}
</span></span></code></div></div></pre>

> 说明：
>
> * `?` 可能是题目略微混淆的占位，或者在原题中会给完整 flag。
> * 解题关键是 **base-17 解码**，把超出 Hex 的字符映射到对应数字。

---

## 5️⃣ 总结（技巧与教训）

1. **不要被 Hex 的表面形式迷惑**：
   * Hex 是 0-9A-F，但题目可能故意加入额外字符，提示你要“跳出 Hex”。
2. **观察字符集大小**：
   * 17 个不同字符 → base-17。
   * 26 个字符 →可能是 base-26 或 Base32 变体。
3. **处理大整数**：
   * 将整个字符串看作一个大数，再转换成字节流是常见技巧。
4. **CTF 思路**：
   * **质疑、理解、尝试** → 正如题目提示。
   * 不要先入为主地认为一定是 Hex/Base64。

# two Es（Week1）——详细解题报告（中文）

## 一、题目概述

给出一个简单的 RSA 加密脚本（Python）：同一条消息 `flag` 被两个不同的指数 `e1` 和 `e2` 加密，且使用相同的模数 `n`。题目输出了五个值：`n, e1, e2, c1, c2`。目标是从这些已知量中恢复明文 `flag`。

已知（示例）：

```
n = 118951231851047571559217335117170383889369241506334435506974203511684612137655707364175506626353185266191175920454931743776877868558249224244622243762576178613428854425451444084313631798543697941971483572795632393388563520060136915983419489153783614798844426447471675798105689571205618922034550157013396634443
e1 = 2819786085
e2 = 4203935931
c1 = 104852820628577684483432698430994392212341947538062367608937715761740532036933756841425619664673877530891898779701009843985308556306656168566466318961463247186202599188026358282735716902987474154862267239716349298652942506512193240265260314062483869461033708176350145497191865168924825426478400584516421567974
c2 = 43118977673121220602933248973628727040318421596869003196014836853751584691920445952955467668612608693138227541764934104815818143729167823177291260165694321278079072309885687887255739841571920269405948846600660240154954071184064262133096801059918060973055211029726526524241753473771587909852399763354060832968
```

## 二、解题思路（核心原理）

这是经典的“双指数但同模”的 RSA 问题的一个变体。若两个密文是对同一明文 `m` 用相同模 `n`、不同指数 `e1`、`e2` 分别加密得到：

[ c\_1 \\equiv m^{e\_1} \\pmod n, \\quad c\_2 \\equiv m^{e\_2} \\pmod n. ]

若 `gcd(e1, e2) = 1`，可以通过扩展欧几里得找到整数 `s, t` 使得 `s*e1 + t*e2 = 1`，进而

[ m \\equiv c\_1^{s} \\cdot c\_2^{t} \\pmod n. ]

但当 `gcd(e1, e2) = d > 1` 时，扩展欧几里得只能得到 `s, t` 使 `s*e1 + t*e2 = d`，这时我们只能直接恢复 `m^{d}`（记作 `M`）：

[ M \\equiv m^{d} \\equiv c\_1^{s} \\cdot c\_2^{t} \\pmod n. ]

若 `m` 是小整数（或 `m^d` 在整数范围内的 d 次方），或者 `m` 本身未使用复杂填充且 `m^d` 小于 `n`，或可以从 `M` 恢复 `m` 的整数 d 次方根，则可以得到 `m`。常见情况：`d` 比较小（例如 `d=2` 或 `3`），且 `m` 是直接的 ASCII 编码（没有复杂填充），这使得取整数 d 次根可行。

题目中，我们首先计算 `g = gcd(e1, e2)`。如果 `g > 1`，令 `e1' = e1/g, e2' = e2/g` 并用扩展欧几里得在 `e1'` 与 `e2'` 上求解得到系数 `s` 和 `t`，随后按如下方式构造：

[ M \\equiv c\_1^{s} \\cdot c\_2^{t} \\pmod n, ]

注意当 `s` 或 `t` 为负数时，意味着要对相应的 `c` 求模逆（即计算 `c^{-1} mod n`），然后再取正整数次幂。

得到 `M = m^{g}` 后，对 `M` 在整数域上求 `g` 次整数根（integer g-th root）。如果根是精确整数，则就是明文 `m`。最后将 `m` 转换为字节并解码为 ASCII 即可得到 `flag`。

## 三、解题步骤（详细、可复现）

下面给出可直接运行的 Python 代码（与题目使用的库兼容），包含注释，按顺序运行即可复现得到 flag：

```python
# two_es_solve.py
from math import gcd
from Crypto.Util.number import long_to_bytes

# 把题目给出的数据粘贴到这里
n = 118951231851047571559217335117170383889369241506334435506974203511684612137655707364175506626353185266191175920454931743776877868558249224244622243762576178613428854425451444084313631798543697941971483572795632393388563520060136915983419489153783614798844426447471675798105689571205618922034550157013396634443
e1 = 2819786085
e2 = 4203935931
c1 = 104852820628577684483432698430994392212341947538062367608937715761740532036933756841425619664673877530891898779701009843985308556306656168566466318961463247186202599188026358282735716902987474154862267239716349298652942506512193240265260314062483869461033708176350145497191865168924825426478400584516421567974
c2 = 43118977673121220602933248973628727040318421596869003196014836853751584691920445952955467668612608693138227541764934104815818143729167823177291260165694321278079072309885687887255739841571920269405948846600660240154954071184064262133096801059918060973055211029726526524241753473771587909852399763354060832968

# 1) 计算 gcd
g = gcd(e1, e2)
print('gcd(e1, e2) =', g)

# 2) 用扩展欧几里得在 e1/g, e2/g 上求系数

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    else:
        x, y, g = egcd(b, a % b)
        return (y, x - (a // b) * y, g)

# 若 g==1，直接用 s,t 使 s*e1 + t*e2 = 1
# 若 g>1，记 e1' = e1/g, e2' = e2/g，用它们求 s,t 使 s*e1' + t*e2' = 1，
# 然后 s*e1 + t*e2 = g。

if g == 1:
    s, t, _ = egcd(e1, e2)
else:
    e1p = e1 // g
    e2p = e2 // g
    s, t, _ = egcd(e1p, e2p)
    # s,t 满足 s*e1p + t*e2p = 1
    # 因此 s*(e1/g) + t*(e2/g) = 1 => s*e1 + t*e2 = g

print('s =', s)
print('t =', t)

# 3) 计算 M = c1^s * c2^t mod n，处理负指数（取模逆）

def modpow_with_neg(base, exp, mod):
    if exp < 0:
        inv = pow(base, -1, mod)   # Python 3.8+: pow(base, -1, mod) 求逆元
        return pow(inv, -exp, mod)
    else:
        return pow(base, exp, mod)

A = modpow_with_neg(c1, s, n)
B = modpow_with_neg(c2, t, n)
M = (A * B) % n

print('M = m^g (mod n) 计算完成')

# 4) 对 M 在整数域求 g 次根（注意：这里需要 M 在整数域上确实是 m^g）

def integer_nth_root(x, n):
    # 返回 (root, exact_bool)
    low = 0
    high = 1 << ((x.bit_length() + n - 1) // n + 1)
    while low < high:
        mid = (low + high) // 2
        p = pow(mid, n)
        if p == x:
            return mid, True
        if p < x:
            low = mid + 1
        else:
            high = mid
    root = low - 1
    return root, pow(root, n) == x

root, exact = integer_nth_root(M, g)

if exact:
    m = root
    print('找到精确的 g 次整数根！')
else:
    # 有时需要尝试 root+1, root+2 等
    found = False
    for cand in [root, root+1, root+2, root+3]:
        if pow(cand, g) == M:
            m = cand
            found = True
            break
    if not found:
        raise ValueError('无法在整数域找到精确的 g 次根，可能消息被填充或不满足小明文条件')

# 5) 将 m 转换为字节并解码
flag_bytes = long_to_bytes(m)
print('Recovered flag bytes:', flag_bytes)
try:
    print('Flag:', flag_bytes.decode())
except:
    print('Flag (raw bytes):', flag_bytes)
```

## 四、在本题中发生了什么（具体到给出的样例）

1. 计算 `g = gcd(e1, e2)`，得到 `g = 3`（即两个指数的最大公约数为 3）。
2. 将 `e1`、`e2` 各自除以 3，得到 `e1'`、`e2'`，对它们求解扩展欧几里得系数 `s`、`t`，使 `s*e1' + t*e2' = 1`，从而 `s*e1 + t*e2 = 3`。
3. 利用 `c1^s * c2^t (mod n)` 可得到 `M ≡ m^3 (mod n)`。题目中 `m`（即 flag 的整数形式）满足没有复杂填充，且 `m^3` 在整数域上正好是某个整数的立方（即 `M` 的立方根是整数）。
4. 对 `M` 求整数 3 次根，得到 `m`，把 `m` 转为字节后解码，得到明文：`flag{s01v3_rO0T_bY_7he_S4mE_m0dU1u5}`。

## 五、常见变体与防御建议

* 变体：若明文使用了 PKCS#1 v1.5 或 OAEP 等填充，单纯的取 d 次根通常无法成功，需要借助更多信息或不同攻击方法。若填充使得 `m` 不满足 `m^d < n`，则在整数域上不能直接取根。
* 防御建议（作为题目作者或真实系统的角度）：
  * 永远不要对原始明文使用裸 RSA（即不要仅做 `m^e mod n`），务必使用行业标准填充（如 RSA-OAEP）。
  * 使用随机填充和良好的密钥管理，确保不会重复用相同 `n` 给两个不同的公钥对外（同模不同指数容易引发此类问题）。
  * 保证指数选择合理，避免使用小且带有公因子的指数对（例如两个指数共享公因子）。

## 六、参考（原理）

* 扩展欧几里得与 Bézout 恒等式
* RSA 同模不同指数攻击（common modulus attack）
* 整数次根与牛顿法/二分法求根

---

**附：我已将完整可运行代码以及详细说明写在本份报告中。**

如果你需要我把这份报告导出为 PDF/Word，或把代码打包成文件给你下载，告诉我你想要的格式，我可以直接帮你生成。

# two Es（Week1）——中文详细解题教程

## 一、题目背景

题目给了一个 Python 脚本，功能是：

* 生成两个 512 位素数 `p`、`q`，得到 RSA 模数 `n = p*q`。
* 随机生成两个 32 位整数 `e1`、`e2` 作为指数。
* 同一条消息 `flag` 被分别用 `e1`、`e2` 加密，得到密文 `c1`、`c2`。
* 输出 `n, e1, e2, c1, c2`。

我们的目标是 **从这些已知量恢复明文 `flag`**。

---

## 二、数学原理讲解

### 1. RSA 的基本公式

RSA 加密：

c≡me(modn)c \\equiv m^e \\pmod n**c**≡**m**e**(**mod**n**)解密：

m≡cd(modn)m \\equiv c^d \\pmod n**m**≡**c**d**(**mod**n**)题目特殊点：**同模不同指数加密同一明文**。

c1≡me1(modn),c2≡me2(modn)c\_1 \\equiv m^{e\_1} \\pmod n, \\quad c\_2 \\equiv m^{e\_2} \\pmod n**c**1****≡**m**e**1****(**mod**n**)**,**c**2****≡**m**e**2****(**mod**n**)**### 2. 同模不同指数攻击

#### 情况 1：指数互质

如果 `gcd(e1, e2) = 1`，扩展欧几里得定理保证存在整数 `s, t`：

se1+te2=1s e\_1 + t e\_2 = 1**s**e**1****+**t**e**2****=**1**于是可以得到：

m≡c1s⋅c2t(modn)m \\equiv c\_1^s \\cdot c\_2^t \\pmod n**m**≡**c**1**s****⋅**c**2**t****(**mod**n**)**> **理解**：因为

> c1s⋅c2t≡(me1)s(me2)t=mse1+te2=m1(modn)c\_1^s \\cdot c\_2^t \\equiv (m^{e\_1})^s (m^{e\_2})^t = m^{s e\_1 + t e\_2} = m^1 \\pmod n**c**1**s****⋅**c**2**t****≡**(**m**e**1****)**s**(**m**e**2****)**t**=**m**s**e**1****+**t**e**2****=**m**1**(**mod**n**)

这样就能直接求出明文。

#### 情况 2：指数不互质

如果 `gcd(e1, e2) = d > 1`，则扩展欧几里得得到 `s, t`：

se1+te2=ds e\_1 + t e\_2 = d**s**e**1****+**t**e**2****=**d**此时我们只能得到：

M≡md(modn)M \\equiv m^d \\pmod n**M**≡**m**d**(**mod**n**)如果 `m` 很小或没有复杂填充（通常 CTF flag 的 ASCII 编码非常小），我们可以在整数域上求 `d` 次整数根来恢复 `m`。

> 关键点：
>
> * 负指数意味着取 **模逆**。
> * 求整数根可以通过二分法或牛顿法完成。

---

## 三、解题步骤（教你如何操作）

1. **计算指数的最大公约数**：

<pre class="overflow-visible!" data-start="1092" data-end="1143"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>from</span><span> math </span><span>import</span><span> gcd

g = gcd(e1, e2)
</span></span></code></div></div></pre>

* 若 `g = 1` → 扩展欧几里得求 `s, t`，直接算 `m = c1^s * c2^t mod n`
* 若 `g > 1` → 将 `e1, e2` 除以 `g`，再扩展欧几里得得到 `s, t`，然后算 `M = c1^s * c2^t mod n`，得到 `M = m^g`。

2. **扩展欧几里得求解 `s, t`**：

<pre class="overflow-visible!" data-start="1319" data-end="1467"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>def</span><span> </span><span>egcd</span><span>(</span><span>a, b</span><span>):
    </span><span>if</span><span> b == </span><span>0</span><span>:
        </span><span>return</span><span> </span><span>1</span><span>, </span><span>0</span><span>, a
    </span><span>else</span><span>:
        x, y, g = egcd(b, a % b)
        </span><span>return</span><span> y, x - (a // b) * y, g
</span></span></code></div></div></pre>

3. **处理负指数（取模逆）**：

<pre class="overflow-visible!" data-start="1489" data-end="1675"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>def</span><span> </span><span>modpow_with_neg</span><span>(</span><span>base, exp, mod</span><span>):
    </span><span>if</span><span> exp < </span><span>0</span><span>:
        inv = </span><span>pow</span><span>(base, -</span><span>1</span><span>, mod)  </span><span># 求逆元</span><span>
        </span><span>return</span><span> </span><span>pow</span><span>(inv, -exp, mod)
    </span><span>else</span><span>:
        </span><span>return</span><span> </span><span>pow</span><span>(base, exp, mod)
</span></span></code></div></div></pre>

4. **计算 `M`**：

<pre class="overflow-visible!" data-start="1693" data-end="1782"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>A = modpow_with_neg(c1, s, n)
B = modpow_with_neg(c2, t, n)
M = (A * B) % n
</span></span></code></div></div></pre>

5. **求整数 d 次根**：

<pre class="overflow-visible!" data-start="1802" data-end="2213"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>def</span><span> </span><span>integer_nth_root</span><span>(</span><span>x, n</span><span>):
    low, high = </span><span>0</span><span>, </span><span>1</span><span> << ((x.bit_length() + n - </span><span>1</span><span>) // n + </span><span>1</span><span>)
    </span><span>while</span><span> low < high:
        mid = (low + high) // </span><span>2</span><span>
        p = </span><span>pow</span><span>(mid, n)
        </span><span>if</span><span> p == x:
            </span><span>return</span><span> mid, </span><span>True</span><span>
        </span><span>elif</span><span> p < x:
            low = mid + </span><span>1</span><span>
        </span><span>else</span><span>:
            high = mid
    root = low - </span><span>1</span><span>
    </span><span>return</span><span> root, </span><span>pow</span><span>(root, n) == x

root, exact = integer_nth_root(M, g)
m = root
</span></span></code></div></div></pre>

6. **转换为字节并解码**：

<pre class="overflow-visible!" data-start="2233" data-end="2360"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span>from</span><span> Crypto.Util.number </span><span>import</span><span> long_to_bytes

flag_bytes = long_to_bytes(m)
</span><span>print</span><span>(flag_bytes.decode())  </span><span># 得到 flag</span><span>
</span></span></code></div></div></pre>

---

## 四、题目示例结果

运行上面步骤，得到：

<pre class="overflow-visible!" data-start="2392" data-end="2436"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>flag{s01v3_rO0T_bY_7he_S4mE_m0dU1u5}
</span></span></code></div></div></pre>

---

## 五、知识点总结

1. **扩展欧几里得与 Bézout 恒等式**
   * 求整数解 `s, t` 使得 `s e1 + t e2 = gcd(e1, e2)`
2. **同模不同指数攻击**
   * 当同一条消息用相同模数但不同指数加密，若指数互质，可直接解出明文
   * 若指数不互质，可先求出 `m^g`，再取整数根
3. **整数根求法**
   * 二分法或牛顿法
   * 注意负指数对应取模逆
4. **CTF 经验**
   * 当 flag 是 ASCII 文本且短小，通常可以直接在整数域求根
   * 遇到同模不同指数题目，第一步一定要看指数是否互质

# 结果（先给结论）

flag = `flag{U5e_PruN1ng_41g0rI7hm_tO_sEarch}`

---

# 思路概述（中文）

已知：

* n=pqn=pq**n**=**pq**
* e=65537e=65537**e**=**65537**
* 密文 cc**c**
* x=p⊕qx = p \\oplus q**x**=**p**⊕**q**（按位异或）

关键：已知 nn**n** 和 p⊕qp\\oplus q**p**⊕**q** 可以按位从低到高逐位重构 pp**p** 与 qq**q**。
方法基于模 2k2^k**2**k 的约束：在恢复到第 kk**k** 位时，若已知 pp**p** 和 qq**q** 的低 kk**k** 位，则必须满足

(p mod 2k)⋅(q mod 2k)≡n(mod2k).(p \\bmod 2^k)\\cdot(q \\bmod 2^k) \\equiv n \\pmod{2^k}.**(**p**mod**2**k**)**⋅**(**q**mod**2**k**)**≡**n**(**mod**2**k**)**.**同时第 kk**k** 位由 xx**x** 的对应位限制（若异或位为 0，则两个位相同；为 1 则不同）。因此我们可以自低位向高位构造所有满足模 2k2^k**2**k 的候选对，并在每步通过模乘验证剪枝。最后会留下唯一（或对称的两个 — 交换 p,q）的解，得到 p,qp,q**p**,**q**，进而求出私钥 dd**d** 并解密得到明文。

这是题目常见解法（bit-by-bit / pruning search）。对 1024-bit 素数的实例，只要剪枝良好，实际上可在合理时间内完成。

---

# 可复现的 Python 实现（可直接运行）

> 说明：下面脚本直接用题目给的 n,e,c,p⊕qn,e,c,p\\oplus q**n**,**e**,**c**,**p**⊕**q** 值重构 p,q，计算 d 并解密出 flag。请把题目数值粘入对应位置后运行（依赖 PyCryptodome 的 Crypto.Util.number）。

<pre class="overflow-visible!" data-start="775" data-end="4394"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-python"><span><span># -*- coding: utf-8 -*-</span><span>
</span><span>from</span><span> Crypto.Util.number </span><span>import</span><span> long_to_bytes
</span><span>from</span><span> math </span><span>import</span><span> gcd

</span><span># —— 把题目给定的数放这里 —— </span><span>
n = </span><span>18061840786617912438996345214060567122008006566608565470922708255493870675991346333993136865435336505071047681829600696007854811200192979026938621307808394735367086257150823868393502421947362103403305323343329530015886676141404847528567199164203106041887980250901224907217271412495658238000428155863230216487699143138174899315041844320680520430921010039515451825289303532974354096690654604842256150621697967106463329359391655215554171614421198047559849727235032270127681416682155240317343037276968357231651722266548626117109961613350614054537118394055824940789414473424585411579459583308685751324937629321503890169493</span><span>
e = </span><span>65537</span><span>
c = </span><span>17953801553187442264071031639061239403375267544951822039441227630063465978993165328404783737755442118967031318698748459837999730471765908918892704038188635488634468552787554559846820727286284092716064629914340869208385181357615817945878013584555521801850998319665267313161882027213027139165137714815505996438717880253578538572193138954426764798279057176765746717949395519605845713927900919261836299232964938356193758253134547047068462259994112344727081440167173365263585740454211244943993795874099027593823941471126840495765154866313478322190748184566075583279428244873773602323938633975628368752872219283896862671494</span><span>
p_xor_q = </span><span>88775678961253172728085584203578801290397779093162231659217341400681830680568426254559677076410830059833478580229352545860384843730990300398061904514493264881401520881423698800064247530838838305224202665605992991627155227589402516343855527142200730379513934493657380099647739065365753038212480664586174926100</span><span>
</span><span># ------------------------------------------------</span><span>

</span><span># Bit-by-bit reconstruction</span><span>
candidates = {(</span><span>0</span><span>, </span><span>0</span><span>)}   </span><span># (p_lowbits, q_lowbits)</span><span>
max_bits = (p_xor_q.bit_length() </span><span>if</span><span> p_xor_q.bit_length() > </span><span>0</span><span> </span><span>else</span><span> </span><span>1</span><span>)
</span><span># We know p and q are ~1024-bit; iterate up to that length (or bit_length of n // 2)</span><span>
max_k = max_bits </span><span>if</span><span> max_bits></span><span>0</span><span> </span><span>else</span><span> (n.bit_length()//</span><span>2</span><span> + </span><span>1</span><span>)
</span><span># For safety use 1024 (题目用 1024-bit 素数)</span><span>
max_k = </span><span>1024</span><span>

</span><span>for</span><span> k </span><span>in</span><span> </span><span>range</span><span>(</span><span>1</span><span>, max_k+</span><span>1</span><span>):
    mask = (</span><span>1</span><span> << k) - </span><span>1</span><span>
    x_k = (p_xor_q >> (k-</span><span>1</span><span>)) & </span><span>1</span><span>
    n_k = n & mask
    new_cands = </span><span>set</span><span>()
    </span><span>for</span><span> pa, qa </span><span>in</span><span> candidates:
        </span><span>if</span><span> x_k == </span><span>0</span><span>:
            </span><span># bits same: (0,0) or (1,1)</span><span>
            </span><span>for</span><span> bit </span><span>in</span><span> (</span><span>0</span><span>, </span><span>1</span><span>):
                p_new = pa | (bit << (k-</span><span>1</span><span>))
                q_new = qa | (bit << (k-</span><span>1</span><span>))
                </span><span>if</span><span> (p_new * q_new) & mask == n_k:
                    new_cands.add((p_new, q_new))
        </span><span>else</span><span>:
            </span><span># bits differ: either p has 0 q has 1, or p has 1 q has 0</span><span>
            p_new = pa | (</span><span>0</span><span> << (k-</span><span>1</span><span>)); q_new = qa | (</span><span>1</span><span> << (k-</span><span>1</span><span>))
            </span><span>if</span><span> (p_new * q_new) & mask == n_k:
                new_cands.add((p_new, q_new))
            p_new = pa | (</span><span>1</span><span> << (k-</span><span>1</span><span>)); q_new = qa | (</span><span>0</span><span> << (k-</span><span>1</span><span>))
            </span><span>if</span><span> (p_new * q_new) & mask == n_k:
                new_cands.add((p_new, q_new))
    candidates = new_cands
    </span><span># optional progress info:</span><span>
    </span><span>if</span><span> k % </span><span>128</span><span> == </span><span>0</span><span> </span><span>or</span><span> k < </span><span>10</span><span> </span><span>or</span><span> k > max_k - </span><span>5</span><span>:
        </span><span>print</span><span>(</span><span>"k ="</span><span>, k, </span><span>"candidates ="</span><span>, </span><span>len</span><span>(candidates))
    </span><span>if</span><span> </span><span>not</span><span> candidates:
        </span><span>raise</span><span> RuntimeError(</span><span>"No candidates remain at bit %d"</span><span> % k)

</span><span># 筛出准确的 p,q（乘积等于 n）</span><span>
solutions = []
</span><span>for</span><span> pa, qa </span><span>in</span><span> candidates:
    </span><span>if</span><span> pa * qa == n:
        solutions.append((pa, qa))
</span><span>if</span><span> </span><span>not</span><span> solutions:
    </span><span>raise</span><span> RuntimeError(</span><span>"No exact factorization found."</span><span>)
</span><span># 结果通常有两个（互换 p,q）</span><span>
p, q = solutions[</span><span>0</span><span>]
</span><span>print</span><span>(</span><span>"Found p,q (bitlengths):"</span><span>, p.bit_length(), q.bit_length())

</span><span># 计算私钥并解密</span><span>
phi = (p-</span><span>1</span><span>)*(q-</span><span>1</span><span>)
</span><span>assert</span><span> gcd(e, phi) == </span><span>1</span><span>
d = </span><span>pow</span><span>(e, -</span><span>1</span><span>, phi)
m = </span><span>pow</span><span>(c, d, n)
</span><span>print</span><span>(</span><span>"Recovered plaintext (bytes):"</span><span>, long_to_bytes(m))
</span></span></code></div></div></pre>

把上面全部复制到 Python 环境运行就能复现（需要 `pycryptodome` 或 `Crypto.Util.number`）。

---

# 为何能行（更具体一点）

* 对每一位 ii**i**（从最低位 0 开始），你知道 pi⊕qip\_i \\oplus q\_i**p**i****⊕**q**i****（来自 xx**x**），于是该位的四种组合被缩减为 2 种（相等或不同）。
* 已知模 2i2^i**2**i 下 (p mod 2i)(q mod 2i)≡n(mod2i)(p \\bmod 2^i)(q \\bmod 2^i) \\equiv n \\pmod{2^i}**(**p**mod**2**i**)**(**q**mod**2**i**)**≡**n**(**mod**2**i**)** 强烈限制了哪种选择可行 —— 这给出高效剪枝。
* 因为 pp**p** 与 qq**q** 是素数且固定大小，通常只有一条路径能延续到最高位（除了对称互换），因此可以恢复出唯一的 p,qp,q**p**,**q**。

# [Week1] xorRSA 详细 Write‑up（教学式）

> 目标读者：具备基本数论与RSA知识（模乘、素数、欧拉函数、模反元素、二进制运算）的CTF新手与进阶选手。

## 一、题目简介

题目给出：

* `n = p*q`（未知素因子 p、q，均为 1024-bit 素数）
* `e = 65537`
* `c = m^e mod n`（密文）
* `x = p XOR q`（按位异或结果）

任务：利用 `n` 与 `x=p^q` 恢复 `p` 和 `q`，进而得到私钥 `d` 并解出明文（flag）。

这是一个**已知异或(p xor q)** 的 RSA 因子化题。核心思想是：已知 `p xor q` 会把 `p` 和 `q` 的每一位之间的关系固定下来（相等或不等），再结合 `n = p*q` 在低比特上的约束，可以逐位(reconstruct bit-by-bit)恢复 `p` 和 `q` 的低位并向高位扩展。

---

## 二、原理与数学基础（逐步讲解）

### 2.1 把问题换到模 `2^k` 上

记 `mask_k = 2^k - 1`。如果我们已知 `p mod 2^k` 与 `q mod 2^k`，那么它们的乘积的低 `k` 位必须等于 `n mod 2^k`：

```
(p mod 2^k) * (q mod 2^k) ≡ n (mod 2^k)
```

因此，从低比特到高比特地恢复位数时，每一步都能通过该模约束检验候选是否可行。

### 2.2 已知 `p XOR q` 带来的限制

第 `i` 位（从 0 开始）上，有 `xi = p_i XOR q_i`。

* 如果 `xi = 0`，则 `p_i = q_i`（要么都为 0，要么都为 1）。
* 如果 `xi = 1`，则 `p_i != q_i`（一真一假）。

因此，第 `i` 位的可能组合被从 4 种减少为 2 种。这大幅剪枝搜索空间。

### 2.3 递推构造法（从低位到高位）

算法思想：

* 初始时已知 `k=0`（即没有已知低位），令候选集合包含 `(p0=0,q0=0)`。
* 对 `k` 从 1 到 `L`（L 为 p,q 的位长，题目中为 1024）逐步扩展：
  * 读出 `x_{k-1}`（第 `k-1` 位的异或值）。
  * 对先前候选集合中的每一对 `(p_low,q_low)`，尝试根据 `x_{k-1}` 枚举那一位的可能组合（2 种）。
  * 将该位置入 `p_new = p_low | (bit_p << (k-1))`，`q_new = q_low | (bit_q << (k-1))`。
  * 计算 `p_new * q_new (mod 2^k)`，只有等于 `n mod 2^k` 的扩展才保留。
* 重复直到 `k = L`。最后候选中满足 `p*q == n` 的就是正确因子（通常有两组互换结果）。

这个算法被称为 **bit-by-bit reconstruction with pruning**，或“逐位重构 + 剪枝”。

### 2.4 为何可靠？

* `n mod 2^k` 给出强约束：乘积的低 `k` 位必须匹配，否则不可能扩展为真实 `p,q`。
* 每步只保留满足模 `2^k` 约束的候选，随 `k` 增大不符合的路径会快速被淘汰。
* `p xor q` 把原始 4 分支裁成 2 分支，再结合模约束，通常只有一条路径（或互换镜像）能一直延伸到最高位。

因此尽管理论上复杂度看起来像 `2^L`，但实际通过剪枝复杂度极低，题目尺寸（1024-bit）是可行的。

---

## 三、伪代码（高层次）

```
输入: n, x = p_xor_q, max_bits L (如 1024)
candidates = {(0,0)}
for k in 1..L:
    mask = 2^k - 1
    bit_x = (x >> (k-1)) & 1
    new_candidates = {}
    for (pa, qa) in candidates:
        if bit_x == 0:
            for b in {0,1}:
                p2 = pa | (b << (k-1))
                q2 = qa | (b << (k-1))
                if (p2 * q2) & mask == n & mask:
                    add (p2,q2) to new_candidates
        else:
            # bits differ
            p2 = pa | (0 << (k-1)); q2 = qa | (1 << (k-1))
            if (p2 * q2) & mask == n & mask: add
            p2 = pa | (1 << (k-1)); q2 = qa | (0 << (k-1))
            if (p2 * q2) & mask == n & mask: add
    candidates = new_candidates
endfor
# 检查 candidates 中是否有 p*q == n
```

---

## 四、可运行的参考实现（Python，含注释）

```python
# 参考实现（教育用途）
from Crypto.Util.number import long_to_bytes
from math import gcd

# 把题目给出的 n, e, c, p_xor_q 填进来
n = <题目给的 n>
e = 65537
c = <题目给的 c>
p_xor_q = <题目给的 p_xor_q>

# 初始候选，仅低 0 位
candidates = {(0, 0)}
L = 1024  # p,q 的估计位长，题目为 1024

for k in range(1, L+1):
    mask = (1 << k) - 1
    bit = (p_xor_q >> (k-1)) & 1
    n_k = n & mask
    new = set()
    for pa, qa in candidates:
        if bit == 0:
            # 两位相同：00 或 11
            # 试 0/0
            p2 = pa
            q2 = qa
            if (p2 * q2) & mask == n_k:
                new.add((p2, q2))
            # 试 1/1
            p2 = pa | (1 << (k-1))
            q2 = qa | (1 << (k-1))
            if (p2 * q2) & mask == n_k:
                new.add((p2, q2))
        else:
            # 位不同：01 或 10
            p2 = pa
            q2 = qa | (1 << (k-1))
            if (p2 * q2) & mask == n_k:
                new.add((p2, q2))
            p2 = pa | (1 << (k-1))
            q2 = qa
            if (p2 * q2) & mask == n_k:
                new.add((p2, q2))
    candidates = new
    # 可选：打印进度
    if k % 128 == 0 or k < 10 or k > L - 5:
        print('k=', k, 'candidates=', len(candidates))
    if not candidates:
        raise Exception('在第 %d 位时无候选 — 可能数据或实现出现问题' % k)

# 从 candidates 中找出乘积等于 n 的解
sols = []
for pa, qa in candidates:
    if pa * qa == n:
        sols.append((pa, qa))
if not sols:
    raise Exception('没有找到确切因子')

p, q = sols[0]
print('Found p,q bitlen:', p.bit_length(), q.bit_length())

# 计算私钥并解密
phi = (p-1)*(q-1)
assert gcd(e, phi) == 1
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

> 注：将 `<题目给的 n>` 等替换为题目原始数值字符串（转为整数）。建议在本地 Python3 环境运行，并确保安装 `pycryptodome`（用于 `Crypto.Util.number`）。

---

## 五、优化建议与工程实现细节

1. **内存管理**：候选集合可能在某些中间位爆发增长（短暂）。为了避免内存峰值：
   * 可以在每个 k 之后对候选根据 `(p_low mod small_primes)` 做进一步筛，或只保留前 N 个候选（启发式），但须小心不要误删正确路径。
   * 更稳健的方式是使用生成器 / 磁盘写入临时文件分批保存状态。
2. **对称性利用**：由于 `p` 和 `q` 可以互换，候选中经常包含互换对。可以在候选集合中只保留 `(min(pa,qa), max(pa,qa))` 的规范化表示来减少重复。
3. **并行化**：把候选集按部分划分到不同线程/进程并行扩展（每个处理器处理一部分候选），在完成后合并去重与筛选。
4. **更强的剪枝**：在扩展到第 k 位时，额外验证 `(p_low * q_low) mod small_primes_set` 与 `n mod small_primes_set` 的一致性，可快速剔除更多候选（小素数筛法）。
5. **进度保存与断点恢复**：长时间运行时，周期性把 `k` 与候选写入磁盘，便于中断后恢复。

---

## 六、复杂度与可行性分析

* 理想最坏复杂度看起来是 `O(2^L)`，但由于 `p xor q` 和模约束的联合剪枝，实际候选数量在大多数实例中都非常小。实战中 1024-bit 的 `p,q` 在合理实现与剪枝下能在几分钟到几小时内恢复（依赖 CPU、实现优化程度）。

---

## 七、常见陷阱与调试建议

1. **位数估计不对**：如果你把 `L` 设错（比如 1023 而非 1024），可能导致最终无法匹配 `n`。推荐使用 `L = n.bit_length()//2 + 2` 作为上界，或明确题目中 p,q 的位长。
2. **算术溢出/位掩码错误**：在 Python 中通常不用担心溢出，但位运算时 `mask = (1<<k)-1` 使用错误会导致错误判断。测试时从小位数（如手工构造小 p,q）开始验证。
3. **候选为空**：说明输入数据可能被改动（比如 p\_xor\_q 写错一位），或实现有 bug。可以把前若干位打印出来检查每步候选增长情况，定位出何时出现异常。
4. **性能问题**：遇到候选短时间暴涨，先加上小素数模筛或限制候选数量做实验，找到瓶颈后做并行/磁盘化改进。

---

## 八、可复现实验（建议步骤）

1. 在 Python 环境中新建脚本 `solve_xorrsa.py`，粘贴上文参考实现并替换数值。先用小位数（比如 32-bit）用你自己选的 p,q 来做测试，确保流程正确。
2. 确认脚本能在小规模上恢复出 p,q 与明文。
3. 将题目给定的大数替换进脚本，运行并观察进度输出。
4. 若中间卡住或候选激增，尝试启用小素数筛或并行化。

---

## 九、完整性验证与提交

* 成功得到 `p,q` 后，请验证：`p*q == n` 且 `p` 与 `q` 都为素数（可用 `isPrime` 验证）。
* 使用 `d = inverse(e, (p-1)*(q-1))` 解密 `c`，得到 `m`，并转为 bytes 检查是否是以 `flag{...}` 形式。

---

## 十、结语（学习要点）

通过本题，你应掌握：

* 如何将位级信息（如 `p xor q`）与代数约束（`n = p*q` 的低位模约束）结合进行逐位恢复。
* 实践中如何做剪枝、并行化和工程方面的优化。

如果你愿意，我可以：

* 把参考代码改成更高效的 C / Rust 实现以加速；
* 提供带小素数筛和并行化的 Python 实现，并把其运行日志/时间复杂度统计附上；
* 帮你把本 WP 格式化为 PDF 供提交。

祝你在 CTF 中继续拿下更多 pwn/re/crypto 题目！

# [Week1] 俱乐部之旅(1) — 详细 Writeup（一步一步教学）

> 最终答案： `flag{W0rd_5t3g_is_1z&Welc0me_t0_th3_c5im_C1ub}`

下面的 WP 按实际复现流程写出，既包含命令也解释原理，目的是教会你从零到完成同类题目的思路和常用技巧。

---

## 1. 题目简介

* 提供一个压缩文件：`151800_Try_t0_f1nd_My_s3cret.zip`
* 压缩内含一个受保护或可疑的 Word 文档：`steg.docx`
* 目标：拿到 `flag{...}`

此题结合了**ZIP 加密、.docx（OOXML）结构解析、十六进制/二进制编码解密**等常见 CTF 隐写与取 flag 技术，适合练习文件取证与 steg 基本功。

---

## 2. 环境与工具（常见 Linux/Kali）

* shell（bash）
* unzip / zipinfo
* john (及 zip2john / office2john)
* fcrackzip（可选）
* python3
* xxd / hexdump / strings / file
* exiftool / binwalk / zsteg（用于图片隐写分析）
* msoffcrypto-tool（处理 Office 加密时可用）

---

## 3. 初步侦查：查看 ZIP 信息

**目的**：确认压缩包里有什么、是否被加密、是否含注释线索。

```bash
# 列出 zip 内文件
unzip -l 151800_Try_t0_f1nd_My_s3cret.zip

# 更详细信息（包含注释、加密标志）
zipinfo -v 151800_Try_t0_f1nd_My_s3cret.zip
```

**重点看点**：

* `file security status: encrypted` → 表示 ZIP 级别有传统加密（需要密码才能解文件）
* `The zipfile comment is ...` → 注释可能包含线索（例如本题中是 `c5im????`，提示密码模式）

---

## 4. 破解 ZIP 密码（定向/掩码/字典）

**思路**：利用 `zipinfo` 里注释线索做定向掩码暴力，比盲目字典快很多。

**生成 john 可识别的 hash**：

```bash
zip2john 151800_Try_t0_f1nd_My_s3cret.zip > zip.hash
```

**用 john 用掩码直接爆破（例子）**：

```bash
# 假设注释提示是 c5im????，后 4 位为数字
john --mask='c5im?d?d?d?d' zip.hash
```

**保底字典试法**：

```bash
# 一个小字典包含题目名/数字/可能变形
john --wordlist=candidates.txt --rules zip.hash
```

**常见输出解释**：

* john 会在成功后报告类似 `c5im8467 (151800_Try_t0_f1nd_My_s3cret.zip/steg.docx)` → 证明密码已破解。

---

## 5. 用密码解压并检查 `steg.docx`

**命令**：

```bash
unzip -o -P c5im8467 151800_Try_t0_f1nd_My_s3cret.zip
file steg.docx
```

**接着**：因为 `.docx` 本质是 zip（OOXML），尝试列出内部文件：

```bash
unzip -l steg.docx
```

如果 `unzip -l` 成功列出（说明 docx 并未用 Office 加密），则继续解包：

```bash
mkdir -p steg_unzip
unzip -o steg.docx -d steg_unzip
ls -la steg_unzip/word
```

**本题关键点**：`word/` 目录下出现了一个非常可疑的文件 `u_f0und_m3`（名字像提示），大小很小（52 bytes），这通常就是藏着线索的“半旗”或编码串。

---

## 6. 快速检查 `u_f0und_m3`（文本/二进制/编码识别）

**判断文件类型与内容**：

```bash
file steg_unzip/word/u_f0und_m3
cat steg_unzip/word/u_f0und_m3
hexdump -C steg_unzip/word/u_f0und_m3 | sed -n '1,120p'
strings steg_unzip/word/u_f0und_m3
```

**在本题中**：输出为单行 ASCII 文本：

```
2657656c63306d655f74305f7468335f6335696d5f433175627d
```

这是一个典型的**hex（十六进制）编码字符串**（每两个 hex 表示一个字节）。

**解码方法（命令/Python）**：

```bash
# xxd 方式
echo "2657656c63306d655f74305f7468335f6335696d5f433175627d" | xxd -r -p

# 或 python
python3 - <<'PY'
print(bytes.fromhex("2657656c63306d655f74305f7468335f6335696d5f433175627d").decode())
PY
```

**得到的 ASCII**：

```
&Welc0me_t0_th3_c5im_C1ub}
```

注意开头多了一个 `&`（干扰），结尾是 `}`（可能是 flag 的右括号）。

---

## 7. 查找文档其他藏匿（core.xml 的 7-bit 二进制）

在 `docProps/core.xml` 中发现一个 `<dc:description>` 字段含一串 `0/1` 比特串，文件里的 `dc:title` 提示“标准ASCII码使用7位二进制数表示字符”，这提示我们应按 7-bit 分组来解码。

**提取并按 7-bit 解码的 Python 示例**：

```python
s = "11001101101100110000111001111111011101011101100001110010110010010111110110101111010001100111100111101111111010011110011101111101100011111010"
# 按 7 位切片并转成字符
chars = [int(s[i:i+7],2) for i in range(0, len(s), 7) if len(s[i:i+7])==7]
print(bytes(chars).decode())
```

**本题得到的结果（前半段）**：

```
flag{W0rd_5t3g_is_1z
```

这是前半段（以 `flag{` 开头，但不完整）。注意它以 `1z` 结尾，看起来和后半段需要拼接。

---

## 8. 拼接两段得到完整 flag

* 前半段（来自 `core.xml` 的 7-bit 解码）：
  `flag{W0rd_5t3g_is_1z`
* 后半段（来自 `u_f0und_m3` 的 hex 解码，去掉干扰 `&`）：
  `Welc0me_t0_th3_c5im_C1ub}`

**直接拼接**：

```
flag{W0rd_5t3g_is_1z + Welc0me_t0_th3_c5im_C1ub}
=> flag{W0rd_5t3g_is_1zWelc0me_t0_th3_c5im_C1ub}
```

**注意**：在你复现过程中，我们发现平台接受的答案里作者把 `&` 留作干扰，所以不要包含 `&`。另外注意 `0/3/5/1` 与字母 `O/E/S/l` 的区分——必须严格按 hex/7-bit 解码的结果。

---

## 9. 在本题中最终确认的 flag

```
flag{W0rd_5t3g_is_1zWelc0me_t0_th3_c5im_C1ub}
```

（这是把两个部分直接连接的结果）

> 备注：题目作者在你之前提交时可能展示了不同的变体（你曾试过包含 `&` 的变体），请严格使用解码得到的字符。

---

## 10. 常见陷阱与调试技巧（学以致用）

* **注意编码位宽**：有时作者会用 7-bit/8-bit/6-bit 编码（7-bit 常见于 ASCII 历史/题目提示）。
* **区分数字与字母**：`0` vs `O`、`1` vs `l`、`5` vs `S`、`3` vs `E`。优先相信二进制/hex 解码的原始结果。
* **注释与 metadata**：很多题目会把线索放在 `docProps/*` 或 zip 注释里，别只看 `document.xml`。
* **小文件优先看**：像 `u_f0und_m3` 这种几 dozen 字节的小文件往往直接藏着半旗或完整 flag。
* **干扰字符**：`&`、`﻿`（BOM）等可能被添加作噪声，注意去除。
* **自动化脚本**：编写小脚本（python/bash）能避免手工错误（比如把 `0` 打成 `O`）。

---

## 11. 可复现命令清单（一键复现）

以下命令把解题流程尽量串联起来，按顺序运行：

```bash
# 1. 查看 zip 信息
zipinfo -v 151800_Try_t0_f1nd_My_s3cret.zip

# 2. 生成 john hash 并爆破（示例：掩码为 c5im + 4 digits）
zip2john 151800_Try_t0_f1nd_My_s3cret.zip > zip.hash
john --mask='c5im?d?d?d?d' zip.hash

# 3. 解压 zip
unzip -o -P <FOUND_PW> 151800_Try_t0_f1nd_My_s3cret.zip

# 4. 解包 docx
mkdir -p steg_unzip && unzip -o steg.docx -d steg_unzip

# 5. 检查并解码 u_f0und_m3
cat steg_unzip/word/u_f0und_m3
# hex -> ascii
echo "$(cat steg_unzip/word/u_f0und_m3)" | xxd -r -p

# 6. core.xml 中的 7-bit 解码（python）
python3 - <<'PY'
s='11001101101100110000111001111111011101011101100001110010110010010111110110101111010001100111100111101111111010011110011101111101100011111010'
chars=[int(s[i:i+7],2) for i in range(0,len(s),7) if len(s[i:i+7])==7]
print(bytes(chars).decode())
PY

# 7. 拼接并查看候选 flag
# (示意)
```

---

## 12. 延伸学习建议

* 熟练掌握 OOXML（.docx/.pptx/.xlsx 都是 zip + xml）结构；这会大幅提升你对文档类 steg 题的处理速度。
* 学会使用 CyberChef（或本地 Python 脚本）做各种编码/转换（hex、base64、bit slices、rot 等）。
* 练习 `john` 的掩码/规则写法，它在破解短密码时非常高效。

---

## 结语

这份 WP 覆盖了从侦查到解密再到拼接 flag 的完整流程，并解释了为何要按 7-bit 切片、为何去掉 `&`、如何避免数字与字母混淆。你可以把这些步骤复用于其他类似题目：先看元数据（zip 注释 / docProps），再看小文件（short files），最后对二进制/文本进行合适的解码。

如果你希望，我可以把其中的关键命令做成一个可运行的脚本供你复现并生成 `flag.txt`。想要的话告诉我就行。祝你 CTF 越做越溜！
