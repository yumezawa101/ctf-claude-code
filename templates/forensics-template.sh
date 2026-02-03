#!/bin/bash
# CTF Forensics テンプレート
# 使い方: ./forensics-template.sh <filename>

FILE="${1:-challenge}"

echo "=== 基本情報 ==="
file "$FILE"
echo ""

echo "=== strings (flag検索) ==="
strings "$FILE" | grep -iE "flag|ctf|hint|password|secret" | head -20
echo ""

echo "=== Exiftool ==="
exiftool "$FILE" 2>/dev/null | head -30
echo ""

echo "=== Binwalk ==="
binwalk "$FILE"
echo ""

echo "=== xxd (先頭) ==="
xxd "$FILE" | head -20
echo ""

echo "=== xxd (末尾) ==="
xxd "$FILE" | tail -20
echo ""

# === 画像ファイルの場合 ===
if file "$FILE" | grep -qi "image\|png\|jpeg\|gif"; then
    echo "=== 画像解析 ==="

    # PNG: zsteg
    if file "$FILE" | grep -qi "png"; then
        echo "--- zsteg ---"
        zsteg "$FILE" 2>/dev/null | head -20
    fi

    # JPEG: steghide
    if file "$FILE" | grep -qi "jpeg\|jpg"; then
        echo "--- steghide (パスワード空) ---"
        steghide extract -sf "$FILE" -p "" 2>/dev/null
    fi
fi

# === アーカイブの場合 ===
if file "$FILE" | grep -qi "zip\|archive"; then
    echo "=== ZIP情報 ==="
    zipinfo "$FILE" 2>/dev/null
    unzip -l "$FILE" 2>/dev/null
fi

# === PCAPの場合 ===
if file "$FILE" | grep -qi "pcap\|capture"; then
    echo "=== PCAP解析 ==="
    echo "--- プロトコル統計 ---"
    tshark -r "$FILE" -q -z io,phs 2>/dev/null | head -30
    echo "--- HTTP リクエスト ---"
    tshark -r "$FILE" -Y "http.request" -T fields -e http.host -e http.request.uri 2>/dev/null | head -20
    echo "--- FTP認証情報 ---"
    tshark -r "$FILE" -Y "ftp.request.command == USER || ftp.request.command == PASS" 2>/dev/null
fi

echo ""
echo "=== 追加コマンド ==="
echo "binwalk -e $FILE          # 埋め込みファイル抽出"
echo "foremost -i $FILE         # ファイルカービング"
echo "volatility3 -f $FILE      # メモリダンプ解析"
