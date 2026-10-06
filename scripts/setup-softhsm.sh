#!/usr/bin/env bash
# サンプル用の SoftHSM2 トークンを作る。既存の本番トークンには触らないよう、専用ディレクトリを使う。
set -euo pipefail

MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"
WORK="${PKCS11_WORKDIR:-$PWD/.softhsm}"
SO_PIN="${PKCS11_SO_PIN:-5678}"
USER_PIN="${PKCS11_USER_PIN:-1234}"
LABEL="${PKCS11_TOKEN_LABEL:-demo}"

# 再実行しても同じ状態になるよう、前回のトークンは消してから作り直す
rm -rf "$WORK/tokens"
mkdir -p "$WORK/tokens"
cat > "$WORK/softhsm2.conf" <<CONF
directories.tokendir = $WORK/tokens
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$WORK/softhsm2.conf"

softhsm2-util --init-token --free --label "$LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN"
# SoftHSM2 は未初期化の空きスロットも「トークンあり」で返すため、ラベルで指定する
pkcs11-tool --module "$MODULE" --token-label "$LABEL" --login --pin "$USER_PIN" \
  --keypairgen --key-type rsa:2048 --label demo-key >/dev/null

echo "準備完了。次を実行してからサンプルを動かす:"
echo "  export SOFTHSM2_CONF=$SOFTHSM2_CONF"
