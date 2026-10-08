#!/usr/bin/env bash
# コマンドリファレンス（docs/ref-commands.html）に載せたコマンドを、そのとおりに動かして確かめる。
# pkcs11-tool は pkcs11-spy を通して呼び、ページに書いた関数が実際に呼ばれたかも確かめる。
# このファイルはページの表から作った（手で直さない）。テスト用トークン（SoftHSM2）の専用の置き場を使うので、demo トークンには触らない。
set -euo pipefail
MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"
SPY="${PKCS11_SPY:-/usr/lib/x86_64-linux-gnu/pkcs11-spy.so}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK/tokens" > "$WORK/softhsm2.conf"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
cd "$WORK"

fail() { echo "NG $1: $2"; cat out.txt; exit 1; }
# p11 <id> <期待する出力> <呼ばれるべき関数> <pkcs11-tool の引数…>
p11() {
  local id=$1 expect=$2 funcs=$3
  shift 3
  rm -f spy.log
  PKCS11SPY="$MODULE" PKCS11SPY_OUTPUT="$WORK/spy.log" pkcs11-tool --module "$SPY" "$@" >out.txt 2>&1 || fail "$id" "終了コードが 0 でない"
  [ -z "$expect" ] || grep -Eq "$expect" out.txt || fail "$id" "出力に /$expect/ がない"
  for f in $funcs; do grep -Eq "^[0-9]+: $f( |$)" spy.log || fail "$id" "$f が呼ばれていない"; done
}
# shc <id> <期待する出力> <コマンド>
shc() {
  local id=$1 expect=$2
  bash -c "$3" >out.txt 2>&1 || [ "$id" = pin-count-low ] || fail "$id" "終了コードが 0 でない"
  grep -Eq "$expect" out.txt || fail "$id" "出力に /$expect/ がない"
}

# 下準備：証明書と PKCS#8 の鍵（openssl で作る）、ハッシュする元データ、空きスロット
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout web.key -subj /CN=web -days 30 -outform DER -out web.der 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in web.key -outform DER -out web.p8.der
printf 'hello hsm' > data.txt

# A. トークンを用意する
FREE=$(softhsm2-util --show-slots | awk '/^Slot /{s=$2} /Initialized:/{if($2=="no"){print s; exit}}')
p11 init-token 'Token successfully initialized' C_InitToken --slot $FREE --init-token --label maint --so-pin 5678
echo "OK init-token"
p11 init-pin 'User PIN successfully initialized' 'C_Login C_InitPIN' --token-label maint --login --login-type so --so-pin 5678 --init-pin --new-pin 1111
echo "OK init-pin"

# B. 状態を見る
p11 list-slots 'token label +: maint' 'C_GetSlotList C_GetSlotInfo C_GetTokenInfo' -L
pkcs11-tool --module "$MODULE" --token-label mai -O >/dev/null 2>&1 || fail list-slots '追加の確認に失敗'
echo "OK list-slots"
p11 show-info 'Cryptoki version' C_GetInfo -I
echo "OK show-info"
p11 list-mechanisms ECDSA 'C_GetMechanismList C_GetMechanismInfo' --token-label maint -M
echo "OK list-mechanisms"

# C. 鍵を作る・入れる・出す
p11 keypairgen 'Key pair generated' C_GenerateKeyPair --token-label maint --login --pin 1111 --keypairgen --key-type EC:prime256v1 --id 01 --label orders-sign --usage-sign
echo "OK keypairgen"
p11 keygen 'Key generated' C_GenerateKey --token-label maint --login --pin 1111 --keygen --key-type AES:32 --id 02 --label orders-data --sensitive
echo "OK keygen"
p11 list-objects 'Private Key Object' 'C_FindObjectsInit C_FindObjects C_GetAttributeValue C_FindObjectsFinal' --token-label maint --login --pin 1111 -O
echo "OK list-objects"
p11 read-pubkey '' 'C_FindObjects C_GetAttributeValue' --token-label maint --read-object --type pubkey --id 01 -o pub.der
openssl pkey -pubin -inform DER -in pub.der -noout -text | grep -q 'Public-Key: (256 bit)' || fail read-pubkey '追加の確認に失敗'
echo "OK read-pubkey"
p11 write-cert 'Created certificate' C_CreateObject --token-label maint --login --pin 1111 --write-object web.der --type cert --id 03 --label web
echo "OK write-cert"
p11 import-key 'Created private key' C_CreateObject --token-label maint --login --pin 1111 --write-object web.p8.der --type privkey --id 03 --label web --sensitive
echo "OK import-key"

# D. 動かして確かめる
p11 random '' C_GenerateRandom --token-label maint --generate-random 16 -o rnd.bin
test "$(stat -c %s rnd.bin)" = 16 || fail random '追加の確認に失敗'
echo "OK random"
p11 hash '' 'C_DigestInit C_DigestUpdate C_DigestFinal' --token-label maint --hash -m SHA256 -i data.txt -o h.bin
cmp -s h.bin <(openssl dgst -sha256 -binary data.txt) || fail hash '追加の確認に失敗'
echo "OK hash"
p11 sign '' 'C_SignInit C_Sign' --token-label maint --login --pin 1111 --sign -m ECDSA --id 01 -i h.bin -o sig.der --signature-format openssl
openssl pkey -pubin -inform DER -in pub.der -out pub.pem && openssl dgst -sha256 -verify pub.pem -signature sig.der data.txt | grep -q 'Verified OK' || fail sign '追加の確認に失敗'
echo "OK sign"
p11 verify 'Signature is valid' 'C_VerifyInit C_Verify' --token-label maint --login --pin 1111 --verify -m ECDSA --id 01 -i h.bin --signature-file sig.der --signature-format openssl
echo "OK verify"
p11 test 'No errors' 'C_GenerateRandom C_DigestInit C_DigestUpdate C_DigestFinal' --token-label maint --login --pin 1111 --test
echo "OK test"

# E. 変える・消す
p11 set-id-priv 'ID: +11' C_SetAttributeValue --token-label maint --login --pin 1111 --set-id 11 --type privkey --id 01
! pkcs11-tool --module "$MODULE" --token-label maint --login --pin 1111 --verify -m ECDSA --id 11 -i h.bin --signature-file sig.der --signature-format openssl >/dev/null 2>&1 || fail set-id-priv '追加の確認に失敗'
echo "OK set-id-priv"
p11 set-id-pub 'ID: +11|label: +orders-sign' C_SetAttributeValue --token-label maint --login --pin 1111 --set-id 11 --type pubkey --id 01
pkcs11-tool --module "$MODULE" --token-label maint --login --pin 1111 --verify -m ECDSA --id 11 -i h.bin --signature-file sig.der --signature-format openssl 2>/dev/null | grep -q 'Signature is valid' || fail set-id-pub '追加の確認に失敗'
echo "OK set-id-pub"
p11 delete-cert '' C_DestroyObject --token-label maint --login --pin 1111 --delete-object --type cert --id 03
! pkcs11-tool --module "$MODULE" --token-label maint --login --pin 1111 -O --type cert 2>/dev/null | grep -q 'Certificate Object' || fail delete-cert '追加の確認に失敗'
echo "OK delete-cert"

# F. PIN の管理
p11 change-pin 'PIN successfully changed' 'C_Login C_SetPIN' --token-label maint --login --pin 1111 --change-pin --new-pin 2222
! pkcs11-tool --module "$MODULE" --token-label maint --login --pin 1111 -O >/dev/null 2>&1 || fail change-pin '追加の確認に失敗'
echo "OK change-pin"
shc pin-count-low 'user PIN count low' "for i in 1 2 3; do pkcs11-tool --module \"$MODULE\" --token-label maint --login --pin 9999 -O; done; pkcs11-tool --module \"$MODULE\" -L"
echo "OK pin-count-low"
p11 unlock 'User PIN successfully initialized' 'C_Login C_InitPIN' --token-label maint --login --login-type so --so-pin 5678 --init-pin --new-pin 3333
pkcs11-tool --module "$MODULE" -L 2>/dev/null | grep -A6 maint | grep flags | grep -vq 'count low' && pkcs11-tool --module "$MODULE" --token-label maint --login --pin 3333 -O >/dev/null 2>&1 || fail unlock '追加の確認に失敗'
echo "OK unlock"

# G. 呼ばれた関数を記録する（pkcs11-spy）
shc spy C_GetSlotList "PKCS11SPY=\"$MODULE\" PKCS11SPY_OUTPUT=spy-list.log pkcs11-tool --module $SPY -L >/dev/null && grep -E '^[0-9]+: C_' spy-list.log"
echo "OK spy"
shc spy-app hSession "PKCS11SPY=\"$MODULE\" PKCS11SPY_OUTPUT=spy-app.log pkcs11-tool --module $SPY --token-label maint --login --pin 3333 -O >/dev/null && grep -Eq '^[0-9]+: C_Login' spy-app.log && grep -A3 -E '^[0-9]+: C_Login' spy-app.log"
echo "OK spy-app"

echo "OK: コマンドリファレンスのコマンドはすべて記述どおりに動いた"
