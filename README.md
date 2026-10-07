# PKCS#11 入門

PKCS#11（Cryptoki）を、図とアニメーションで段階的に説明する日本語ドキュメントです。
コード例はすべて Rust（[cryptoki](https://crates.io/crates/cryptoki) クレート）で、動作確認には SoftHSM2 を使います。

- 公開ページ：GitHub Pages（`index.html` から各章へ）
- 各章は1画面構成です。「次へ」または → キーで図が1段階ずつ組み上がります
  - `A` 全体を表示。最後の手順の「次へ」で最初に戻る
  - `#3` のように手順番号を URL に付けると、その手順から開きます

## 方針

- 根拠は OASIS が公開している PKCS#11 仕様書のみとし、特定ベンダの製品情報は扱いません
- 関数がどの版の仕様から存在するかを、章ごとに明記します
- サンプルは CI で SoftHSM2 に対して実際に実行し、記述と挙動のずれを防ぎます

## 根拠にしている仕様書（OASIS）

- [PKCS #11 Base Specification Version 2.40（エラッタ 01 反映版）](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html) … 関数・データ型・オブジェクトと属性。このサイトの基準
- [PKCS #11 Current Mechanisms Specification Version 2.40](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html) … RSA・EC・AES・3DES などのメカニズムとパラメータ
- [PKCS #11 Base Specification Version 3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html) … v3.0 で追加された関数・属性（CKA_UNIQUE_ID など）
- [PKCS #11 Specification Version 3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html) … Base と Mechanisms を1冊にまとめた版
- [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html) … 最新版
- [OASIS PKCS 11 TC](https://www.oasis-open.org/committees/pkcs11) … 仕様を作っている技術委員会のページ（版の一覧・ヘッダファイル）

## 構成

```
index.html            目次
docs/                 各章（NN-*.html）とリファレンス（ref-*.html）
assets/               共通のスタイルとスクリプト（chapter.css / steps.js は第1章以降の章ページ用）
diagrams/             図の元データ（draw.io）
examples/             Rust サンプル（Cargo workspace）
scripts/              SoftHSM2 のテスト用トークン作成
```

## サンプルを動かす

Ubuntu の場合：

```sh
sudo apt-get install -y softhsm2 opensc
bash scripts/setup-softhsm.sh
export SOFTHSM2_CONF=$PWD/.softhsm/softhsm2.conf
cd examples && cargo run -p overview && cargo run -p objects && cargo run -p keygen && cargo run -p sign && cargo run -p crypt
```

テスト用トークン（ラベル `demo`）はリポジトリ内の `.softhsm/` に作られ、既存の SoftHSM2 トークンには影響しません。
スクリプトは実行のたびにトークンを作り直します。サンプルは結果を assert で確かめるので、章の記述と挙動がずれると CI が失敗します。

## ライセンス

未定（決まり次第記載）
