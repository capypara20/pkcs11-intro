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
cd examples && cargo run -p overview && cargo run -p objects && cargo run -p keypair && cargo run -p sign && cargo run -p crypt
```

テスト用トークン（ラベル `demo`）はリポジトリ内の `.softhsm/` に作られ、既存の SoftHSM2 トークンには影響しません。
スクリプトは実行のたびにトークンを作り直します。サンプルは結果を assert で確かめるので、章の記述と挙動がずれると CI が失敗します。

## ライセンス

未定（決まり次第記載）
