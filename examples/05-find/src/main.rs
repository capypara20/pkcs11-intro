//! 第5章 鍵の探し方と名前の付け方：ハンドル・CKA_LABEL・CKA_ID の違い、C_FindObjects での探し方、
//! ログインと見える範囲、ラベルの重複、CKA_ID で鍵ペアを結ぶこと、1セッション1検索を確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 作る鍵はすべてセッションオブジェクト（CKA_TOKEN=FALSE）なので、トークンには何も残らない。
//! トークンにある demo-key（setup-softhsm.sh が pkcs11-tool で作った RSA 鍵ペア）も一緒に探す。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::collections::BTreeSet;
use std::env;
use std::num::NonZeroUsize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// P-256 の OID（1.2.840.10045.3.1.7）を DER にしたもの
const P256: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn find_slot(lib: &Pkcs11, label: &str) -> Result<Slot> {
    for slot in lib.get_slots_with_token()? {
        if lib.get_token_info(slot)?.label() == label {
            return Ok(slot);
        }
    }
    Err(format!("ラベル {label} のトークンが見つからない").into())
}

/// 見つかったハンドルを順序に関係なく比べるため、集合にする
fn set(v: Vec<ObjectHandle>) -> BTreeSet<u64> {
    v.into_iter().map(|h| h.handle()).collect()
}

fn label(s: &str) -> Attribute {
    Attribute::Label(s.as_bytes().to_vec())
}

/// データ用の AES 鍵（セッションオブジェクト）
fn aes_key(s: &Session, name: &str) -> Result<ObjectHandle> {
    Ok(s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            label(name),
        ],
    )?)
}

/// 同じラベルの鍵がまだないときだけ作る（PKCS#11 は重複を止めないので、アプリが確かめる）
fn create_unique(s: &Session, name: &str) -> Result<ObjectHandle> {
    if !s.find_objects(&[label(name)])?.is_empty() {
        return Err(format!("ラベル {name} はもう使われている").into());
    }
    aes_key(s, name)
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let token = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    let lib = Pkcs11::new(module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &token)?;
    let s = lib.open_rw_session(slot)?;
    let pin = AuthPin::new(pin.into());

    // 3. ログインしていないと、非公開（CKA_PRIVATE=TRUE）のオブジェクトは見つからない
    let before = s.find_objects(&[])?; // まだログインしていない
    let demo_pub =
        s.find_objects(&[label("demo-key"), Attribute::Class(ObjectClass::PUBLIC_KEY)])?;
    assert_eq!(before, demo_pub, "見えるのは demo-key の公開鍵だけ");
    s.login(UserType::User, Some(&pin))?;
    let demo_priv = [
        label("demo-key"),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
    ];
    let first = s.find_objects(&demo_priv)?;
    assert_eq!(first.len(), 1);
    // ログアウトすると、非公開のセッションオブジェクトは消える（ログインし直しても戻らない）
    aes_key(&s, "tmp")?; // AES 鍵の CKA_PRIVATE は既定で TRUE
    s.logout()?;
    s.login(UserType::User, Some(&pin))?;
    assert!(s.find_objects(&[label("tmp")])?.is_empty());
    // 1. ハンドルは名前ではない。ログアウトすると非公開オブジェクトのハンドルは無効になり、番号が変わりうる
    let again = s.find_objects(&demo_priv)?;
    if lib.get_library_info()?.manufacturer_id() == "SoftHSM" {
        assert_ne!(first, again, "SoftHSM2 では新しい番号になる");
    }
    println!(
        "demo-key の秘密鍵のハンドル: {} → ログインし直したら {}",
        first[0].handle(),
        again[0].handle()
    );
    println!("ログイン前 → demo-key の公開鍵 1 件だけ。ログアウトで非公開のセッションオブジェクトは消えた");

    // この章で探す鍵：同じラベルの AES 鍵2つと、CKA_ID をそろえた EC 鍵ペア
    let old = aes_key(&s, "orders-data")?;
    let new = aes_key(&s, "orders-data")?;
    let id = vec![0xA1, 0x01];
    let (ec_pub, ec_priv) = s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::Private(false), // 公開鍵はログインなしでも見えるようにする
            Attribute::EcParams(P256.to_vec()),
            Attribute::Verify(true),
            Attribute::Id(id.clone()),
            label("orders-sign"),
        ],
        &[
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
            Attribute::Id(id.clone()),
            label("orders-sign"),
        ],
    )?;

    // 1（続き）ラベルは人が読む名前、ID はバイト列。どちらも作るときに付ける
    let demo = s.find_objects(&[label("demo-key")])?;
    assert_eq!(demo.len(), 2, "demo-key は公開鍵と秘密鍵の2つ");
    for h in &demo {
        let attrs = s.get_attributes(*h, &[AttributeType::Id])?;
        assert!(
            matches!(attrs.as_slice(), [Attribute::Id(v)] if v.is_empty()),
            "pkcs11-tool で --id を付けずに作った鍵は CKA_ID が空"
        );
    }
    println!(
        "demo-key: ハンドル {:?}、CKA_ID は空（pkcs11-tool で --id なし）",
        demo.iter().map(|h| h.handle()).collect::<Vec<_>>()
    );

    // 2. C_FindObjectsInit（テンプレート）→ C_FindObjects → C_FindObjectsFinal。空のテンプレートは「全部」
    let all = s.find_objects(&[])?;
    assert_eq!(all.len(), 6, "demo-key 2つ + この章で作った4つ");
    println!("空のテンプレート → {} 件", all.len());

    // 3（続き）セッションオブジェクトは、同じアプリの別のセッションからも見える
    let other = lib.open_ro_session(slot)?;
    assert_eq!(
        set(other.find_objects(&[label("orders-data")])?),
        set(vec![old, new])
    );
    println!("セッションオブジェクトは別のセッションからも見える");

    // 4. ラベルは重複できる。同じ名前で探すと2件返る
    let dup = s.find_objects(&[label("orders-data")])?;
    assert_eq!(set(dup), set(vec![old, new]));
    println!("CKA_LABEL=orders-data → 2 件（重複は止められない）");

    // 5. 条件は「すべて一致」で重ねる。持っていない属性で探すとエラーではなく 0 件。前方一致はない
    assert_eq!(
        s.find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
        ])?,
        vec![ec_priv]
    );
    assert!(s
        .find_objects(&[
            Attribute::KeyType(KeyType::AES),
            Attribute::ModulusBits(2048.into()),
        ])?
        .is_empty());
    assert!(
        s.find_objects(&[label("orders")])?.is_empty(),
        "前方一致はしない"
    );
    println!(
        "CLASS=秘密鍵 かつ KEY_TYPE=EC → 1 件。AES かつ MODULUS_BITS → 0 件。「orders」→ 0 件"
    );

    // 6. CKA_ID をそろえておけば、片方から相手を見つけられる
    assert_eq!(
        set(s.find_objects(&[Attribute::Id(id.clone())])?),
        set(vec![ec_pub, ec_priv])
    );
    assert_eq!(
        s.find_objects(&[
            Attribute::Id(id.clone()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ])?,
        vec![ec_priv]
    );
    println!("CKA_ID=A1 01 → 公開鍵と秘密鍵。CLASS も足すと秘密鍵だけ");

    // 7. ID は後から付け替えられる。公開鍵のハッシュ（SHA-1）を ID にすると、同じ鍵から同じ ID が決まる
    let point = match s
        .get_attributes(ec_pub, &[AttributeType::EcPoint])?
        .as_slice()
    {
        [Attribute::EcPoint(p)] => p.clone(),
        _ => return Err("CKA_EC_POINT を読めない".into()),
    };
    let hash_id = s.digest(&Mechanism::Sha1, &point)?; // C_Digest（ハッシュもトークンで）
    assert_eq!(hash_id.len(), 20);
    for h in [ec_pub, ec_priv] {
        s.update_attributes(h, &[Attribute::Id(hash_id.clone())])?; // C_SetAttributeValue
    }
    assert_eq!(
        set(s.find_objects(&[Attribute::Id(hash_id.clone())])?),
        set(vec![ec_pub, ec_priv])
    );
    assert!(s.find_objects(&[Attribute::Id(id)])?.is_empty());
    println!(
        "CKA_ID を SHA-1(公開鍵) = {:02X}{:02X}… に付け替えた",
        hash_id[0], hash_id[1]
    );

    // 8. 名前の付け方の例：ラベルに用途と世代を入れ、作る前に探す。ラベルも後から変えられる
    s.update_attributes(old, &[label("orders-data-2025")])?;
    s.update_attributes(new, &[label("orders-data-2026")])?;
    assert!(s.find_objects(&[label("orders-data")])?.is_empty());
    assert_eq!(s.find_objects(&[label("orders-data-2026")])?, vec![new]);
    assert!(
        create_unique(&s, "orders-data-2026").is_err(),
        "同じ名前は作らない"
    );
    let next = create_unique(&s, "orders-data-2027")?;
    println!(
        "ラベルを orders-data-2025 / -2026 に変えた。-2026 はもうあるので作らず、-2027 を作った"
    );

    // 9. 1つのセッションで進められる検索は1つだけ。別のセッションなら並行して探せる
    let mut it = s.iter_objects(&[])?; // C_FindObjectsInit（Final はイテレータを捨てたとき）
    assert!(it.next().is_some());
    assert_eq!(
        match s.find_objects(&[]) {
            Err(Error::Pkcs11(e, Function::FindObjectsInit)) => Some(e),
            _ => None,
        },
        Some(RvError::OperationActive)
    );
    assert_eq!(other.find_objects(&[])?.len(), 7);
    drop(it); // C_FindObjectsFinal
    println!("検索の途中で同じセッションから探す → CKR_OPERATION_ACTIVE。別のセッションなら探せる");

    // 10. たくさんあるときは、C_FindObjects で決まった数ずつ取り出せる
    let batch = NonZeroUsize::new(2).ok_or("0 は渡せない")?;
    let mut count = 0;
    for h in s.iter_objects_with_cache_size(&[], batch)? {
        h?;
        count += 1;
    }
    assert_eq!(count, s.find_objects(&[])?.len());
    println!("2 件ずつ取り出して {count} 件");

    // 11. ほかのツールはラベルと ID で鍵を呼ぶ（PKCS#11 URI、RFC 7512）。ハンドルは使わない
    let hex: String = hash_id.iter().map(|b| format!("%{b:02X}")).collect();
    let uri = format!("pkcs11:token={token};object=orders-sign;type=private;id={hex}");
    println!("PKCS#11 URI: {uri}");
    // v3.0 には変えられない一意の ID（CKA_UNIQUE_ID）がある。使えるかはトークン次第
    let info = s.get_attribute_info(ec_priv, &[AttributeType::UniqueId])?;
    let has = matches!(info.as_slice(), [AttributeInfo::Available(_)]);
    println!(
        "CKA_UNIQUE_ID: {}",
        if has {
            "あり"
        } else {
            "このトークンにはない"
        }
    );

    s.destroy_object(next)?;
    other.close()?;
    s.logout()?;
    s.close()?; // セッションオブジェクトはここで消える
    lib.finalize()?;
    println!("OK: 第5章の記述どおりに動いた");
    Ok(())
}
