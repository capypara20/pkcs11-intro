//! 第1章 オブジェクトと属性：テンプレートで作り、トークンが埋め、読める属性と読めない属性があることを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 作る鍵はすべてセッションオブジェクト（CKA_TOKEN=FALSE）なので、トークンには何も残らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn find_slot(lib: &Pkcs11, label: &str) -> Result<Slot> {
    for slot in lib.get_slots_with_token()? {
        if lib.get_token_info(slot)?.label() == label {
            return Ok(slot);
        }
    }
    Err(format!("ラベル {label} のトークンが見つからない").into())
}

/// 属性を1つ読む（C_GetAttributeValue）。読めなければ None
fn read(s: &Session, h: ObjectHandle, t: AttributeType) -> Result<Option<Attribute>> {
    Ok(s.get_attributes(h, &[t])?.into_iter().next())
}

/// AES 鍵を作る（C_GenerateKey）。CKA_CLASS と CKA_KEY_TYPE は書かない：メカニズムから決まる
fn aes_key(s: &Session, label: &str, sensitive: bool, extractable: bool) -> Result<ObjectHandle> {
    let template = [
        Attribute::Token(false), // セッションオブジェクト（閉じたら消える）
        Attribute::Label(label.into()),
        Attribute::ValueLen(32.into()), // 鍵長 32 バイト
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Sensitive(sensitive),
        Attribute::Extractable(extractable),
    ];
    Ok(s.generate_key(&Mechanism::AesKeyGen, &template)?)
}

fn by_label(s: &Session, label: &str) -> Result<usize> {
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(label.into()),
    ];
    Ok(s.find_objects(&template)?.len()) // C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
}

/// CKA_VALUE が「秘匿で読めない」状態か（C_GetAttributeValue が CKR_ATTRIBUTE_SENSITIVE を返す）
fn value_hidden(s: &Session, h: ObjectHandle) -> Result<bool> {
    let info = s.get_attribute_info(h, &[AttributeType::Value])?;
    Ok(matches!(info.as_slice(), [AttributeInfo::Sensitive]))
}

/// 属性の状態だけを調べる（値は読まない）。TypeInvalid ならその種類のオブジェクトにはない属性
fn info(s: &Session, h: ObjectHandle, t: AttributeType) -> Result<AttributeInfo> {
    Ok(s.get_attribute_info(h, &[t])?.remove(0))
}

/// 鍵の種類が変われば、持つ属性（下の層）が変わることを確かめる
fn other_kinds(s: &Session) -> Result<()> {
    use AttributeInfo::{Available, Sensitive, TypeInvalid};
    // RSA：鍵長 CKA_MODULUS_BITS は公開鍵側のテンプレートに書く
    let (rsa_pub, rsa_priv) = s.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Verify(true),
        ],
        &[
            Attribute::Token(false),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
        ],
    )?;
    // 秘密鍵には CKA_MODULUS_BITS がなく、秘密指数 d は SENSITIVE で読めない
    assert!(matches!(
        info(s, rsa_priv, AttributeType::ModulusBits)?,
        TypeInvalid
    ));
    assert!(matches!(
        info(s, rsa_priv, AttributeType::Modulus)?,
        Available(_)
    ));
    assert!(matches!(
        info(s, rsa_priv, AttributeType::PrivateExponent)?,
        Sensitive
    ));
    // 公開鍵には CKA_SENSITIVE そのものがない
    assert!(matches!(
        info(s, rsa_pub, AttributeType::ModulusBits)?,
        Available(_)
    ));
    assert!(matches!(
        info(s, rsa_pub, AttributeType::Sensitive)?,
        TypeInvalid
    ));
    println!("RSA: 秘密鍵に MODULUS_BITS はない、公開鍵に SENSITIVE はない");

    // EC：曲線 CKA_EC_PARAMS（P-256 の OID を DER で）を公開鍵側に書く
    let p256 = vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let (ec_pub, ec_priv) = s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::EcParams(p256),
            Attribute::Verify(true),
        ],
        &[
            Attribute::Token(false),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
        ],
    )?;
    assert!(matches!(
        info(s, ec_pub, AttributeType::EcPoint)?,
        Available(_)
    ));
    assert!(matches!(
        info(s, ec_pub, AttributeType::ModulusBits)?,
        TypeInvalid
    ));
    assert!(matches!(
        info(s, ec_priv, AttributeType::EcParams)?,
        Available(_)
    ));
    assert!(matches!(info(s, ec_priv, AttributeType::Value)?, Sensitive));
    println!("EC: 公開鍵に EC_POINT、秘密鍵に EC_PARAMS。秘密値 CKA_VALUE は読めない");

    // 上の層の属性はどの種類も同じように持つ
    for h in [rsa_pub, rsa_priv, ec_pub, ec_priv] {
        assert!(matches!(info(s, h, AttributeType::Label)?, Available(_)));
        assert!(matches!(info(s, h, AttributeType::Local)?, Available(_)));
    }
    for h in [rsa_pub, rsa_priv, ec_pub, ec_priv] {
        s.destroy_object(h)?; // C_DestroyObject
    }
    Ok(())
}

fn is_read_only(r: cryptoki::error::Result<()>) -> bool {
    matches!(r, Err(Error::Pkcs11(RvError::AttributeReadOnly, _)))
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    let lib = Pkcs11::new(module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;
    let a = lib.open_rw_session(slot)?;
    let b = lib.open_ro_session(slot)?;
    a.login(UserType::User, Some(&AuthPin::new(pin.into())))?;

    // 1. テンプレートで作る。返るのはハンドル
    let key = aes_key(&a, "ch1-sealed", true, false)?;
    println!("生成: ハンドル {key}");

    // 2. 書かなかった属性はトークンが埋める
    assert_eq!(
        read(&a, key, AttributeType::Class)?,
        Some(Attribute::Class(ObjectClass::SECRET_KEY))
    );
    assert_eq!(
        read(&a, key, AttributeType::KeyType)?,
        Some(Attribute::KeyType(KeyType::AES))
    );
    assert_eq!(
        read(&a, key, AttributeType::Local)?,
        Some(Attribute::Local(true))
    );
    assert_eq!(
        read(&a, key, AttributeType::AlwaysSensitive)?,
        Some(Attribute::AlwaysSensitive(true))
    );
    assert_eq!(
        read(&a, key, AttributeType::NeverExtractable)?,
        Some(Attribute::NeverExtractable(true))
    );
    println!("トークンが埋めた: CLASS=SECRET_KEY, KEY_TYPE=AES, LOCAL/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE=TRUE");

    // 3. SENSITIVE=TRUE の鍵の値は読めない（CKR_ATTRIBUTE_SENSITIVE）
    assert!(value_hidden(&a, key)?);
    println!("CKA_VALUE: 読めない（CKR_ATTRIBUTE_SENSITIVE）");

    // SENSITIVE=FALSE でも、EXTRACTABLE=FALSE なら値は読めない
    let locked = aes_key(&a, "ch1-locked", false, false)?;
    assert!(value_hidden(&a, locked)?);
    println!("ch1-locked（SENSITIVE=FALSE, EXTRACTABLE=FALSE）: CKA_VALUE は読めない");

    // 4. ラベルは書き換えられる。SENSITIVE を FALSE に戻すことはできない
    a.update_attributes(key, &[Attribute::Label("ch1-renamed".into())])?;
    assert_eq!(by_label(&a, "ch1-renamed")?, 1);
    assert!(is_read_only(
        a.update_attributes(key, &[Attribute::Sensitive(false)])
    ));
    println!("LABEL は変更できた。SENSITIVE TRUE→FALSE は CKR_ATTRIBUTE_READ_ONLY");

    // 5. SENSITIVE=FALSE で作った鍵は値が読める。FALSE→TRUE は許され、履歴は ALWAYS_SENSITIVE に残る
    let open = aes_key(&a, "ch1-open", false, true)?;
    match read(&a, open, AttributeType::Value)? {
        Some(Attribute::Value(v)) => assert_eq!(v.len(), 32),
        other => panic!("値が読めるはず: {other:?}"),
    }
    a.update_attributes(open, &[Attribute::Sensitive(true)])?;
    assert!(value_hidden(&a, open)?);
    assert_eq!(
        read(&a, open, AttributeType::AlwaysSensitive)?,
        Some(Attribute::AlwaysSensitive(false))
    );
    println!("ch1-open: 値を読めた → SENSITIVE=TRUE にした → もう読めない。ALWAYS_SENSITIVE=FALSE のまま");

    // EXTRACTABLE は逆向き：TRUE→FALSE だけ許され、履歴は NEVER_EXTRACTABLE に残る
    a.update_attributes(open, &[Attribute::Extractable(false)])?;
    assert!(is_read_only(
        a.update_attributes(open, &[Attribute::Extractable(true)])
    ));
    assert_eq!(
        read(&a, open, AttributeType::NeverExtractable)?,
        Some(Attribute::NeverExtractable(false))
    );
    println!("ch1-open: EXTRACTABLE TRUE→FALSE は通り、FALSE→TRUE は CKR_ATTRIBUTE_READ_ONLY");

    // 6. 種類が変われば持つ属性も変わる（RSA・EC）
    other_kinds(&a)?;

    // 7. 検索条件もテンプレート。書いた属性がすべて一致するものだけ返る
    let aes = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
    ];
    assert_eq!(b.find_objects(&aes)?.len(), 3);
    println!("CLASS=SECRET_KEY かつ KEY_TYPE=AES で検索: 3 件");

    // 8. セッションオブジェクトは同じアプリの別セッションからも見えるが、作ったセッションを閉じると消える
    assert_eq!(by_label(&b, "ch1-renamed")?, 1);
    a.close()?;
    assert_eq!(by_label(&b, "ch1-renamed")?, 0);
    assert_eq!(b.find_objects(&aes)?.len(), 0);
    println!("セッション A を閉じたら、A が作った鍵は B からも見えなくなった");

    b.close()?; // 最後のセッションを閉じるとログアウトも済む
    lib.finalize()?;
    println!("OK: 第1章の記述どおりに動いた");
    Ok(())
}
