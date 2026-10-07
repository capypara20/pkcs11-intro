//! 第2章 鍵の生成：共通鍵は C_GenerateKey（テンプレート1つ）、鍵ペアは C_GenerateKeyPair（2つ）で作る。
//! 長さの書き方は鍵の種類で違うこと、生成した鍵と持ち込んだ鍵の違い、テンプレートのどちら側に何を書くか、
//! トークンが何を作るかを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 共通鍵はセッションオブジェクト、鍵ペアはトークンオブジェクト（CKA_TOKEN=TRUE）として作り、最後に C_DestroyObject で消す。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const ID: [u8; 1] = [0x01];
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

fn read(s: &Session, h: ObjectHandle, t: AttributeType) -> Result<Attribute> {
    s.get_attributes(h, &[t])?
        .pop()
        .ok_or_else(|| format!("{t:?} が読めない").into())
}

fn info(s: &Session, h: ObjectHandle, t: AttributeType) -> Result<AttributeInfo> {
    Ok(s.get_attribute_info(h, &[t])?.remove(0))
}

fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

/// 失敗を試す用：トークンには残さない（SoftHSM2 は失敗した生成でも、作りかけの
/// オブジェクトを残すことがある。セッションオブジェクトなら閉じれば消える）
fn session_only(t: Vec<Attribute>) -> Vec<Attribute> {
    t.into_iter()
        .map(|a| match a {
            Attribute::Token(_) => Attribute::Token(false),
            a => a,
        })
        .collect()
}

/// 公開鍵側：強さ（鍵長・曲線）と、検証などの用途
fn pub_template(strength: &[Attribute]) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::Token(true),
        Attribute::Label("signer".into()),
        Attribute::Id(ID.to_vec()),
        Attribute::Verify(true),
    ];
    t.extend_from_slice(strength);
    t
}

/// 秘密鍵側：守り（見えない・読めない・持ち出せない）と、署名などの用途
fn priv_template() -> Vec<Attribute> {
    vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label("signer".into()),
        Attribute::Id(ID.to_vec()),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ]
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    let lib = Pkcs11::new(module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;

    // 1. 作れるか・大きさの範囲はトークンに聞く（C_GetMechanismInfo）。単位はメカニズムで違う
    let aes = lib.get_mechanism_info(slot, MechanismType::AES_KEY_GEN)?;
    assert!(
        aes.generate() && !aes.generate_key_pair(),
        "共通鍵は C_GenerateKey で作る"
    );
    assert_eq!(
        (aes.min_key_size(), aes.max_key_size()),
        (16, 32),
        "AES はバイトで 16〜32"
    );
    let des3 = lib.get_mechanism_info(slot, MechanismType::DES3_KEY_GEN)?;
    assert!(des3.generate());
    for (name, m) in [
        (
            "CKM_RSA_PKCS_KEY_PAIR_GEN",
            MechanismType::RSA_PKCS_KEY_PAIR_GEN,
        ),
        ("CKM_EC_KEY_PAIR_GEN", MechanismType::ECC_KEY_PAIR_GEN),
    ] {
        let mi = lib.get_mechanism_info(slot, m)?;
        assert!(
            mi.generate_key_pair() && !mi.generate(),
            "{name} は C_GenerateKeyPair で作る"
        );
        println!(
            "{name}: 鍵ペア生成 OK, 鍵長 {}〜{}",
            mi.min_key_size(),
            mi.max_key_size()
        );
    }
    println!(
        "CKM_AES_KEY_GEN: 共通鍵の生成 OK, {}〜{} バイト。CKM_DES3_KEY_GEN: 長さは固定（{}〜{}）",
        aes.min_key_size(),
        aes.max_key_size(),
        des3.min_key_size(),
        des3.max_key_size()
    );

    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;
    // 2. 共通鍵：C_GenerateKey にテンプレート1つ。AES は長さ CKA_VALUE_LEN を書く
    let secret = |extra: &[Attribute]| -> Vec<Attribute> {
        let mut t = vec![
            Attribute::Token(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ];
        t.extend_from_slice(extra);
        t
    };
    let aes_key = s.generate_key(
        &Mechanism::AesKeyGen,
        &secret(&[Attribute::ValueLen(32.into())]),
    )?; // C_GenerateKey(CKM_AES_KEY_GEN)
    assert_eq!(
        read(&s, aes_key, AttributeType::KeyType)?,
        Attribute::KeyType(KeyType::AES)
    );
    assert_eq!(
        rv(s.generate_key(&Mechanism::AesKeyGen, &secret(&[]))),
        Some(RvError::TemplateIncomplete),
        "AES は長さを書かないと作れない"
    );
    assert_eq!(
        rv(s.generate_key(
            &Mechanism::AesKeyGen,
            &secret(&[Attribute::ValueLen(20.into())])
        )),
        Some(RvError::AttributeValueInvalid),
        "AES の長さは 16 / 24 / 32 バイトだけ"
    );
    assert_eq!(
        rv(s.generate_key(
            &Mechanism::AesKeyGen,
            &secret(&[
                Attribute::ValueLen(32.into()),
                Attribute::KeyType(KeyType::DES3)
            ])
        )),
        Some(RvError::TemplateInconsistent),
        "メカニズムと食い違う CKA_KEY_TYPE は書けない"
    );
    println!("AES: 32 バイトで生成 OK。長さなし → TEMPLATE_INCOMPLETE、20 バイト → ATTRIBUTE_VALUE_INVALID");

    // 3. DES・3DES は長さが決まっている。CKA_VALUE_LEN は書けない
    let des3_key = s.generate_key(&Mechanism::Des3KeyGen, &secret(&[]))?;
    assert_eq!(
        read(&s, des3_key, AttributeType::KeyType)?,
        Attribute::KeyType(KeyType::DES3)
    );
    let des2_key = s.generate_key(&Mechanism::Des2KeyGen, &secret(&[]))?;
    assert_eq!(
        read(&s, des2_key, AttributeType::KeyType)?,
        Attribute::KeyType(KeyType::DES2)
    );
    assert_eq!(
        rv(s.generate_key(
            &Mechanism::Des3KeyGen,
            &secret(&[Attribute::ValueLen(24.into())])
        )),
        Some(RvError::AttributeTypeInvalid),
        "DES 系は CKA_VALUE_LEN を持たない"
    );
    println!("3DES: 長さを書かずに生成 OK。CKA_VALUE_LEN を書く → ATTRIBUTE_TYPE_INVALID");

    // 4. 汎用の共通鍵（HMAC 用）は長さを自由に決める
    let mac_t = [
        Attribute::Token(false),
        Attribute::Sign(true),
        Attribute::Verify(true),
    ];
    assert_eq!(
        rv(s.generate_key(&Mechanism::GenericSecretKeyGen, &mac_t)),
        Some(RvError::TemplateIncomplete)
    );
    let mac_key = s.generate_key(
        &Mechanism::GenericSecretKeyGen,
        &[mac_t.to_vec(), vec![Attribute::ValueLen(20.into())]].concat(),
    )?;
    assert_eq!(
        read(&s, mac_key, AttributeType::ValueLen)?,
        Attribute::ValueLen(20.into())
    );
    println!("汎用の共通鍵: 20 バイトで生成 OK（長さは自由。書き忘れると TEMPLATE_INCOMPLETE）");

    // 5. 生成した鍵と、外から持ち込んだ鍵（C_CreateObject）の違いは記録の属性に残る
    let imported = s.create_object(&[
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Value(vec![0x42; 32]),
        Attribute::Encrypt(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ])?; // C_CreateObject
    for (h, expected) in [(aes_key, true), (imported, false)] {
        assert_eq!(
            read(&s, h, AttributeType::Local)?,
            Attribute::Local(expected)
        );
        assert_eq!(
            read(&s, h, AttributeType::AlwaysSensitive)?,
            Attribute::AlwaysSensitive(expected)
        );
        assert_eq!(
            read(&s, h, AttributeType::NeverExtractable)?,
            Attribute::NeverExtractable(expected)
        );
    }
    assert_eq!(
        rv(s.create_object(&[
            Attribute::Token(false),
            Attribute::KeyType(KeyType::AES),
            Attribute::Value(vec![0x42; 32]),
        ])),
        Some(RvError::TemplateIncomplete),
        "持ち込むときは CKA_CLASS を自分で書く"
    );
    println!("生成: LOCAL/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE = TRUE、持ち込み: すべて FALSE");

    let keys = [Attribute::Class(ObjectClass::PRIVATE_KEY)];
    let before = s.find_objects(&keys)?.len();

    // 6. RSA：1回の呼び出しで2つできる。鍵長は公開鍵側に書く
    let rsa_strength = [
        Attribute::ModulusBits(2048.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    ];
    let (rsa_pub, rsa_priv) = s.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &pub_template(&rsa_strength),
        &priv_template(),
    )?; // C_GenerateKeyPair
    println!("RSA: 公開鍵 {rsa_pub}, 秘密鍵 {rsa_priv}");

    // CLASS・KEY_TYPE・LOCAL はトークンが決める
    assert_eq!(
        read(&s, rsa_pub, AttributeType::Class)?,
        Attribute::Class(ObjectClass::PUBLIC_KEY)
    );
    assert_eq!(
        read(&s, rsa_priv, AttributeType::Class)?,
        Attribute::Class(ObjectClass::PRIVATE_KEY)
    );
    assert_eq!(
        read(&s, rsa_priv, AttributeType::KeyType)?,
        Attribute::KeyType(KeyType::RSA)
    );
    assert_eq!(
        read(&s, rsa_pub, AttributeType::Local)?,
        Attribute::Local(true)
    );
    // 秘密鍵側の守り
    assert_eq!(
        read(&s, rsa_priv, AttributeType::AlwaysSensitive)?,
        Attribute::AlwaysSensitive(true)
    );
    assert_eq!(
        read(&s, rsa_priv, AttributeType::NeverExtractable)?,
        Attribute::NeverExtractable(true)
    );
    assert!(matches!(
        info(&s, rsa_priv, AttributeType::PrivateExponent)?,
        AttributeInfo::Sensitive
    ));
    // 公開鍵の値は読める。秘密鍵の n も同じ値（n は公開情報）
    let n_pub = read(&s, rsa_pub, AttributeType::Modulus)?;
    let n_priv = read(&s, rsa_priv, AttributeType::Modulus)?;
    match &n_pub {
        Attribute::Modulus(n) => assert_eq!(n.len(), 256, "2048 ビット = 256 バイト"),
        other => panic!("{other:?}"),
    }
    assert_eq!(n_pub, n_priv);
    assert_eq!(
        read(&s, rsa_pub, AttributeType::ModulusBits)?,
        Attribute::ModulusBits(2048.into())
    );
    println!("RSA: n（256 バイト）は両方から読め、d は読めない");

    // 7. 同じ CKA_ID でペアを探せる
    let pair = s.find_objects(&[Attribute::Id(ID.to_vec())])?;
    assert_eq!(pair.len(), 2);
    println!("CKA_ID=01 で検索: {} 件（公開鍵と秘密鍵）", pair.len());

    // 8. 書く場所を間違える・書き忘れる（別のセッションで、セッションオブジェクトとして試す）
    let e = lib.open_rw_session(slot)?;
    let wrong = rv(e.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &session_only(pub_template(&[])),
        &session_only([priv_template(), rsa_strength.to_vec()].concat()),
    ));
    assert_eq!(
        wrong,
        Some(RvError::TemplateIncomplete),
        "公開鍵側に鍵長がない"
    );
    let both = rv(e.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &session_only(pub_template(&rsa_strength)),
        &session_only([priv_template(), vec![Attribute::ModulusBits(2048.into())]].concat()),
    ));
    assert_eq!(
        both,
        Some(RvError::AttributeTypeInvalid),
        "秘密鍵は MODULUS_BITS を持たない"
    );
    let missing = rv(e.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &session_only(pub_template(&[])),
        &session_only(priv_template()),
    ));
    assert_eq!(
        missing,
        Some(RvError::TemplateIncomplete),
        "EC は曲線が必須"
    );
    println!("書き忘れ → CKR_TEMPLATE_INCOMPLETE、秘密鍵側に鍵長 → CKR_ATTRIBUTE_TYPE_INVALID");
    e.close()?; // 作りかけが残っていても、ここで消える

    // 9. EC：強さの書き方だけが違う（曲線の OID を公開鍵側に）
    let (ec_pub, ec_priv) = s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &pub_template(&[Attribute::EcParams(P256.to_vec())]),
        &priv_template(),
    )?;
    assert_eq!(
        read(&s, ec_priv, AttributeType::KeyType)?,
        Attribute::KeyType(KeyType::EC)
    );
    assert_eq!(
        read(&s, ec_priv, AttributeType::EcParams)?,
        Attribute::EcParams(P256.to_vec())
    );
    match read(&s, ec_pub, AttributeType::EcPoint)? {
        Attribute::EcPoint(q) => println!("EC: 公開点 Q {} バイト", q.len()),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        info(&s, ec_priv, AttributeType::Value)?,
        AttributeInfo::Sensitive
    ));

    for h in [rsa_pub, rsa_priv, ec_pub, ec_priv] {
        s.destroy_object(h)?; // C_DestroyObject
    }
    assert_eq!(s.find_objects(&[Attribute::Id(ID.to_vec())])?.len(), 0);
    assert_eq!(
        s.find_objects(&keys)?.len(),
        before,
        "トークンに何も残していない"
    );
    s.logout()?;
    s.close()?;
    lib.finalize()?;
    println!("OK: 第2章の記述どおりに動いた");
    Ok(())
}
