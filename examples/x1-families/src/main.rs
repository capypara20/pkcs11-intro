//! 解説1 楕円曲線と PQC：方式（土台の数学）ごとに、鍵の種類（CKK_*）と
//! 鍵生成・署名・鍵共有のメカニズムが分かれていることを確かめる。
//!
//! - 楕円曲線は曲線の形で鍵の種類が3つに分かれる（CKK_EC / CKK_EC_EDWARDS / CKK_EC_MONTGOMERY）
//! - Edwards の鍵は署名（CKM_EDDSA）、Weierstrass の鍵は ECDSA と ECDH（C_DeriveKey）
//! - ML-KEM は C_EncapsulateKey / C_DecapsulateKey、ML-DSA は C_Sign / C_Verify（v3.2）
//!
//! PQC と Montgomery は、トークンが対応しているときだけ動かす（SoftHSM2 2.6 は未対応）。
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 鍵はすべてセッションオブジェクト（CKA_TOKEN=FALSE）なので、トークンには何も残らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, KeyType, MlDsaParameterSetType, MlKemParameterSetType, ObjectClass,
    ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// 曲線の OID を DER にしたもの（CKA_EC_PARAMS に入れる）
const P256: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const ED25519: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70]; // 1.3.101.112
const X25519: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x6E]; // 1.3.101.110
const DATA: &[u8] = b"hello hsm";

fn find_slot(lib: &Pkcs11, label: &str) -> Result<Slot> {
    for slot in lib.get_slots_with_token()? {
        if lib.get_token_info(slot)?.label() == label {
            return Ok(slot);
        }
    }
    Err(format!("ラベル {label} のトークンが見つからない").into())
}

/// 失敗したときの戻り値（CKR_*）を取り出す
fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

fn key_type(s: &Session, h: ObjectHandle) -> Result<KeyType> {
    match s.get_attributes(h, &[AttributeType::KeyType])?.pop() {
        Some(Attribute::KeyType(k)) => Ok(k),
        _ => Err("CKA_KEY_TYPE を読めない".into()),
    }
}

/// 公開鍵の値（CKA_EC_POINT）。DER の OCTET STRING に包まれていれば中身だけにする
fn ec_point(s: &Session, h: ObjectHandle) -> Result<Vec<u8>> {
    match s.get_attributes(h, &[AttributeType::EcPoint])?.pop() {
        Some(Attribute::EcPoint(p))
            if p.len() > 2 && p[0] == 0x04 && p[1] as usize == p.len() - 2 =>
        {
            Ok(p[2..].to_vec())
        }
        Some(Attribute::EcPoint(p)) => Ok(p),
        _ => Err("CKA_EC_POINT を読めない".into()),
    }
}

/// 鍵共有で作る AES 鍵のテンプレート
fn aes_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Token(false),
        Attribute::Encrypt(true),
    ]
}

/// 2つの AES 鍵が同じ値かを、同じブロックを暗号化して比べる（鍵の値は外に出さない）
fn same_key(s: &Session, a: ObjectHandle, b: ObjectHandle) -> Result<bool> {
    let block = [0u8; 16];
    Ok(s.encrypt(&Mechanism::AesEcb, a, &block)? == s.encrypt(&Mechanism::AesEcb, b, &block)?)
}

/// ECDH（CKM_ECDH1_DERIVE）で A と B が同じ鍵を得られるか。curve は CKA_EC_PARAMS
fn ecdh(s: &Session, gen: &Mechanism, curve: &[u8]) -> Result<KeyType> {
    let pair = || {
        s.generate_key_pair(
            gen,
            &[Attribute::Token(false), Attribute::EcParams(curve.to_vec())],
            &[Attribute::Token(false), Attribute::Derive(true)],
        )
    };
    let (a_pub, a_priv) = pair()?;
    let (b_pub, b_priv) = pair()?;
    let (a_point, b_point) = (ec_point(s, a_pub)?, ec_point(s, b_pub)?);
    let a_key = s.derive_key(
        &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &b_point)),
        a_priv,
        &aes_template(),
    )?; // C_DeriveKey：自分の秘密鍵 ＋ 相手の公開鍵
    let b_key = s.derive_key(
        &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &a_point)),
        b_priv,
        &aes_template(),
    )?;
    assert!(same_key(s, a_key, b_key)?, "両側で同じ鍵ができている");
    key_type(s, a_priv)
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    let lib = Pkcs11::new(module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;
    let mechs = lib.get_mechanism_list(slot)?;
    let has = |m: MechanismType| mechs.contains(&m);

    // 1. 方式ごとの「鍵を作る」メカニズムが、このトークンにあるか（トークン次第）
    let families = [
        ("RSA", MechanismType::RSA_PKCS_KEY_PAIR_GEN),
        ("楕円曲線（Weierstrass）", MechanismType::ECC_KEY_PAIR_GEN),
        (
            "楕円曲線（Edwards）",
            MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
        ),
        (
            "楕円曲線（Montgomery）",
            MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN,
        ),
        ("ML-KEM", MechanismType::ML_KEM_KEY_PAIR_GEN),
        ("ML-DSA", MechanismType::ML_DSA_KEY_PAIR_GEN),
        ("SLH-DSA", MechanismType::SLH_DSA_KEY_PAIR_GEN),
    ];
    for (name, gen) in families {
        println!(
            "{name}：{gen} → {}",
            if has(gen) {
                "あり"
            } else {
                "なし（トークン次第）"
            }
        );
    }
    assert!(has(MechanismType::RSA_PKCS_KEY_PAIR_GEN) && has(MechanismType::ECC_KEY_PAIR_GEN));

    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;

    // 2. Weierstrass（P-256）：鍵の種類は CKK_EC。鍵共有は ECDH（C_DeriveKey）
    let kt = ecdh(&s, &Mechanism::EccKeyPairGen, &P256)?;
    assert_eq!(kt, KeyType::EC);
    println!("P-256：鍵の種類 {kt}、ECDH（C_DeriveKey）で A と B が同じ AES 鍵を得た");

    // 3. Edwards（Ed25519）：鍵の種類は CKK_EC_EDWARDS。署名は CKM_EDDSA で 64 バイト
    if has(MechanismType::ECC_EDWARDS_KEY_PAIR_GEN) && has(MechanismType::EDDSA) {
        let (ed_pub, ed_priv) = s.generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &[
                Attribute::Token(false),
                Attribute::EcParams(ED25519.to_vec()),
                Attribute::Verify(true),
            ],
            &[Attribute::Token(false), Attribute::Sign(true)],
        )?;
        assert_eq!(key_type(&s, ed_priv)?, KeyType::EC_EDWARDS);
        let eddsa = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
        let sig = s.sign(&eddsa, ed_priv, DATA)?;
        assert_eq!(sig.len(), 64);
        s.verify(&eddsa, ed_pub, DATA, &sig)?;
        // 同じ「楕円曲線」でも、Edwards の鍵で ECDSA はできない（返すエラーはトークン次第）
        let e = rv(s.sign(&Mechanism::Ecdsa, ed_priv, &[0u8; 32]));
        assert!(e.is_some(), "Edwards の鍵で CKM_ECDSA は断られる");
        println!(
            "Ed25519：鍵の種類 {}、EdDSA の署名 {} バイト、検証 OK。CKM_ECDSA は {:?}",
            KeyType::EC_EDWARDS,
            sig.len(),
            e.unwrap()
        );
    }

    // 4. Montgomery（X25519）：鍵の種類は CKK_EC_MONTGOMERY。鍵共有は同じ CKM_ECDH1_DERIVE
    if has(MechanismType::ECC_MONTGOMERY_KEY_PAIR_GEN) && has(MechanismType::ECDH1_DERIVE) {
        let kt = ecdh(&s, &Mechanism::EccMontgomeryKeyPairGen, &X25519)?;
        assert_eq!(kt, KeyType::EC_MONTGOMERY);
        println!("X25519：鍵の種類 {kt}、ECDH で A と B が同じ AES 鍵を得た");
    }

    // 5. ML-KEM：強さは公開鍵テンプレートの CKA_PARAMETER_SET。鍵共有は C_EncapsulateKey
    if has(MechanismType::ML_KEM_KEY_PAIR_GEN) && has(MechanismType::ML_KEM) {
        let (kem_pub, kem_priv) = s.generate_key_pair(
            &Mechanism::MlKemKeyPairGen,
            &[
                Attribute::Token(false),
                Attribute::ParameterSet(MlKemParameterSetType::ML_KEM_768.into()),
                Attribute::Encapsulate(true),
            ],
            &[Attribute::Token(false), Attribute::Decapsulate(true)],
        )?;
        assert_eq!(key_type(&s, kem_priv)?, KeyType::ML_KEM);
        // 送る側：相手の公開鍵だけで、共通鍵と暗号文ができる
        let (ct, a_key) = s.encapsulate_key(&Mechanism::MlKem, kem_pub, &aes_template())?;
        // 受け取る側：自分の秘密鍵と暗号文から、同じ共通鍵を取り出す
        let b_key = s.decapsulate_key(&Mechanism::MlKem, kem_priv, &aes_template(), &ct)?;
        assert!(same_key(&s, a_key, b_key)?, "両側で同じ鍵ができている");
        println!(
            "ML-KEM-768：暗号文 {} バイトを渡して、同じ AES 鍵を得た",
            ct.len()
        );
    }

    // 6. ML-DSA：署名の呼び方（C_SignInit → C_Sign）は ECDSA と同じ。変わるのはメカニズムと鍵
    if has(MechanismType::ML_DSA_KEY_PAIR_GEN) && has(MechanismType::ML_DSA) {
        let (dsa_pub, dsa_priv) = s.generate_key_pair(
            &Mechanism::MlDsaKeyPairGen,
            &[
                Attribute::Token(false),
                Attribute::ParameterSet(MlDsaParameterSetType::ML_DSA_65.into()),
                Attribute::Verify(true),
            ],
            &[Attribute::Token(false), Attribute::Sign(true)],
        )?;
        assert_eq!(key_type(&s, dsa_priv)?, KeyType::ML_DSA);
        let mech = Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None));
        let sig = s.sign(&mech, dsa_priv, DATA)?;
        s.verify(&mech, dsa_pub, DATA, &sig)?;
        println!("ML-DSA-65：署名 {} バイト、検証 OK", sig.len());
    }

    s.logout()?;
    s.close()?;
    lib.finalize()?;
    println!("OK: 方式ごとに鍵の種類とメカニズムが分かれていた");
    Ok(())
}
