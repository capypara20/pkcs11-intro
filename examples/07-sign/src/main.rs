//! 第7章 署名と検証：Init → 本体の2段階、メカニズムと鍵の組み合わせ、検証の失敗、
//! 分けて渡す署名、1セッション1操作、共通鍵での MAC、鍵を使わないハッシュと乱数を確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 鍵はすべてセッションオブジェクト（CKA_TOKEN=FALSE）なので、トークンには何も残らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// P-256 の OID（1.2.840.10045.3.1.7）を DER にしたもの
const P256: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const DATA: &[u8] = b"hello hsm";
const TAMPERED: &[u8] = b"hello hsn"; // 最後の1バイトだけ違う

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

/// 署名用の鍵ペア（第4章と同じ形）。sign=false なら秘密鍵に CKA_SIGN を付けない
fn key_pair(s: &Session, ec: bool, sign: bool) -> Result<(ObjectHandle, ObjectHandle)> {
    let (mech, strength) = if ec {
        (
            Mechanism::EccKeyPairGen,
            vec![Attribute::EcParams(P256.to_vec())],
        )
    } else {
        (
            Mechanism::RsaPkcsKeyPairGen,
            vec![
                Attribute::ModulusBits(2048.into()),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            ],
        )
    };
    let pub_t = [
        vec![Attribute::Token(false), Attribute::Verify(true)],
        strength,
    ]
    .concat();
    let priv_t = [
        Attribute::Token(false),
        Attribute::Sign(sign),
        Attribute::Sensitive(true),
    ];
    Ok(s.generate_key_pair(&mech, &pub_t, &priv_t)?)
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    let lib = Pkcs11::new(module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;

    let (rsa_pub, rsa_priv) = key_pair(&s, false, true)?;
    let (ec_pub, ec_priv) = key_pair(&s, true, true)?;

    // 1. 署名は C_SignInit（メカニズムと鍵）→ C_Sign（データ）の2段階。cryptoki の sign は両方を呼ぶ
    let rsa_sig = s.sign(&Mechanism::Sha256RsaPkcs, rsa_priv, DATA)?;
    assert_eq!(rsa_sig.len(), 256, "RSA 2048 の署名は 256 バイト");
    println!("RSA（CKM_SHA256_RSA_PKCS）: 署名 {} バイト", rsa_sig.len());

    // 2. 使えるメカニズムはトークン次第。ないメカニズムを使うと CKR_MECHANISM_INVALID
    let mechs = lib.get_mechanism_list(slot)?; // C_GetMechanismList
    assert!(mechs.contains(&MechanismType::SHA256_RSA_PKCS));
    assert!(mechs.contains(&MechanismType::ECDSA));
    if !mechs.contains(&MechanismType::ECDSA_SHA256) {
        assert_eq!(
            rv(s.sign(&Mechanism::EcdsaSha256, ec_priv, DATA)),
            Some(RvError::MechanismInvalid)
        );
        println!("CKM_ECDSA_SHA256 はこのトークンにない → CKR_MECHANISM_INVALID");
    }

    // 3. ハッシュを含まない CKM_ECDSA には、先にハッシュした値を渡す（ハッシュもトークンで C_Digest）
    let hash = s.digest(&Mechanism::Sha256, DATA)?; // C_DigestInit / C_Digest
    assert_eq!(hash.len(), 32);
    let ec_sig = s.sign(&Mechanism::Ecdsa, ec_priv, &hash)?;
    assert_eq!(
        ec_sig.len(),
        64,
        "P-256 の ECDSA 署名は r と s を並べた 64 バイト（DER ではない）"
    );
    println!(
        "ECDSA（CKM_ECDSA）: SHA-256 の値 32 バイトに署名 → {} バイト",
        ec_sig.len()
    );

    // 4. 鍵とメカニズムが合わない・用途がない
    let mismatch = rv(s.sign(&Mechanism::Ecdsa, rsa_priv, &hash));
    // 仕様では CKR_KEY_TYPE_INCONSISTENT。返すエラーはトークン次第なので、失敗したことだけを確かめる
    assert!(mismatch.is_some());
    let (_, no_sign) = key_pair(&s, false, false)?;
    assert_eq!(
        rv(s.sign(&Mechanism::Sha256RsaPkcs, no_sign, DATA)),
        Some(RvError::KeyFunctionNotPermitted)
    );
    assert_eq!(
        rv(s.sign(&Mechanism::Sha256RsaPkcs, rsa_pub, DATA)),
        Some(RvError::KeyFunctionNotPermitted),
        "公開鍵（CKA_SIGN を持たない）では署名できない"
    );
    println!("RSA 鍵で ECDSA → {mismatch:?}、CKA_SIGN のない鍵 → CKR_KEY_FUNCTION_NOT_PERMITTED");

    // 5. 検証は公開鍵で。データが1バイト違えば CKR_SIGNATURE_INVALID、長さが違えば CKR_SIGNATURE_LEN_RANGE
    s.verify(&Mechanism::Sha256RsaPkcs, rsa_pub, DATA, &rsa_sig)?; // C_VerifyInit / C_Verify
    s.verify(&Mechanism::Ecdsa, ec_pub, &hash, &ec_sig)?;
    assert_eq!(
        rv(s.verify(&Mechanism::Sha256RsaPkcs, rsa_pub, TAMPERED, &rsa_sig)),
        Some(RvError::SignatureInvalid)
    );
    assert_eq!(
        rv(s.verify(&Mechanism::Sha256RsaPkcs, rsa_pub, DATA, &rsa_sig[..255])),
        Some(RvError::SignatureLenRange)
    );
    println!("検証: 正しい → OK、1バイト改ざん → CKR_SIGNATURE_INVALID、短い署名 → CKR_SIGNATURE_LEN_RANGE");

    // 6. 長いデータは分けて渡せる（C_SignUpdate × n → C_SignFinal）。結果は一度に渡したときと同じ
    s.sign_init(&Mechanism::Sha256RsaPkcs, rsa_priv)?;
    // 7. 1つのセッションで進められる署名は1つだけ。別のセッションなら並行して署名できる
    assert_eq!(
        rv(s.sign_init(&Mechanism::Sha256RsaPkcs, rsa_priv)),
        Some(RvError::OperationActive)
    );
    let other = lib.open_rw_session(slot)?;
    assert_eq!(
        other.sign(&Mechanism::Sha256RsaPkcs, rsa_priv, DATA)?,
        rsa_sig
    );
    other.close()?;
    s.sign_update(b"hello ")?;
    s.sign_update(b"hsm")?;
    let parts_sig = s.sign_final()?;
    assert_eq!(parts_sig, rsa_sig);
    println!("分けて署名した結果 = 一度に署名した結果。途中の C_SignInit は CKR_OPERATION_ACTIVE");

    // 8. RSA PKCS#1 v1.5 は毎回同じ署名、ECDSA は毎回違う署名（どちらも検証は通る）
    assert_eq!(s.sign(&Mechanism::Sha256RsaPkcs, rsa_priv, DATA)?, rsa_sig);
    let ec_sig2 = s.sign(&Mechanism::Ecdsa, ec_priv, &hash)?;
    assert_ne!(ec_sig2, ec_sig);
    s.verify(&Mechanism::Ecdsa, ec_pub, &hash, &ec_sig2)?;
    println!("ECDSA は署名のたびに値が変わるが、どれも検証が通る");

    // 9. 共通鍵での「署名」は MAC。鍵は C_GenerateKey（汎用の共通鍵）で作り、同じ鍵で検証する
    let mac_key = s.generate_key(
        &Mechanism::GenericSecretKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Sign(true),
            Attribute::Verify(true),
            Attribute::Sensitive(true),
        ],
    )?; // C_GenerateKey(CKM_GENERIC_SECRET_KEY_GEN)
    let mac = s.sign(&Mechanism::Sha256Hmac, mac_key, DATA)?;
    assert_eq!(mac.len(), 32);
    s.verify(&Mechanism::Sha256Hmac, mac_key, DATA, &mac)?;
    assert_eq!(
        rv(s.verify(&Mechanism::Sha256Hmac, mac_key, TAMPERED, &mac)),
        Some(RvError::SignatureInvalid)
    );
    println!(
        "HMAC（CKM_SHA256_HMAC）: {} バイト。同じ共通鍵で検証する",
        mac.len()
    );

    // 10. MAC は同じデータなら毎回同じ値。鍵を持つ人なら誰でも作れる
    assert_eq!(s.sign(&Mechanism::Sha256Hmac, mac_key, DATA)?, mac);
    // 分けて渡すのも、署名と同じ形（C_SignUpdate / C_SignFinal、C_VerifyUpdate / C_VerifyFinal）
    s.sign_init(&Mechanism::Sha256Hmac, mac_key)?;
    s.sign_update(b"hello ")?;
    s.sign_update(b"hsm")?;
    assert_eq!(s.sign_final()?, mac);
    s.verify_init(&Mechanism::Sha256Hmac, mac_key)?;
    s.verify_update(b"hello ")?;
    s.verify_update(b"hsm")?;
    s.verify_final(&mac)?;
    s.verify_init(&Mechanism::Sha256RsaPkcs, rsa_pub)?;
    s.verify_update(b"hello ")?;
    s.verify_update(b"hsm")?;
    s.verify_final(&rsa_sig)?;
    println!("HMAC は毎回同じ値。MAC も検証も分けて渡せる");

    // 11. ハッシュは鍵を使わない：C_DigestInit → C_Digest。標準の SHA-256 と同じ値になる
    let h = s.digest(&Mechanism::Sha256, DATA)?;
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "a26275f66cab7104b8af28e676d6d1dbff44dbb8b6ba3c595123c63e0d1a6005"
    );
    s.digest_init(&Mechanism::Sha256)?; // 分けて渡しても同じ
    s.digest_update(b"hello ")?;
    s.digest_update(b"hsm")?;
    assert_eq!(s.digest_final()?, h);
    println!("SHA-256: {hex}");

    // 12. 乱数：C_GenerateRandom は長さだけを渡す。C_SeedRandom に対応するかはトークン次第
    let r1 = s.generate_random_vec(32)?;
    let r2 = s.generate_random_vec(32)?;
    assert_eq!(r1.len(), 32);
    assert_ne!(r1, r2, "呼ぶたびに違う値");
    match s.seed_random(&[0x01, 0x02, 0x03, 0x04]) {
        Ok(()) | Err(Error::Pkcs11(RvError::RandomSeedNotSupported, _)) => {}
        Err(e) => return Err(e.into()),
    }
    println!("乱数: 32 バイト・毎回違う");

    s.logout()?;
    s.close()?; // セッションオブジェクトの鍵はここで消える
    lib.finalize()?;
    println!("OK: 第7章の記述どおりに動いた");
    Ok(())
}
