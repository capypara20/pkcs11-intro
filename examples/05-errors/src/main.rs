//! 第5章 エラーコード：どの段階でどの CKR_* が返るか、エラーのあと操作がどうなるか、
//! 仕様と実装（SoftHSM2）の違いを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! わざと1回だけ PIN を間違える。鍵はすべてセッションオブジェクトなので、トークンには何も残らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, Rv, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType};
use cryptoki::session::UserType;
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

/// 失敗したときの戻り値（CKR_*）を取り出す。成功なら None
fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    // 1. 戻り値はすべて CK_RV（数値）。0 が CKR_OK、それ以外が失敗。cryptoki は番号を名前に直す
    assert_eq!(Rv::from(0x0), Rv::Ok);
    assert_eq!(Rv::from(0xA0), Rv::Error(RvError::PinIncorrect));
    assert_eq!(Rv::from(0x101), Rv::Error(RvError::UserNotLoggedIn));
    assert_eq!(Rv::from(0x150), Rv::Error(RvError::BufferTooSmall));
    // 0x80000000 以上はベンダー独自のエラー
    assert_eq!(
        Rv::from(0x8000_0001),
        Rv::Error(RvError::VendorDefined(0x8000_0001))
    );
    println!("0x0 = CKR_OK、0xA0 = CKR_PIN_INCORRECT、0x80000001 = ベンダー独自");

    // 3. ライブラリ：初期化の前に呼ぶ・2回初期化する
    let lib = Pkcs11::new(module)?;
    assert_eq!(
        rv(lib.get_all_slots()),
        Some(RvError::CryptokiNotInitialized)
    );
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    assert_eq!(
        rv(lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))),
        Some(RvError::CryptokiAlreadyInitialized)
    );
    println!("C_Initialize 前 → CRYPTOKI_NOT_INITIALIZED、2回目 → CRYPTOKI_ALREADY_INITIALIZED");
    let slot = find_slot(&lib, &label)?;

    // 4. セッション：R/O セッションではトークンオブジェクトを作れない
    let ro = lib.open_ro_session(slot)?;
    let aes = |token: bool, private: bool| {
        vec![
            Attribute::Token(token),
            Attribute::Private(private),
            Attribute::ValueLen(32.into()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ]
    };
    assert_eq!(
        rv(ro.generate_key(&Mechanism::AesKeyGen, &aes(true, false))),
        Some(RvError::SessionReadOnly)
    );
    ro.generate_key(&Mechanism::AesKeyGen, &aes(false, false))?; // セッションオブジェクトなら作れる
    println!("R/O セッションでトークンオブジェクト → CKR_SESSION_READ_ONLY");

    // 5. ログイン：ログイン前の非公開オブジェクト・PIN の間違い・2回ログイン
    assert_eq!(
        rv(ro.generate_key(&Mechanism::AesKeyGen, &aes(false, true))),
        Some(RvError::UserNotLoggedIn)
    );
    assert_eq!(
        rv(ro.login(UserType::User, Some(&AuthPin::new("0000".into())))),
        Some(RvError::PinIncorrect)
    );
    // 間違えるとトークンの情報に「残り回数が少ない」の印が立つ
    assert!(lib.get_token_info(slot)?.user_pin_count_low());
    ro.login(UserType::User, Some(&AuthPin::new(pin.clone().into())))?;
    assert_eq!(
        rv(ro.login(UserType::User, Some(&AuthPin::new(pin.into())))),
        Some(RvError::UserAlreadyLoggedIn)
    );
    println!("ログイン前の非公開オブジェクト → USER_NOT_LOGGED_IN、PIN 間違い → PIN_INCORRECT、2回目 → USER_ALREADY_LOGGED_IN");

    let s = lib.open_rw_session(slot)?;
    let key = s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Sensitive(true),
        ],
    )?;

    // 6. テンプレート：書き忘れ・値の間違い・変えられない属性・読めない属性
    assert_eq!(
        rv(s.generate_key(&Mechanism::AesKeyGen, &[Attribute::Token(false)])),
        Some(RvError::TemplateIncomplete)
    );
    assert_eq!(
        rv(s.generate_key(
            &Mechanism::AesKeyGen,
            &[Attribute::Token(false), Attribute::ValueLen(20.into())]
        )),
        Some(RvError::AttributeValueInvalid)
    );
    assert_eq!(
        rv(s.update_attributes(key, &[Attribute::Sensitive(false)])),
        Some(RvError::AttributeReadOnly)
    );
    assert!(s.get_attributes(key, &[AttributeType::Value])?.is_empty()); // 読めない属性は返らない
    println!("テンプレート → TEMPLATE_INCOMPLETE / ATTRIBUTE_VALUE_INVALID / ATTRIBUTE_READ_ONLY");

    // 7・8. 操作の開始とデータ
    let (pub_h, priv_h) = s.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Verify(true),
        ],
        &[Attribute::Token(false), Attribute::Sign(true)],
    )?;
    assert_eq!(
        rv(s.sign(&Mechanism::EcdsaSha256, priv_h, b"x")),
        Some(RvError::MechanismInvalid)
    );
    assert_eq!(
        rv(s.sign(&Mechanism::Sha256RsaPkcs, pub_h, b"x")),
        Some(RvError::KeyFunctionNotPermitted)
    );
    let iv = [0u8; 16];
    assert_eq!(
        rv(s.encrypt(&Mechanism::AesCbc(iv), key, b"hello hsm")),
        Some(RvError::DataLenRange)
    );
    let sig = s.sign(&Mechanism::Sha256RsaPkcs, priv_h, b"hello")?;
    assert_eq!(
        rv(s.verify(&Mechanism::Sha256RsaPkcs, pub_h, b"hellx", &sig)),
        Some(RvError::SignatureInvalid)
    );
    println!("開始 → MECHANISM_INVALID / KEY_FUNCTION_NOT_PERMITTED、データ → DATA_LEN_RANGE / SIGNATURE_INVALID");

    // 9. エラーのあと、その操作は終わっている。続きを呼ぶと CKR_OPERATION_NOT_INITIALIZED
    s.encrypt_init(&Mechanism::AesCbc(iv), key)?;
    assert_eq!(s.encrypt_update(b"hello hsm")?.len(), 0); // 途中はためるだけ
    assert_eq!(rv(s.encrypt_final()), Some(RvError::DataLenRange));
    assert_eq!(
        rv(s.encrypt_update(&[0u8; 16])),
        Some(RvError::OperationNotInitialized)
    );
    s.verify_init(&Mechanism::Sha256RsaPkcs, pub_h)?;
    s.verify_update(b"hellx")?;
    assert_eq!(rv(s.verify_final(&sig)), Some(RvError::SignatureInvalid));
    assert_eq!(
        rv(s.verify_update(b"x")),
        Some(RvError::OperationNotInitialized)
    );
    assert_eq!(
        rv(s.sign_init(&Mechanism::Sha256RsaPkcs, pub_h)),
        Some(RvError::KeyFunctionNotPermitted)
    );
    assert_eq!(
        rv(s.sign_update(b"x")),
        Some(RvError::OperationNotInitialized)
    );
    s.encrypt_init(&Mechanism::AesCbc(iv), key)?; // もう一度 Init から始めれば使える
    s.encrypt_final()?;
    println!("エラーのあと続きを呼ぶ → OPERATION_NOT_INITIALIZED（Init からやり直す）");

    // 10. 仕様どおりとは限らない（SoftHSM2 2.6.1）
    // 仕様では CKR_KEY_TYPE_INCONSISTENT
    assert_eq!(
        rv(s.sign(&Mechanism::Ecdsa, priv_h, &[0u8; 32])),
        Some(RvError::GeneralError)
    );
    // 仕様では CKR_USER_NOT_LOGGED_IN
    let fresh = lib.open_ro_session(slot)?;
    ro.logout()?;
    assert!(fresh.logout().is_ok());
    println!("RSA 鍵で ECDSA → GENERAL_ERROR、ログインしていないのに C_Logout → CKR_OK（どちらも仕様と違う）");

    // 1. エラーには失敗した関数の名前も付いている
    let e = s.sign(&Mechanism::Sha256RsaPkcs, pub_h, b"x").unwrap_err();
    assert!(matches!(
        e,
        Error::Pkcs11(RvError::KeyFunctionNotPermitted, _)
    ));
    assert!(e.to_string().starts_with("Function::SignInit"));
    println!(
        "エラーの表示: {}",
        e.to_string()
            .split(':')
            .take(3)
            .collect::<Vec<_>>()
            .join(":")
    );

    s.close()?;
    fresh.close()?;
    ro.close()?;
    lib.finalize()?;
    println!("OK: 第5章の記述どおりに動いた");
    Ok(())
}
