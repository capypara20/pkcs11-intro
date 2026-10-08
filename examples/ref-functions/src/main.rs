//! 関数リファレンスの裏付け：各関数を呼んで、仕様で決まっていることを確かめる。
//! 使えるかがトークン次第の関数は、使えた場合と使えない場合のどちらも受け入れる。
//! 章のサンプルで使っていない関数（cryptoki に包みがないものを含む）を、ここでまとめて呼ぶ。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 作る鍵はすべてセッションオブジェクトなので、トークンには何も残らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use cryptoki_sys::*;
use std::env;
use std::ptr::null_mut;

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

fn one(s: &Session, class: ObjectClass) -> Result<ObjectHandle> {
    let found = s.find_objects(&[
        Attribute::Label(b"demo-key".to_vec()),
        Attribute::Class(class),
    ])?;
    found
        .first()
        .copied()
        .ok_or_else(|| "demo-key がない".into())
}

/// ECDH 用の鍵ペア（P-256）。公開点は 04 || X || Y の形で返す
fn ec_pair(s: &Session) -> Result<(ObjectHandle, Vec<u8>)> {
    let (pub_h, priv_h) = s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[Attribute::Token(false), Attribute::EcParams(P256.to_vec())],
        &[Attribute::Token(false), Attribute::Derive(true)],
    )?;
    let point = match s.get_attributes(pub_h, &[AttributeType::EcPoint])?.pop() {
        Some(Attribute::EcPoint(p)) => p[2..].to_vec(), // DER の OCTET STRING の中身
        _ => return Err("CKA_EC_POINT を読めない".into()),
    };
    Ok((priv_h, point))
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    // cryptoki に包みがない関数は、関数の表（C_GetFunctionList）から直接呼ぶ
    let raw = unsafe { cryptoki_sys::Pkcs11::new(&module)? };
    let mut list: *mut CK_FUNCTION_LIST = null_mut();
    assert_eq!(unsafe { raw.C_GetFunctionList(&mut list) }, CKR_OK);
    let f = unsafe { &*list };

    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;
    let h = s.handle();
    let rsa_priv = one(&s, ObjectClass::PRIVATE_KEY)?;
    let rsa_pub = one(&s, ObjectClass::PUBLIC_KEY)?;
    let aes = s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ],
    )?;
    let not_supported = CKR_FUNCTION_NOT_SUPPORTED;

    // B. スロット・トークン：C_GetSlotInfo と、イベント待ち（待たずに聞くと「なし」）
    let info = lib.get_slot_info(slot)?; // C_GetSlotInfo
    assert!(info.token_present());
    assert_eq!(lib.get_slot_event()?, None); // C_WaitForSlotEvent(CKF_DONT_BLOCK) → CKR_NO_EVENT
    println!("B: C_GetSlotInfo OK、C_WaitForSlotEvent（待たない）→ CKR_NO_EVENT");

    // C. セッション：操作の状態の保存・復元。使えるかはトークン次第
    let mut len: CK_ULONG = 0;
    let mut state = [0u8; 16];
    let (get, set) = unsafe {
        (
            f.C_GetOperationState.unwrap()(h, null_mut(), &mut len),
            f.C_SetOperationState.unwrap()(h, state.as_mut_ptr(), 16, 0, 0),
        )
    };
    assert!([CKR_OK, not_supported, CKR_STATE_UNSAVEABLE].contains(&get));
    assert_ne!(set, CKR_OK, "でたらめな状態は戻せない");
    println!(
        "C: C_GetOperationState → 0x{get:X}、C_SetOperationState（でたらめな状態）→ 0x{set:X}"
    );

    // D. オブジェクト：C_CopyObject。C_GetObjectSize は「不明」を返すこともある（トークン次第）
    let copy = s.copy_object(aes, &[Attribute::Label(b"copy".to_vec())])?; // C_CopyObject
    assert_eq!(
        s.find_objects(&[Attribute::Label(b"copy".to_vec())])?,
        vec![copy]
    );
    let mut size: CK_ULONG = 0;
    let rv = unsafe { f.C_GetObjectSize.unwrap()(h, rsa_pub.handle(), &mut size) };
    assert!([CKR_OK, not_supported].contains(&rv));
    let unknown = rv == CKR_OK && size == CK_UNAVAILABLE_INFORMATION;
    println!(
        "D: C_CopyObject OK、C_GetObjectSize → 0x{rv:X}（大きさ{}）",
        if unknown { "は不明" } else { "あり" }
    );

    // E. 分けて復号（C_DecryptUpdate / C_DecryptFinal）
    let iv = [0u8; 16];
    let data = [7u8; 32];
    let ct = s.encrypt(&Mechanism::AesCbc(iv), aes, &data)?;
    s.decrypt_init(&Mechanism::AesCbc(iv), aes)?;
    let mut pt = s.decrypt_update(&ct[..16])?;
    pt.extend(s.decrypt_update(&ct[16..])?);
    pt.extend(s.decrypt_final()?);
    assert_eq!(pt, data);
    println!("E: C_DecryptUpdate × 2 → C_DecryptFinal で元のデータ");

    // F. ハッシュ：分けて渡す・鍵を混ぜる（C_DigestKey は共通鍵だけ）
    s.digest_init(&Mechanism::Sha256)?;
    s.digest_update(b"hello ")?;
    s.digest_update(b"hsm")?;
    assert_eq!(
        s.digest_final()?,
        s.digest(&Mechanism::Sha256, b"hello hsm")?
    );
    s.digest_init(&Mechanism::Sha256)?;
    s.digest_key(aes)?; // C_DigestKey
    assert_eq!(s.digest_final()?.len(), 32);
    s.digest_init(&Mechanism::Sha256)?;
    let rv = unsafe { f.C_DigestKey.unwrap()(h, rsa_priv.handle()) };
    assert_ne!(rv, CKR_OK, "混ぜられるのは共通鍵の値だけ");
    // エラーのあとに操作が続いているかはトークン次第。続いていなければ C_DigestInit からやり直す
    let _ = s.digest_final();
    println!("F: C_DigestKey は AES 鍵 OK・RSA 秘密鍵 → 0x{rv:X}");

    // G. 署名から元データを取り出す方式（Recover）。メカニズムが CKF_SIGN_RECOVER を持つときだけ使える
    let rsa_info = lib.get_mechanism_info(slot, MechanismType::RSA_PKCS)?;
    let mut mech = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: null_mut(),
        ulParameterLen: 0,
    };
    let mut buf = [0u8; 512];
    let mut buf_len: CK_ULONG = 512;
    let mut msg = *b"hello";
    let init = unsafe { f.C_SignRecoverInit.unwrap()(h, &mut mech, rsa_priv.handle()) };
    if rsa_info.sign_recover() && init == CKR_OK {
        let mut out = [0u8; 512];
        let mut out_len: CK_ULONG = 512;
        unsafe {
            assert_eq!(
                f.C_SignRecover.unwrap()(h, msg.as_mut_ptr(), 5, buf.as_mut_ptr(), &mut buf_len),
                CKR_OK
            );
            assert_eq!(
                f.C_VerifyRecoverInit.unwrap()(h, &mut mech, rsa_pub.handle()),
                CKR_OK
            );
            assert_eq!(
                f.C_VerifyRecover.unwrap()(
                    h,
                    buf.as_mut_ptr(),
                    buf_len,
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                CKR_OK
            );
        }
        assert_eq!(
            &out[..out_len as usize],
            b"hello",
            "署名から元のデータが戻る"
        );
        println!("G: CKM_RSA_PKCS は CKF_SIGN_RECOVER あり。署名から元のデータが戻った");
    } else {
        assert_ne!(init, CKR_OK);
        println!(
            "G: CKM_RSA_PKCS で C_SignRecoverInit → 0x{init:X}（CKF_SIGN_RECOVER: {}）",
            rsa_info.sign_recover()
        );
    }

    // H. 鍵の導出：ECDH（CKM_ECDH1_DERIVE）。互いの公開点から同じ共通鍵ができる
    let (a_priv, a_point) = ec_pair(&s)?;
    let (b_priv, b_point) = ec_pair(&s)?;
    let shared = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Token(false),
        Attribute::Encrypt(true),
    ];
    let a_key = s.derive_key(
        &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &b_point)),
        a_priv,
        &shared,
    )?; // C_DeriveKey
    let b_key = s.derive_key(
        &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &a_point)),
        b_priv,
        &shared,
    )?;
    let block = [0u8; 16];
    assert_eq!(
        s.encrypt(&Mechanism::AesEcb, a_key, &block)?,
        s.encrypt(&Mechanism::AesEcb, b_key, &block)?,
        "両側で同じ鍵ができている"
    );
    println!("H: C_DeriveKey（ECDH）で、A と B が同じ AES 鍵を得た");

    // I. 乱数：種を足す（C_SeedRandom）。対応するかはトークン次第
    match s.seed_random(&[1, 2, 3, 4]) {
        Ok(()) => println!("I: C_SeedRandom OK"),
        Err(Error::Pkcs11(RvError::RandomSeedNotSupported, _)) => {
            println!("I: C_SeedRandom → CKR_RANDOM_SEED_NOT_SUPPORTED")
        }
        Err(e) => return Err(e.into()),
    }

    // J. 複合操作（2つの操作を同時に進める）。使えるかはトークン次第。何も始めていなければ成功しない
    unsafe {
        for (name, func) in [
            ("C_DigestEncryptUpdate", f.C_DigestEncryptUpdate.unwrap()),
            ("C_DecryptDigestUpdate", f.C_DecryptDigestUpdate.unwrap()),
            ("C_SignEncryptUpdate", f.C_SignEncryptUpdate.unwrap()),
            ("C_DecryptVerifyUpdate", f.C_DecryptVerifyUpdate.unwrap()),
        ] {
            buf_len = 512;
            let rv = func(h, msg.as_mut_ptr(), 5, buf.as_mut_ptr(), &mut buf_len);
            assert!(
                [not_supported, CKR_OPERATION_NOT_INITIALIZED].contains(&rv),
                "{name}: 0x{rv:X}"
            );
        }
    }
    println!("J: 複合操作 4 つ → 使えないか、操作を始めていない");

    // A. 旧式の並行処理の関数は、仕様どおり CKR_FUNCTION_NOT_PARALLEL を返すだけ
    unsafe {
        assert_eq!(f.C_GetFunctionStatus.unwrap()(h), CKR_FUNCTION_NOT_PARALLEL);
        assert_eq!(f.C_CancelFunction.unwrap()(h), CKR_FUNCTION_NOT_PARALLEL);
    }
    println!("A: C_GetFunctionStatus / C_CancelFunction → CKR_FUNCTION_NOT_PARALLEL");

    // C. スロットのセッションをまとめて閉じる（cryptoki に包みはない）
    let other = lib.open_ro_session(slot)?;
    let mut si: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(f.C_CloseAllSessions.unwrap()(slot.id()), CKR_OK);
        assert_eq!(
            f.C_GetSessionInfo.unwrap()(other.handle(), &mut si),
            CKR_SESSION_HANDLE_INVALID
        );
    }
    // 閉じたセッションを cryptoki が閉じ直さないよう、ここで手放す
    std::mem::forget(other);
    std::mem::forget(s);
    println!("C: C_CloseAllSessions OK（そのあとのハンドルは CKR_SESSION_HANDLE_INVALID）");

    lib.finalize()?;
    println!("OK: 関数リファレンスの記述どおりに動いた");
    Ok(())
}
