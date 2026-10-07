//! メカニズムリファレンスの裏付け：SoftHSM2 の C_GetMechanismList / C_GetMechanismInfo が、
//! ページの表（expected.rs）と1行ずつ一致することを確かめる。あわせて表に書いた動作を少し動かす。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 別のトークンでは一覧も用途も違うので、このサンプルは SoftHSM2 2.6.1 専用。

mod expected;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use cryptoki_sys::*;
use expected::EXPECTED;
use std::collections::BTreeSet;
use std::env;
use std::ptr::null_mut;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Ed25519 の曲線（1.3.101.112）を DER にしたもの
const ED25519: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

fn find_slot(lib: &Pkcs11, label: &str) -> Result<Slot> {
    for slot in lib.get_slots_with_token()? {
        if lib.get_token_info(slot)?.label() == label {
            return Ok(slot);
        }
    }
    Err(format!("ラベル {label} のトークンが見つからない").into())
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    // cryptoki は知らない種類を一覧から落とすので、一覧と情報は関数の表から直接聞く
    let raw = unsafe { cryptoki_sys::Pkcs11::new(&module)? };
    let mut list: *mut CK_FUNCTION_LIST = null_mut();
    assert_eq!(unsafe { raw.C_GetFunctionList(&mut list) }, CKR_OK);
    let f = unsafe { &*list };

    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;

    // 1. C_GetMechanismList：件数を聞いてから受け取る（2回呼ぶ）
    let get_list = f.C_GetMechanismList.ok_or("C_GetMechanismList がない")?;
    let mut n: CK_ULONG = 0;
    assert_eq!(unsafe { get_list(slot.id(), null_mut(), &mut n) }, CKR_OK);
    let mut types = vec![0 as CK_MECHANISM_TYPE; n as usize];
    assert_eq!(
        unsafe { get_list(slot.id(), types.as_mut_ptr(), &mut n) },
        CKR_OK
    );
    let actual: BTreeSet<u64> = types.into_iter().collect();
    let table: BTreeSet<u64> = EXPECTED.iter().map(|r| r.0).collect();
    assert_eq!(actual, table, "一覧が表と違う");
    assert_eq!(actual.len(), 70);

    // 2. C_GetMechanismInfo：用途の印と鍵の長さが、表のとおり
    let get_info = f.C_GetMechanismInfo.ok_or("C_GetMechanismInfo がない")?;
    for &(ty, name, flags, min, max) in EXPECTED {
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        assert_eq!(
            unsafe { get_info(slot.id(), ty, &mut info) },
            CKR_OK,
            "{name}"
        );
        assert_eq!(
            (info.flags, info.ulMinKeySize, info.ulMaxKeySize),
            (flags, min, max),
            "{name}"
        );
    }
    println!(
        "C_GetMechanismList: {} 個。全行の用途と鍵の長さが表と一致",
        actual.len()
    );

    // 3. cryptoki の get_mechanism_list は、知らない種類を落とす
    let known = lib.get_mechanism_list(slot)?.len();
    assert_eq!(known, 40);
    println!("cryptoki の get_mechanism_list(): {known} 個（30 個は落ちる）");

    // 4. 表に書いた動作：AES-192 の鍵、Ed25519 の署名
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;
    let aes192 = s.generate_key(
        &Mechanism::AesKeyGen,
        &[Attribute::Token(false), Attribute::ValueLen(24.into())],
    )?;
    assert!(s
        .get_attributes(aes192, &[AttributeType::ValueLen])?
        .contains(&Attribute::ValueLen(24.into())));
    let (ed_pub, ed_priv) = s.generate_key_pair(
        &Mechanism::EccEdwardsKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::EcParams(ED25519.to_vec()),
            Attribute::Verify(true),
        ],
        &[Attribute::Token(false), Attribute::Sign(true)],
    )?;
    let eddsa = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
    let sig = s.sign(&eddsa, ed_priv, b"hello hsm")?;
    assert_eq!(sig.len(), 64);
    s.verify(&eddsa, ed_pub, b"hello hsm", &sig)?;
    println!(
        "AES-192 の鍵を作れた。Ed25519 で署名 {} バイト、検証 OK",
        sig.len()
    );

    s.logout()?;
    s.close()?;
    lib.finalize()?;
    println!("OK: メカニズムリファレンスの表どおりだった");
    Ok(())
}
