//! メカニズムリファレンスの裏付け：トークンが C_GetMechanismInfo で答える用途が、ページの表（expected.rs）に
//! 書いた「仕様で使える関数」の中に収まっていること、鍵の長さの単位が表のとおりであることを確かめる。
//! あわせて表に書いた動作を少し動かす。トークンにないメカニズムは飛ばす。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）

mod expected;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::{Mechanism, MechanismType};
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

    // 2. C_GetMechanismInfo：トークンが答える用途は、表に書いた仕様の範囲に収まる
    let get_info = f.C_GetMechanismInfo.ok_or("C_GetMechanismInfo がない")?;
    // 用途の印（CKF_ENCRYPT 〜 CKF_DERIVE）。CKF_HW や EC の印は見ない
    const USES: u64 = 0xFFF00;
    let mut present = 0;
    for &(ty, name, spec, unit) in EXPECTED {
        if !actual.contains(&ty) {
            continue; // このトークンにはない
        }
        present += 1;
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
            info.flags & USES & !spec,
            0,
            "{name}: トークンの用途 0x{:X} が仕様の範囲 0x{spec:X} を超えた",
            info.flags & USES
        );
        match unit {
            "byte" => assert!(info.ulMaxKeySize <= 64, "{name}: バイトのはず"),
            "bit" => assert!(info.ulMaxKeySize >= 160, "{name}: ビットのはず"),
            _ => {}
        }
    }
    assert!(present > 0);
    println!(
        "C_GetMechanismList: {} 個。表の {} 個のうち {present} 個があり、用途はどれも仕様の範囲",
        actual.len(),
        EXPECTED.len()
    );

    // 3. cryptoki の get_mechanism_list は、知らない種類を落とす
    let known = lib.get_mechanism_list(slot)?.len();
    assert!(known <= actual.len());
    println!(
        "cryptoki の get_mechanism_list(): {known} 個（{} 個は落ちた）",
        actual.len() - known
    );

    // 4. 表に書いた動作：AES-192 の鍵、Ed25519 の署名（トークンにあれば）
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;
    if lib
        .get_mechanism_info(slot, MechanismType::AES_KEY_GEN)?
        .max_key_size()
        >= 24
    {
        let aes192 = s.generate_key(
            &Mechanism::AesKeyGen,
            &[Attribute::Token(false), Attribute::ValueLen(24.into())],
        )?;
        assert!(s
            .get_attributes(aes192, &[AttributeType::ValueLen])?
            .contains(&Attribute::ValueLen(24.into())));
        println!("AES-192（24 バイト）の鍵を作れた");
    }
    if actual.contains(&CKM_EC_EDWARDS_KEY_PAIR_GEN) {
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
        println!("Ed25519 で署名 {} バイト、検証 OK", sig.len());
    }

    s.logout()?;
    s.close()?;
    lib.finalize()?;
    println!("OK: メカニズムリファレンスの表どおりだった");
    Ok(())
}
