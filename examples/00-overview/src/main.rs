//! 第0章 全体像：ログイン状態が同じトークンのセッション間で共有されることを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 章の記述と挙動がずれたら CI で気づけるよう、結果は表示するだけでなく assert で確かめる。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// セッションの状態と、そのセッションから見える秘密鍵の数を返す
fn observe(label: &str, s: &Session) -> Result<(SessionState, usize)> {
    let state = s.get_session_info()?.session_state(); // C_GetSessionInfo
    let private = [Attribute::Class(ObjectClass::PRIVATE_KEY)];
    let found = s.find_objects(&private)?.len(); // C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
    println!("{label}: 状態 {state:?}, 見える秘密鍵 {found} 件");
    Ok((state, found))
}

/// ラベルでトークンを探す。SoftHSM2 は未初期化の空きスロットも「トークンあり」で返すため、
/// 先頭のスロットを使うと別のトークンを掴むことがある
fn find_slot(lib: &Pkcs11, label: &str) -> Result<Slot> {
    // C_GetSlotList(tokenPresent = TRUE)
    for slot in lib.get_slots_with_token()? {
        // C_GetTokenInfo
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

    let lib = Pkcs11::new(module)?; // ライブラリのロード
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?; // C_Initialize

    let slot = find_slot(&lib, &label)?;
    println!("トークン: {label}");

    let a = lib.open_rw_session(slot)?; // C_OpenSession（R/W）
    let b = lib.open_ro_session(slot)?; // C_OpenSession（R/O）

    // 秘密鍵が隠れるのは CKA_PRIVATE=TRUE のとき。setup-softhsm.sh の pkcs11-tool はそう作る
    let before = observe("ログイン前 B", &b)?;
    assert_eq!(
        before,
        (SessionState::RoPublic, 0),
        "ログイン前は秘密鍵が見えないはず"
    );

    a.login(UserType::User, Some(&AuthPin::new(pin.into())))?; // C_Login（A だけで実行）
    let after = observe("A でログイン後 B", &b)?; // B もログイン済みになっている
    assert_eq!(
        after,
        (SessionState::RoUser, 1),
        "A のログインが B にも及ぶはず"
    );

    a.logout()?; // C_Logout
    b.close()?; // C_CloseSession
    a.close()?; // C_CloseSession
    lib.finalize()?; // C_Finalize（cryptoki は drop では呼ばないので明示する）
    println!("OK: ログイン状態はセッション間で共有された");
    Ok(())
}
