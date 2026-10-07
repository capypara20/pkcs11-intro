//! 第2章 アプリからつなぐ：つなぐトークンを選び（C_GetSlotList / C_GetTokenInfo）、
//! セッションを開き（C_OpenSession）、ログインし（C_Login）、セッションの状態と
//! R/O・R/W の違い、ログインが続く範囲、スレッドとセッションの関係を確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! トークンに作る鍵はこのサンプルの最後に消す。PIN には触らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;
use std::thread;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

fn state(s: &Session) -> Result<SessionState> {
    Ok(s.get_session_info()?.session_state())
}

/// ラベルでトークンを探す。スロット番号は実装や起動のたびに変わりうるので、番号は覚えない
fn find_slot(lib: &Pkcs11, label: &str) -> Result<Slot> {
    for slot in lib.get_slots_with_initialized_token()? {
        if lib.get_token_info(slot)?.label() == label {
            return Ok(slot);
        }
    }
    Err(format!("ラベル {label} のトークンが見つからない").into())
}

/// 鍵を使う操作を試すための AES 鍵（セッションオブジェクト）
fn session_key(s: &Session) -> cryptoki::error::Result<ObjectHandle> {
    s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(16.into()),
            Attribute::Encrypt(true),
        ],
    )
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());
    let pin = AuthPin::new(pin.into());

    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // 1. ログインなしで読める情報：ライブラリ・スロット・トークン
    let info = lib.get_library_info()?; // C_GetInfo
    let all = lib.get_all_slots()?; // C_GetSlotList(tokenPresent = FALSE)
    let with_token = lib.get_slots_with_token()?; // C_GetSlotList(tokenPresent = TRUE)
    assert!(with_token.len() <= all.len());
    println!(
        "C_GetInfo: Cryptoki {}、{}。スロット {} 個（トークンあり {}）",
        info.cryptoki_version(),
        info.manufacturer_id(),
        all.len(),
        with_token.len()
    );

    // 2. つなぐトークンを選ぶ：初期化済みのものからラベルで探す
    let slot = find_slot(&lib, &label)?;
    assert!(lib.get_slot_info(slot)?.token_present()); // C_GetSlotInfo

    // 3. トークンの状態をフラグで読む
    let t = lib.get_token_info(slot)?; // C_GetTokenInfo
    assert!(t.token_initialized() && t.user_pin_initialized() && t.login_required() && t.rng());
    assert!(t.min_pin_length() <= t.max_pin_length());
    println!(
        "{label}: 初期化済み・User PIN あり・ログインが必要。PIN は {}〜{} 文字",
        t.min_pin_length(),
        t.max_pin_length()
    );

    // 4. セッションを開く：R/O か R/W かを選ぶ。ログインする前は「ログインなし」の状態
    let rw = lib.open_rw_session(slot)?; // C_OpenSession(CKF_RW_SESSION | CKF_SERIAL_SESSION)
    let ro = lib.open_ro_session(slot)?; // C_OpenSession(CKF_SERIAL_SESSION)
    assert!(rw.get_session_info()?.read_write() && !ro.get_session_info()?.read_write());
    assert_eq!(
        (state(&ro)?, state(&rw)?),
        (SessionState::RoPublic, SessionState::RwPublic)
    );
    println!("C_OpenSession: R/W と R/O を1つずつ。どちらもログインなし");

    // 5. ログインはトークンに対して1回。同じトークンのセッションすべてに効く
    rw.login(UserType::User, Some(&pin))?; // C_Login
    assert_eq!(
        (state(&ro)?, state(&rw)?),
        (SessionState::RoUser, SessionState::RwUser)
    );
    assert_eq!(
        rv(ro.login(UserType::User, Some(&pin))),
        Some(RvError::UserAlreadyLoggedIn),
        "別のセッションからもう一度ログインする必要はない"
    );
    let late = lib.open_ro_session(slot)?;
    assert_eq!(
        state(&late)?,
        SessionState::RoUser,
        "あとから開いても User の状態で始まる"
    );
    late.close()?;
    println!("C_Login: R/W でログインすると R/O も RoUser に。あとから開いたセッションも RoUser");

    // 6. R/O でも鍵は使える。できないのは、トークンに残る変更
    let mine = [Attribute::Label(b"ch2-key".to_vec())];
    let stored = rw.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true), // トークンオブジェクト（R/W なので作れる）
            Attribute::ValueLen(16.into()),
            Attribute::Label(b"ch2-key".to_vec()),
        ],
    )?;
    assert_eq!(ro.find_objects(&mine)?, vec![stored]); // 検索は R/O でもできる
    let key = session_key(&ro)?; // セッションオブジェクトは R/O でも作れる
    assert_eq!(ro.encrypt(&Mechanism::AesEcb, key, &[0u8; 16])?.len(), 16);
    assert_eq!(ro.generate_random_vec(16)?.len(), 16);
    assert_eq!(
        rv(ro.generate_key(
            &Mechanism::AesKeyGen,
            &[Attribute::Token(true), Attribute::ValueLen(16.into())]
        )),
        Some(RvError::SessionReadOnly)
    );
    assert_eq!(
        rv(ro.update_attributes(stored, &[Attribute::Label(b"x".to_vec())])),
        Some(RvError::SessionReadOnly)
    );
    assert_eq!(
        rv(ro.destroy_object(stored)),
        Some(RvError::SessionReadOnly)
    );
    println!("R/O: 鍵の生成（セッション）・暗号化・乱数・検索は OK。トークンオブジェクトの作成・変更・削除は CKR_SESSION_READ_ONLY");

    // 7. ログインは、そのトークンの最後のセッションを閉じるまで続く
    rw.destroy_object(stored)?;
    rw.close()?;
    assert_eq!(
        state(&ro)?,
        SessionState::RoUser,
        "1つ残っていればログインは続く"
    );
    ro.close()?;
    let s = lib.open_rw_session(slot)?;
    assert_eq!(
        state(&s)?,
        SessionState::RwPublic,
        "全部閉じるとログアウトされる"
    );
    println!("最後のセッションを閉じるとログアウトされる");

    // 8. スレッドごとにセッションを開く。ログインはスレッドをまたいで共有される
    s.login(UserType::User, Some(&pin))?;
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let lib = lib.clone(); // 同じライブラリを共有する（中身は Arc）
            thread::spawn(move || -> cryptoki::error::Result<(SessionState, usize)> {
                let t = lib.open_ro_session(slot)?; // このスレッド専用のセッション
                let st = t.get_session_info()?.session_state();
                Ok((st, t.generate_random_vec(16)?.len()))
            })
        })
        .collect();
    for w in workers {
        assert_eq!(
            w.join().expect("スレッドが止まった")?,
            (SessionState::RoUser, 16)
        );
    }
    // セッションごと別のスレッドへ渡すこともできる（Send）。2つのスレッドから同時には使えない（Sync でない）
    let moved = lib.open_ro_session(slot)?;
    let st = thread::spawn(move || moved.get_session_info().map(|i| i.session_state()))
        .join()
        .expect("スレッドが止まった")?;
    assert_eq!(st, SessionState::RoUser);
    session_is_not_sync();
    println!("3つのスレッドがそれぞれのセッションで乱数を取得。どれも RoUser で始まった");

    // 9. 後片付け：C_Logout → C_CloseSession → C_Finalize
    let other = lib.open_ro_session(slot)?;
    s.logout()?; // C_Logout
    assert_eq!(
        (state(&s)?, state(&other)?),
        (SessionState::RwPublic, SessionState::RoPublic),
        "ログアウトは、このアプリのセッションすべてに効く"
    );
    other.close()?;
    s.close()?;
    lib.finalize()?;
    println!("OK: 第2章の記述どおりに動いた");
    Ok(())
}

/// Session が Sync（複数のスレッドから同時に使える型）なら、この関数はコンパイルできない
fn session_is_not_sync() {
    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    <Session as AmbiguousIfSync<_>>::check();
}
