//! 第6章 初期化とセッション：3つの「初期化」（C_Initialize / C_InitToken / C_InitPIN）、
//! SO と User、PIN の変更、セッションの5つの状態、スレッドとセッションを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_TOKEN_LABEL … 見比べるための初期化済みトークンのラベル（既定: demo）
//!
//! この章だけは、空きスロットのトークンを初期化して練習用トークン「ch6」を作る
//! （2回目からは ch6 を初期化し直す）。demo トークンには触らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::{Limit, Slot};
use cryptoki::types::AuthPin;
use std::env;
use std::thread;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LABEL: &str = "ch6";
const SO_PIN: &str = "5678";
const USER_PIN: &str = "1111";
const NEW_PIN: &str = "2222";

fn pin(s: &str) -> AuthPin {
    AuthPin::new(s.to_string().into())
}

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

/// セッションの今の状態（C_GetSessionInfo）
fn state(s: &Session) -> Result<SessionState> {
    Ok(s.get_session_info()?.session_state())
}

/// 鍵を使う操作を試すための AES 鍵（セッションオブジェクト）
fn session_key(s: &Session) -> cryptoki::error::Result<cryptoki::object::ObjectHandle> {
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
    let demo_label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    // 2. C_Initialize はライブラリ（このプロセス）の初期化。複数のスレッドから呼ぶので OS のロックを許す
    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?; // C_Initialize

    // 3. ライブラリの情報は、セッションもログインもなしで読める
    let info = lib.get_library_info()?; // C_GetInfo
    let softhsm = info.manufacturer_id() == "SoftHSM";
    if softhsm {
        assert_eq!(info.cryptoki_version().to_string(), "2.40");
        assert_eq!(info.library_version().to_string(), "2.6");
    }
    println!(
        "C_GetInfo: Cryptoki {} / {} {}（{}）",
        info.cryptoki_version(),
        info.manufacturer_id(),
        info.library_version(),
        info.library_description()
    );

    // 4. スロットの一覧。SoftHSM2 は、未初期化のトークンを入れた空きスロットを1つ用意している
    let all = lib.get_all_slots()?; // C_GetSlotList(tokenPresent = FALSE)
    let with_token = lib.get_slots_with_token()?; // C_GetSlotList(tokenPresent = TRUE)
    let ready = lib.get_slots_with_initialized_token()?; // さらに CKF_TOKEN_INITIALIZED で絞る
    let mut empty = None;
    for &slot in &with_token {
        if !lib.get_token_info(slot)?.token_initialized() {
            empty = Some(slot);
        }
    }
    let empty = empty.ok_or("未初期化のトークンがない")?;
    if softhsm {
        assert_eq!(ready.len() + 1, with_token.len());
    }
    // 未初期化のトークンには、セッションを開けない
    assert_eq!(
        rv(lib.open_ro_session(empty)),
        Some(RvError::TokenNotRecognized)
    );
    println!(
        "スロット: すべて {} / トークンあり {} / 初期化済み {}。未初期化のトークンは CKR_TOKEN_NOT_RECOGNIZED",
        all.len(),
        with_token.len(),
        ready.len()
    );

    // 5. トークンの状態は C_GetTokenInfo のフラグで読む
    let demo = lib.get_token_info(find_slot(&lib, &demo_label)?)?; // C_GetTokenInfo
    assert!(demo.token_initialized() && demo.user_pin_initialized());
    assert!(demo.login_required() && demo.rng());
    let blank = lib.get_token_info(empty)?;
    assert!(!blank.token_initialized() && !blank.user_pin_initialized());
    if softhsm {
        assert_eq!((demo.min_pin_length(), demo.max_pin_length()), (4, 255));
        assert!(matches!(demo.max_session_count(), Limit::Infinite));
        assert_eq!(demo.session_count(), None); // CK_UNAVAILABLE_INFORMATION
    }
    println!(
        "{demo_label}: 初期化済み・User PIN あり・ログイン必要・乱数あり。PIN は {}〜{} 文字",
        demo.min_pin_length(),
        demo.max_pin_length()
    );

    // 6. C_InitToken はトークンの初期化。SO PIN とラベルを決め、中身はすべて消える
    //    1回目は空きスロットのトークンを、2回目からは前回作った ch6 を使う
    let (target, fresh) = match find_slot(&lib, LABEL) {
        Ok(slot) => (slot, false),
        Err(_) => (empty, true),
    };
    lib.init_token(target, &pin(SO_PIN), LABEL)?; // C_InitToken
    let t = lib.get_token_info(target)?;
    assert_eq!(t.label(), LABEL);
    assert!(t.token_initialized() && !t.user_pin_initialized());
    let s = lib.open_ro_session(target)?;
    // そのトークンのセッションが開いていると、初期化できない
    assert_eq!(
        rv(lib.init_token(target, &pin(SO_PIN), LABEL)),
        Some(RvError::SessionExists)
    );
    // User PIN はまだないので、User はログインできない
    assert_eq!(
        rv(s.login(UserType::User, Some(&pin(USER_PIN)))),
        Some(RvError::UserPinNotInitialized)
    );
    s.close()?;
    // 初期化済みのトークンを初期化し直すには、今の SO PIN が要る
    assert_eq!(
        rv(lib.init_token(target, &pin("0000"), LABEL)),
        Some(RvError::PinIncorrect)
    );
    println!("C_InitToken: {LABEL} を作った。User PIN はまだない → CKR_USER_PIN_NOT_INITIALIZED");

    // 7. SO がログインできるのは R/W セッションだけ
    let ro = lib.open_ro_session(target)?;
    let rw = lib.open_rw_session(target)?;
    assert_eq!(
        rv(rw.login(UserType::So, Some(&pin(SO_PIN)))),
        Some(RvError::SessionReadOnlyExists),
        "R/O セッションが1つでもあると SO はログインできない"
    );
    ro.close()?;
    rw.login(UserType::So, Some(&pin(SO_PIN)))?; // C_Login(CKU_SO)
    assert_eq!(state(&rw)?, SessionState::RwSecurityOfficer);
    assert_eq!(
        rv(lib.open_ro_session(target)),
        Some(RvError::SessionReadWriteSoExists),
        "SO がログイン中は R/O セッションを開けない"
    );
    println!("SO: R/O があるとログインできない。ログイン中は R/O を開けない");

    // 8. C_InitPIN は SO が User PIN を決める。SO は管理者で、鍵の利用者ではない
    assert_eq!(rv(rw.init_pin(&pin("12"))), Some(RvError::PinLenRange));
    rw.init_pin(&pin(USER_PIN))?; // C_InitPIN
    let t = lib.get_token_info(target)?;
    assert!(t.user_pin_initialized());
    if softhsm {
        assert!(
            !t.user_pin_to_be_changed(),
            "SoftHSM2 は初回の PIN 変更を求めない"
        );
    }
    let other = lib.open_rw_session(target)?;
    assert_eq!(state(&other)?, SessionState::RwSecurityOfficer); // ログインはトークン単位
    assert_eq!(
        rv(other.login(UserType::User, Some(&pin(USER_PIN)))),
        Some(RvError::UserAnotherAlreadyLoggedIn)
    );
    assert_eq!(
        rv(session_key(&rw)),
        Some(RvError::UserNotLoggedIn),
        "SO は非公開オブジェクト（秘密鍵の既定は CKA_PRIVATE=TRUE）を作れない"
    );
    other.close()?;
    rw.set_pin(&pin(SO_PIN), &pin(SO_PIN))?; // SO も自分の PIN は C_SetPIN で変える（ここでは同じ値に）
    rw.logout()?;
    assert_eq!(state(&rw)?, SessionState::RwPublic);
    println!("C_InitPIN: User PIN を設定。SO のままでは User としてログインも鍵の生成もできない");

    // 9. C_SetPIN はログイン中の本人が自分の PIN を変える（R/W セッションで）
    rw.login(UserType::User, Some(&pin(USER_PIN)))?;
    assert_eq!(
        rv(rw.init_pin(&pin(NEW_PIN))),
        Some(RvError::UserNotLoggedIn),
        "C_InitPIN は SO だけ"
    );
    let ro = lib.open_ro_session(target)?;
    assert_eq!(
        rv(ro.set_pin(&pin(USER_PIN), &pin(NEW_PIN))),
        Some(RvError::SessionReadOnly)
    );
    assert_eq!(
        rv(rw.set_pin(&pin("9999"), &pin(NEW_PIN))),
        Some(RvError::PinIncorrect)
    );
    rw.set_pin(&pin(USER_PIN), &pin(NEW_PIN))?; // C_SetPIN
    rw.logout()?;
    assert_eq!(
        rv(rw.login(UserType::User, Some(&pin(USER_PIN)))),
        Some(RvError::PinIncorrect),
        "古い PIN ではもう入れない"
    );
    println!("C_SetPIN: {USER_PIN} → {NEW_PIN}。R/O では CKR_SESSION_READ_ONLY");

    // 10. セッションの状態は R/O か R/W か × ログインの種類で決まる（5つ）
    assert_eq!(
        (state(&ro)?, state(&rw)?),
        (SessionState::RoPublic, SessionState::RwPublic)
    );
    rw.login(UserType::User, Some(&pin(NEW_PIN)))?;
    assert_eq!(
        (state(&ro)?, state(&rw)?),
        (SessionState::RoUser, SessionState::RwUser),
        "ログインは同じトークンのセッションすべてに効く"
    );
    let late = lib.open_ro_session(target)?;
    assert_eq!(
        state(&late)?,
        SessionState::RoUser,
        "あとから開いても User の状態で始まる"
    );
    late.close()?;
    println!("状態: RoPublic / RwPublic → login(User) → RoUser / RwUser（RwSecurityOfficer は 7 で確認）");

    // 11. R/O でも鍵は使える。できないのはトークンに残る変更（と SO のログイン）
    let mine = [Attribute::Label(b"ch6-key".to_vec())];
    let stored = rw.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true),    // トークンオブジェクト（R/W なので作れる）
            Attribute::Private(false), // ログインなしでも見えるようにする
            Attribute::ValueLen(16.into()),
            Attribute::Label(b"ch6-key".to_vec()),
        ],
    )?;
    assert_eq!(ro.find_objects(&mine)?, vec![stored]); // 検索は R/O でもできる
    assert_eq!(
        rv(ro.update_attributes(stored, &[Attribute::Label(b"x".to_vec())])),
        Some(RvError::SessionReadOnly)
    );
    assert_eq!(
        rv(ro.destroy_object(stored)),
        Some(RvError::SessionReadOnly)
    );
    let key = session_key(&ro)?; // セッションオブジェクトは R/O でも作れる
    let ct = ro.encrypt(&Mechanism::AesEcb, key, &[0u8; 16])?;
    assert_eq!(ct.len(), 16);
    assert_eq!(ro.generate_random_vec(16)?.len(), 16);
    assert_eq!(
        rv(ro.generate_key(
            &Mechanism::AesKeyGen,
            &[Attribute::Token(true), Attribute::ValueLen(16.into())]
        )),
        Some(RvError::SessionReadOnly)
    );
    println!("R/O: セッションの鍵の生成・暗号化・乱数・検索は OK。トークンオブジェクトの作成・変更・削除は CKR_SESSION_READ_ONLY");

    // 12. ログインは、そのトークンの最後のセッションを閉じるまで続く
    rw.close()?;
    assert_eq!(
        state(&ro)?,
        SessionState::RoUser,
        "1つ残っていればログインは続く"
    );
    ro.close()?;
    let s = lib.open_rw_session(target)?;
    assert_eq!(
        state(&s)?,
        SessionState::RwPublic,
        "全部閉じるとログアウトされる"
    );
    println!("最後のセッションを閉じるとログアウトされる");

    // 13. スレッドごとにセッションを開く。ログインはスレッドをまたいで共有される
    s.login(UserType::User, Some(&pin(NEW_PIN)))?;
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let lib = lib.clone(); // 同じライブラリを共有する（中身は Arc）
            thread::spawn(move || -> cryptoki::error::Result<(SessionState, usize)> {
                let t = lib.open_ro_session(target)?; // このスレッド専用のセッション
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
    let moved = lib.open_ro_session(target)?;
    let st = thread::spawn(move || moved.get_session_info().map(|i| i.session_state()))
        .join()
        .expect("スレッドが止まった")?;
    assert_eq!(st, SessionState::RoUser);
    session_is_not_sync();
    println!("3つのスレッドがそれぞれのセッションで乱数を取得。どれも RoUser で始まった");

    // 6（続き）初期化し直すと、中のオブジェクトも User PIN も消える
    s.logout()?;
    assert_eq!(s.find_objects(&mine)?.len(), 1); // 11 で作ったトークンオブジェクト
    s.close()?;
    lib.init_token(target, &pin(SO_PIN), LABEL)?;
    assert!(!lib.get_token_info(target)?.user_pin_initialized());
    let s = lib.open_ro_session(target)?;
    assert!(s.find_objects(&mine)?.is_empty());
    s.close()?;
    println!("初期化し直したら、トークンの鍵も User PIN も消えた");

    // 2（続き）C_Finalize のあとなら、もう一度 C_Initialize できる
    lib.finalize()?; // C_Finalize
    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    // 4（続き）SoftHSM2 は、初期化したトークンのスロット番号を次の起動で付け替える。番号ではなくラベルで探す
    let again = find_slot(&lib, LABEL)?;
    if softhsm && fresh {
        assert_ne!(again, target);
        println!(
            "スロット番号: 初期化の前 {:#x} → 次の起動 {:#x}",
            target.id(),
            again.id()
        );
    }
    lib.finalize()?;
    println!("OK: 第6章の記述どおりに動いた");
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
