//! 第1章 初期化：ライブラリを読み込み（C_GetFunctionList）、使い始め（C_Initialize）、
//! トークンを用意し（C_InitToken / C_InitPIN）、PIN を変え（C_SetPIN）、使い終える（C_Finalize）までを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!
//! この章だけは、未初期化のトークンを初期化して練習用トークン「ch1」を作る
//! （2回目からは ch1 を初期化し直す）。demo トークンには触らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use cryptoki_sys::{CK_C_Initialize, CKR_OK, CK_FUNCTION_LIST};
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LABEL: &str = "ch1";
const SO_PIN: &str = "5678";
const USER_PIN: &str = "1111";
const NEW_PIN: &str = "2222";

fn pin(s: &str) -> AuthPin {
    AuthPin::new(s.to_string().into())
}

/// 失敗したときの戻り値（CKR_*）を取り出す
fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

fn state(s: &Session) -> Result<SessionState> {
    Ok(s.get_session_info()?.session_state())
}

/// 初期化する相手：前回作った ch1 か、まだ初期化されていないトークン
fn target(lib: &Pkcs11) -> Result<Slot> {
    let mut blank = None;
    for slot in lib.get_slots_with_token()? {
        let info = lib.get_token_info(slot)?;
        if info.label() == LABEL {
            return Ok(slot);
        }
        if !info.token_initialized() {
            blank = Some(slot);
        }
    }
    blank.ok_or_else(|| "初期化できるトークンがない".into())
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());

    // 2. ライブラリを読み込み、C_GetFunctionList で関数の表を受け取る（cryptoki の Pkcs11::new の中身）
    {
        let raw = unsafe { cryptoki_sys::Pkcs11::new(&module)? }; // dlopen
        let mut list: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
        assert_eq!(unsafe { raw.C_GetFunctionList(&mut list) }, CKR_OK);
        let table = unsafe { &*list };
        let count = (std::mem::size_of::<CK_FUNCTION_LIST>()
            - std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize))
            / std::mem::size_of::<CK_C_Initialize>();
        assert_eq!(count, 68, "v2.40 の関数の表には 68 個の関数が並ぶ");
        assert!(table.C_Initialize.is_some());
        println!(
            "C_GetFunctionList: 表の版 {}.{}、関数 {count} 個",
            table.version.major, table.version.minor
        );
    }
    let lib = Pkcs11::new(&module)?; // 同じことをして、表を中に持つ

    // 3. C_Initialize はライブラリ（このプロセス）の初期化。2回目はエラー
    let args = || CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
    lib.initialize(args())?; // C_Initialize
    assert_eq!(
        rv(lib.initialize(args())),
        Some(RvError::CryptokiAlreadyInitialized)
    );
    println!("C_Initialize: 2回目は CKR_CRYPTOKI_ALREADY_INITIALIZED");

    // 4. C_InitToken はトークンの初期化。SO PIN とラベルを決め、中身はすべて消える
    let slot = target(&lib)?;
    lib.init_token(slot, &pin(SO_PIN), LABEL)?; // C_InitToken
    let t = lib.get_token_info(slot)?;
    assert_eq!(t.label(), LABEL);
    assert!(t.token_initialized() && !t.user_pin_initialized());
    let s = lib.open_ro_session(slot)?;
    assert_eq!(
        rv(lib.init_token(slot, &pin(SO_PIN), LABEL)),
        Some(RvError::SessionExists),
        "そのトークンのセッションが開いていると初期化できない"
    );
    assert_eq!(
        rv(s.login(UserType::User, Some(&pin(USER_PIN)))),
        Some(RvError::UserPinNotInitialized),
        "User PIN はまだない"
    );
    s.close()?;
    assert_eq!(
        rv(lib.init_token(slot, &pin("0000"), LABEL)),
        Some(RvError::PinIncorrect),
        "初期化し直すには今の SO PIN が要る"
    );
    println!("C_InitToken: {LABEL} を作った。User PIN はまだない");

    // 5. SO がログインできるのは R/W セッションだけ
    let ro = lib.open_ro_session(slot)?;
    let rw = lib.open_rw_session(slot)?;
    assert_eq!(
        rv(rw.login(UserType::So, Some(&pin(SO_PIN)))),
        Some(RvError::SessionReadOnlyExists)
    );
    ro.close()?;
    rw.login(UserType::So, Some(&pin(SO_PIN)))?; // C_Login(CKU_SO)
    assert_eq!(state(&rw)?, SessionState::RwSecurityOfficer);
    assert_eq!(
        rv(lib.open_ro_session(slot)),
        Some(RvError::SessionReadWriteSoExists)
    );
    println!("SO: R/O があるとログインできない。ログイン中は R/O を開けない");

    // 6. C_InitPIN は SO が User PIN を決める。SO は管理者で、鍵の利用者ではない
    assert_eq!(rv(rw.init_pin(&pin("12"))), Some(RvError::PinLenRange));
    rw.init_pin(&pin(USER_PIN))?; // C_InitPIN
    assert!(lib.get_token_info(slot)?.user_pin_initialized());
    let other = lib.open_rw_session(slot)?;
    assert_eq!(
        rv(other.login(UserType::User, Some(&pin(USER_PIN)))),
        Some(RvError::UserAnotherAlreadyLoggedIn)
    );
    other.close()?;
    assert_eq!(
        rv(rw.generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::ValueLen(16.into())
            ]
        )),
        Some(RvError::UserNotLoggedIn),
        "SO は非公開の鍵を作れない"
    );
    rw.set_pin(&pin(SO_PIN), &pin(SO_PIN))?; // SO も自分の PIN は C_SetPIN で変える（ここでは同じ値に）
    rw.logout()?;
    println!("C_InitPIN: User PIN を決めた。SO のままでは User としてログインも非公開の鍵の生成もできない");

    // 7. C_SetPIN はログイン中の本人が自分の PIN を変える（R/W セッションで）
    rw.login(UserType::User, Some(&pin(USER_PIN)))?;
    assert_eq!(
        rv(rw.init_pin(&pin(NEW_PIN))),
        Some(RvError::UserNotLoggedIn),
        "C_InitPIN は SO だけ"
    );
    let ro = lib.open_ro_session(slot)?;
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

    // 8. 初期化し直すと、中のオブジェクトも User PIN も消える
    rw.login(UserType::User, Some(&pin(NEW_PIN)))?;
    let mine = [Attribute::Label(b"ch1-key".to_vec())];
    rw.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::ValueLen(16.into()),
            Attribute::Label(b"ch1-key".to_vec()),
        ],
    )?;
    assert_eq!(ro.find_objects(&mine)?.len(), 1);
    ro.close()?;
    rw.logout()?;
    rw.close()?;
    lib.init_token(slot, &pin(SO_PIN), LABEL)?;
    assert!(!lib.get_token_info(slot)?.user_pin_initialized());
    let s = lib.open_ro_session(slot)?;
    assert!(s.find_objects(&mine)?.is_empty());
    s.close()?;
    println!("初期化し直したら、トークンの鍵も User PIN も消えた");

    // 9. C_Finalize で使い終える。そのあとなら、もう一度 C_Initialize できる
    let same = lib.clone(); // 同じライブラリを指すもう1つの持ち手
    lib.finalize()?; // C_Finalize
    assert_eq!(
        rv(same.get_slots_with_token()),
        Some(RvError::CryptokiNotInitialized),
        "C_Finalize のあとは、どの関数も使えない"
    );
    let lib = Pkcs11::new(&module)?;
    lib.initialize(args())?;
    lib.finalize()?;
    println!("OK: 第1章の記述どおりに動いた");
    Ok(())
}
