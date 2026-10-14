//! シナリオ3「包んだ鍵を外に置く」：業務で使う鍵（データ鍵）を、HSM の中の KEK で包んで DB に置き、
//! 使うときだけ HSM の中でほどく。鍵の値はアプリにも DB にも平文では出ない。
//! KEK には CKA_UNWRAP_TEMPLATE を付け、ほどいた鍵の属性を KEK の側で決めておく。
//! 各手順の主張を assert で確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!
//! 空きスロットに練習用トークン「keystore」を作る（2回目からは初期化し直す）。demo トークンには触らない。
//! cryptoki には CKA_UNWRAP_TEMPLATE（属性の配列を値に持つ属性）の包みがないので、
//! KEK を作るところだけ関数の表（C_GetFunctionList）から C_GenerateKey を直接呼ぶ。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use cryptoki_sys::*;
use std::env;
use std::ffi::c_void;
use std::ptr::null_mut;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const TOKEN: &str = "keystore";
const SO_PIN: &str = "5678";
const USER_PIN: &str = "1111";
const KEK_LABEL: &str = "app-kek";
const AAD: &[u8] = b"orders";

fn pin(s: &str) -> AuthPin {
    AuthPin::new(s.to_string().into())
}

fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

/// 練習用トークンを用意する（前回のものがあれば初期化し直す）
fn prepare(lib: &Pkcs11) -> Result<Slot> {
    let mut found = None;
    let mut free = None;
    for slot in lib.get_slots_with_token()? {
        let info = lib.get_token_info(slot)?;
        if info.label() == TOKEN {
            found = Some(slot);
        } else if !info.token_initialized() {
            free = Some(slot);
        }
    }
    let slot = found.or(free).ok_or("空きスロットがない")?;
    lib.init_token(slot, &pin(SO_PIN), TOKEN)?; // C_InitToken
    let so = lib.open_rw_session(slot)?;
    so.login(UserType::So, Some(&pin(SO_PIN)))?;
    so.init_pin(&pin(USER_PIN))?; // C_InitPIN
    so.logout()?;
    so.close()?;
    Ok(slot)
}

/// CK_ATTRIBUTE を1つ作る（値はポインタで渡すので、呼び出しが終わるまで生かしておく）
fn raw_attr<T>(t: CK_ATTRIBUTE_TYPE, v: &T) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: v as *const T as *mut c_void,
        ulValueLen: std::mem::size_of::<T>() as CK_ULONG,
    }
}

/// KEK を作る（一度だけ）。トークンに残し、値は外に出さない。包む・ほどくだけに使う。
/// CKA_UNWRAP_TEMPLATE で「この KEK でほどいた鍵は SENSITIVE = TRUE・EXTRACTABLE = FALSE」と決めておく。
/// CKA_MODIFIABLE = FALSE で、作ったあとは属性（テンプレートも）を書き換えられないようにする。
fn create_kek(f: &CK_FUNCTION_LIST, session: CK_SESSION_HANDLE) -> Result<()> {
    let (t, fl): (CK_BBOOL, CK_BBOOL) = (CK_TRUE, CK_FALSE);
    let len: CK_ULONG = 32;
    let label = KEK_LABEL.as_bytes();
    // ほどいた鍵に当てる属性（属性の配列が、そのまま1つの属性の値になる）
    let unwrap_template = [raw_attr(CKA_SENSITIVE, &t), raw_attr(CKA_EXTRACTABLE, &fl)];
    let mut template = [
        raw_attr(CKA_TOKEN, &t),
        raw_attr(CKA_PRIVATE, &t),
        raw_attr(CKA_VALUE_LEN, &len),
        raw_attr(CKA_WRAP, &t),
        raw_attr(CKA_UNWRAP, &t),
        raw_attr(CKA_ENCRYPT, &fl),
        raw_attr(CKA_DECRYPT, &fl),
        raw_attr(CKA_SENSITIVE, &t),
        raw_attr(CKA_EXTRACTABLE, &fl),
        raw_attr(CKA_MODIFIABLE, &fl),
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label.as_ptr() as *mut c_void,
            ulValueLen: label.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_UNWRAP_TEMPLATE,
            pValue: unwrap_template.as_ptr() as *mut c_void,
            ulValueLen: std::mem::size_of_val(&unwrap_template) as CK_ULONG,
        },
    ];
    let mut mech = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: null_mut(),
        ulParameterLen: 0,
    };
    let mut kek: CK_OBJECT_HANDLE = 0;
    let generate = f.C_GenerateKey.ok_or("C_GenerateKey がない")?;
    let r = unsafe {
        generate(
            session,
            &mut mech,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut kek,
        )
    }; // C_GenerateKey
    if r != CKR_OK {
        return Err(format!("C_GenerateKey が 0x{r:x} を返した").into());
    }
    Ok(())
}

/// KEK はラベルで探す。ハンドルはセッションごとの番号なので、保存しても使えない
fn find_kek(s: &Session) -> Result<ObjectHandle> {
    let found = s.find_objects(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(KEK_LABEL.as_bytes().to_vec()),
    ])?; // C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
    match found.as_slice() {
        [h] => Ok(*h),
        _ => Err(format!("{KEK_LABEL} が 1 件でない: {} 件", found.len()).into()),
    }
}

/// DB の1行：包んだ鍵と、ほどくのに要ること。鍵の値（平文）は持たない
struct Row {
    kek_label: String,       // どの KEK で包んだか
    mechanism: &'static str, // 包んだメカニズム
    key_type: &'static str,  // ほどくときのテンプレートに書く鍵の種類と長さ
    wrapped: Vec<u8>,        // 包んだ鍵（40 バイト）
    iv: Vec<u8>,
    ct: Vec<u8>, // その鍵で暗号化したデータ
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let raw = unsafe { cryptoki_sys::Pkcs11::new(&module)? };
    let mut list: *mut CK_FUNCTION_LIST = null_mut();
    assert_eq!(unsafe { raw.C_GetFunctionList(&mut list) }, CKR_OK);
    let f = unsafe { &*list };

    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?; // C_Initialize
    let slot = prepare(&lib)?;

    // 1. KEK を作る（一度だけ）。トークンオブジェクトなので、セッションを閉じても残る
    {
        let s = lib.open_rw_session(slot)?;
        s.login(UserType::User, Some(&pin(USER_PIN)))?;
        create_kek(f, s.handle())?;
        let kek = find_kek(&s)?;
        let got = s.get_attributes(
            kek,
            &[
                AttributeType::Token,
                AttributeType::Wrap,
                AttributeType::Modifiable,
            ],
        )?;
        assert_eq!(
            got,
            vec![
                Attribute::Token(true),
                Attribute::Wrap(true),
                Attribute::Modifiable(false)
            ]
        );
        assert!(matches!(
            s.get_attribute_info(kek, &[AttributeType::Value])?
                .as_slice(),
            [AttributeInfo::Sensitive]
        ));
        s.logout()?;
        s.close()?;
    }
    println!("1. KEK（{KEK_LABEL}）を作った。トークンに残り、値は読めない");

    // 2〜5. 保存する側：データ鍵を作って使い、KEK で包んで DB に書く
    let mut db: Vec<Row> = Vec::new();
    let plain = b"order #2001";
    let dk_handle;
    {
        let s = lib.open_rw_session(slot)?;
        s.login(UserType::User, Some(&pin(USER_PIN)))?;
        let kek = find_kek(&s)?;

        // 2. データ鍵を作る。セッションオブジェクト。値は読めないが、包めるようにしておく
        let dk = s.generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Token(false),
                Attribute::ValueLen(32.into()),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(true), // FALSE だと包めない
            ],
        )?; // C_GenerateKey
        dk_handle = dk;

        // 3. データ鍵で業務のデータを暗号化する
        let iv = s.generate_random_vec(12)?;
        let ct = s.encrypt(
            &Mechanism::AesGcm(GcmParams::new(&mut iv.clone(), AAD, 128.into())?),
            dk,
            plain,
        )?; // C_Encrypt

        // 4. 包む：KEK でデータ鍵の値を暗号化して、外に出す
        let wrapped = s.wrap_key(&Mechanism::AesKeyWrap, kek, dk)?; // C_WrapKey
        assert_eq!(
            wrapped.len(),
            40,
            "AES-256 の値 32 バイト + 検査用 8 バイト"
        );

        // 5. DB に書く：包んだ鍵と、ほどくのに要ること。属性は包みに入らないので、要るものは自分で書いておく
        db.push(Row {
            kek_label: KEK_LABEL.to_string(),
            mechanism: "CKM_AES_KEY_WRAP",
            key_type: "AES-256",
            wrapped,
            iv,
            ct,
        });
        s.destroy_object(dk)?; // C_DestroyObject（閉じれば消えるが、使い終わったらすぐ捨てる）
        s.logout()?;
        s.close()?; // C_CloseSession
    }
    println!(
        "2〜5. データ鍵を作って暗号化に使い、KEK で包んで DB へ（40 バイト）。データ鍵は捨てた"
    );

    // 6〜9. 使う側：別のセッション。前のハンドルはもう何も指さない
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&pin(USER_PIN)))?;
    assert_eq!(
        rv(s.get_attributes(dk_handle, &[AttributeType::Class])),
        Some(RvError::ObjectHandleInvalid),
        "セッションオブジェクトは消えている"
    );
    let row = &db[0];

    // 6. KEK を、DB に書いたラベルで探す
    assert_eq!(row.kek_label, KEK_LABEL);
    let kek = find_kek(&s)?;

    // 7. ほどく：包みを HSM に渡すと、中に鍵ができてハンドルが返る。値はアプリに出ない
    //    包みには属性が入っていないので、どんな鍵として戻すかはここで書く（SENSITIVE・EXTRACTABLE は KEK と同じ値）
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    assert_eq!(
        (row.mechanism, row.key_type),
        ("CKM_AES_KEY_WRAP", "AES-256")
    );
    let dk = s.unwrap_key(&Mechanism::AesKeyWrap, kek, &row.wrapped, &template)?; // C_UnwrapKey
    assert_ne!(dk, kek);

    // 8. ほどいた鍵の属性は KEK の CKA_UNWRAP_TEMPLATE に従う。
    //    ほどくテンプレートに同じ値を書いておくと、書かなくてよいトークンでも、書かないと通らないトークンでも動く
    let got = s.get_attributes(dk, &[AttributeType::Sensitive, AttributeType::Extractable])?;
    assert_eq!(
        got,
        vec![Attribute::Sensitive(true), Attribute::Extractable(false)]
    );
    assert!(matches!(
        s.get_attribute_info(dk, &[AttributeType::Value])?
            .as_slice(),
        [AttributeInfo::Sensitive]
    ));
    // テンプレートと食い違う指定をすると、ほどけない（返るエラーはトークン次第）
    let loose = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(false),
        Attribute::Sensitive(false),
    ];
    let e = rv(s.unwrap_key(&Mechanism::AesKeyWrap, kek, &row.wrapped, &loose));
    assert!(e.is_some(), "SENSITIVE = FALSE ではほどけない");
    println!("6〜8. KEK をラベルで探してほどいた。SENSITIVE = TRUE・EXTRACTABLE = FALSE（食い違う指定は {e:?}）");

    // 9. 使って捨てる
    let pt = s.decrypt(
        &Mechanism::AesGcm(GcmParams::new(&mut row.iv.clone(), AAD, 128.into())?),
        dk,
        &row.ct,
    )?; // C_Decrypt
    assert_eq!(pt, plain);
    s.destroy_object(dk)?;
    s.logout()?;
    s.close()?;
    println!("9. ほどいた鍵で復号して元のデータに戻り、鍵は捨てた。トークンに残るのは KEK だけ");
    println!("OK: シナリオ「包んだ鍵を外に置く」が最後まで通った");
    Ok(())
}
