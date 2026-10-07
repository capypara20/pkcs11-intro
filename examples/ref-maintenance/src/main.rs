//! メンテナンス API リファレンスの裏付け：トークンの健康診断・PIN の管理・鍵の棚卸し・属性の手入れ・
//! 退役を、PKCS#11 の関数で行い、ページに書いた振る舞いを確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用の SoftHSM2 を用意すること（空きスロットを使う）。
//!   PKCS11_MODULE … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!
//! PIN を間違えたり初期化したりするので、demo トークンではなく練習用トークン「maint-api」を使う
//! （1回目は空きスロットに作り、2回目からは初期化し直す）。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::{Limit, Slot};
use cryptoki::types::{AuthPin, Date};
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LABEL: &str = "maint-api";
const SO_PIN: &str = "5678";
const USER_PIN: &str = "1111";
/// P-256 の OID（1.2.840.10045.3.1.7）を DER にしたもの
const P256: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn pin(s: &str) -> AuthPin {
    AuthPin::new(s.to_string().into())
}

fn label(s: &str) -> Attribute {
    Attribute::Label(s.as_bytes().to_vec())
}

fn rv<T>(r: cryptoki::error::Result<T>) -> Option<RvError> {
    match r {
        Err(Error::Pkcs11(e, _)) => Some(e),
        _ => None,
    }
}

fn find_slot(lib: &Pkcs11, name: &str) -> Result<Option<Slot>> {
    for slot in lib.get_slots_with_token()? {
        if lib.get_token_info(slot)?.label() == name {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// 練習用トークンを用意する（第1章と同じ）。作り直すと中身は消える
fn prepare(lib: &Pkcs11) -> Result<Slot> {
    let slot = match find_slot(lib, LABEL)? {
        Some(slot) => slot,
        None => {
            let mut free = None;
            for slot in lib.get_slots_with_token()? {
                if !lib.get_token_info(slot)?.token_initialized() {
                    free = Some(slot);
                }
            }
            free.ok_or("空きスロットがない")?
        }
    };
    lib.init_token(slot, &pin(SO_PIN), LABEL)?; // C_InitToken
    let so = lib.open_rw_session(slot)?;
    so.login(UserType::So, Some(&pin(SO_PIN)))?;
    so.init_pin(&pin(USER_PIN))?; // C_InitPIN
    so.close()?;
    Ok(slot)
}

fn aes(s: &Session, extra: &[Attribute]) -> cryptoki::error::Result<ObjectHandle> {
    let mut t = vec![Attribute::ValueLen(16.into()), Attribute::Encrypt(true)];
    t.extend_from_slice(extra);
    s.generate_key(&Mechanism::AesKeyGen, &t)
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let softhsm = lib.get_library_info()?.manufacturer_id() == "SoftHSM";
    let slot = prepare(&lib)?;

    // A. 健康診断：ログインしなくても読める
    assert!(lib.get_slots_with_initialized_token()?.contains(&slot));
    let t = lib.get_token_info(slot)?; // C_GetTokenInfo
    assert!(t.token_initialized() && t.user_pin_initialized());
    if softhsm {
        // 空き容量・セッション数は「不明」、時計はない
        assert_eq!(t.free_public_memory(), None);
        assert_eq!(t.free_private_memory(), None);
        assert_eq!(t.session_count(), None);
        assert!(matches!(t.max_session_count(), Limit::Infinite));
        assert!(!t.clock_on_token() && t.utc_time().is_none());
    }
    assert_eq!(lib.get_slot_event()?, None); // C_WaitForSlotEvent（待たない）→ CKR_NO_EVENT
    println!("A: 初期化済み・User PIN あり。空き容量・セッション数は不明、時計なし、抜き差しの知らせなし");

    // A（続き）PIN を間違えると「残りが少ない」の印が立つ
    let s = lib.open_rw_session(slot)?;
    assert_eq!(
        rv(s.login(UserType::User, Some(&pin("0000")))),
        Some(RvError::PinIncorrect)
    );
    assert!(lib.get_token_info(slot)?.user_pin_count_low());

    // B. SO が User PIN を付け直すと、印は消える。User は自分で PIN を変えられる
    s.login(UserType::So, Some(&pin(SO_PIN)))?;
    s.init_pin(&pin("2222"))?; // C_InitPIN
    s.logout()?;
    assert!(!lib.get_token_info(slot)?.user_pin_count_low());
    s.login(UserType::User, Some(&pin("2222")))?;
    s.set_pin(&pin("2222"), &pin(USER_PIN))?; // C_SetPIN
    println!(
        "B: PIN を間違える → count low。SO が C_InitPIN で付け直す → 消える。C_SetPIN で戻した"
    );

    // C. 鍵の棚卸し：素性を読む（HSM の中で生まれたか、どのメカニズムで作ったか）
    let (sign_pub, sign_priv) = s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[
            Attribute::Token(true),
            Attribute::EcParams(P256.to_vec()),
            Attribute::Verify(true),
            Attribute::Id(vec![1]),
            label("orders-sign"),
        ],
        &[
            Attribute::Token(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Id(vec![1]),
            label("orders-sign"),
        ],
    )?;
    let facts = s.get_attributes(
        sign_priv,
        &[AttributeType::Local, AttributeType::KeyGenMechanism],
    )?;
    assert!(facts.contains(&Attribute::Local(true)));
    assert!(facts.contains(&Attribute::KeyGenMechanism(MechanismType::ECC_KEY_PAIR_GEN)));
    let mut count = 0;
    for h in s.iter_objects(&[])? {
        h?;
        count += 1;
    }
    assert_eq!(count, 2);
    println!("C: オブジェクト {count} 件。秘密鍵は CKA_LOCAL=TRUE、CKA_KEY_GEN_MECHANISM=CKM_EC_KEY_PAIR_GEN");

    // C（続き）日付：書けるが、使い道は止めない。SoftHSM2 では書いた日付を読み戻せない
    let past = Date::new_from_str_slice("2020", "01", "01")?;
    s.update_attributes(sign_priv, &[Attribute::EndDate(past)])?; // C_SetAttributeValue は成功
    let hash = s.digest(&Mechanism::Sha256, b"hello hsm")?;
    let sig = s.sign(&Mechanism::Ecdsa, sign_priv, &hash)?; // 終了日を過ぎていても署名できる
    s.verify(&Mechanism::Ecdsa, sign_pub, &hash, &sig)?;
    if softhsm {
        assert_eq!(
            rv(s.get_attributes(sign_priv, &[AttributeType::EndDate])),
            Some(RvError::GeneralError)
        );
    }
    println!("C: CKA_END_DATE を過去にしても署名できた。SoftHSM2 では読むと CKR_GENERAL_ERROR");

    // D. 用途を止める：CKA_SIGN は変えられる。止めた鍵では署名できない
    s.update_attributes(sign_priv, &[Attribute::Sign(false)])?;
    assert_eq!(
        rv(s.sign(&Mechanism::Ecdsa, sign_priv, &hash)),
        Some(RvError::KeyFunctionNotPermitted)
    );
    println!("D: CKA_SIGN=FALSE にした鍵 → CKR_KEY_FUNCTION_NOT_PERMITTED");

    // D（続き）守りは固める方向にだけ変えられる（複製のときも同じ）
    let open = aes(
        &s,
        &[
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ],
    )?;
    s.update_attributes(
        open,
        &[Attribute::Sensitive(true), Attribute::Extractable(false)],
    )?;
    for loosen in [Attribute::Sensitive(false), Attribute::Extractable(true)] {
        assert_eq!(
            rv(s.update_attributes(open, std::slice::from_ref(&loosen))),
            Some(RvError::AttributeReadOnly)
        );
        assert_eq!(
            rv(s.copy_object(open, &[loosen])),
            Some(RvError::AttributeReadOnly)
        );
    }
    println!("D: SENSITIVE / EXTRACTABLE は固める方向だけ。緩めると C_SetAttributeValue も C_CopyObject も CKR_ATTRIBUTE_READ_ONLY");

    // D（続き）変更・複製・削除を禁じる（CKA_MODIFIABLE / COPYABLE / DESTROYABLE）
    let locked = aes(
        &s,
        &[
            Attribute::Token(true),
            Attribute::Modifiable(false),
            Attribute::Copyable(false),
            Attribute::Destroyable(false),
            label("locked"),
        ],
    )?;
    assert_eq!(
        rv(s.update_attributes(locked, &[label("renamed")])),
        Some(RvError::ActionProhibited)
    );
    assert_eq!(
        rv(s.update_attributes(locked, &[Attribute::Modifiable(true)])),
        Some(RvError::ActionProhibited),
        "変更禁止は解けない"
    );
    assert_eq!(
        rv(s.copy_object(locked, &[])),
        Some(RvError::ActionProhibited)
    );
    assert_eq!(
        rv(s.destroy_object(locked)),
        Some(RvError::ActionProhibited)
    );
    println!("D: 変更・複製・削除を禁じた鍵 → どれも CKR_ACTION_PROHIBITED（禁止は解けない）");

    // D（続き）セッションで作った鍵を、複製でトークンに残す。生まれの印（CKA_LOCAL）は残る
    let temp = aes(&s, &[Attribute::Token(false), label("temp")])?;
    let kept = s.copy_object(temp, &[Attribute::Token(true), label("kept")])?; // C_CopyObject
    assert!(s
        .get_attributes(kept, &[AttributeType::Token, AttributeType::Local])?
        .iter()
        .all(|a| matches!(a, Attribute::Token(true) | Attribute::Local(true))));
    println!("D: C_CopyObject でセッションの鍵をトークンに残せた（CKA_LOCAL=TRUE のまま）");

    // E. 退役：ID で鍵ペアをまとめて消す
    for h in s.find_objects(&[Attribute::Id(vec![1])])? {
        s.destroy_object(h)?; // C_DestroyObject
    }
    assert!(s.find_objects(&[Attribute::Id(vec![1])])?.is_empty());
    s.destroy_object(kept)?;
    println!("E: CKA_ID=01 の鍵ペアを C_DestroyObject で消した");

    // E（続き）削除を禁じたトークンオブジェクトは、トークンを初期化すると消える
    s.logout()?;
    s.close()?;
    lib.init_token(slot, &pin(SO_PIN), LABEL)?;
    let s = lib.open_ro_session(slot)?;
    assert!(s.find_objects(&[label("locked")])?.is_empty());
    s.close()?;
    println!("E: 削除を禁じた鍵も、C_InitToken で消えた（ほかの鍵もすべて消える）");

    // F. 後始末
    lib.finalize()?; // C_Finalize
    println!("OK: メンテナンス API リファレンスの記述どおりに動いた");
    Ok(())
}
