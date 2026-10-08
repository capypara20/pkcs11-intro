//! シナリオ2「鍵の付け替え」：署名鍵と、データ鍵を包む鍵（KEK）を、2025 年の世代から 2026 年の世代へ付け替える。
//! 署名鍵は「新しい公開鍵を先に配る → 署名を切り替える → 古い鍵は検証だけ」、
//! 暗号鍵は「新しいデータは新しい KEK で → 古い KEK はほどくだけ → データ鍵を包み直す」の順に進め、
//! 最後に古い世代を消す。各手順の主張を assert で確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!
//! 空きスロットに練習用トークン「rotate」を作る（2回目からは初期化し直す）。demo トークンには触らない。
//! 外での検証に openssl を使う（PATH にないときは飛ばす）。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;
use std::fs;
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const TOKEN: &str = "rotate";
const SO_PIN: &str = "5678";
const USER_PIN: &str = "1111";
/// P-256 の OID（1.2.840.10045.3.1.7）を DER にしたもの
const P256: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// P-256 の公開鍵を SubjectPublicKeyInfo（DER）にするときの頭（この後に 04 || X || Y が続く）
const SPKI_P256: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const AAD: &[u8] = b"orders";

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

/// 公開点（CKA_EC_POINT、DER の OCTET STRING）から 04 || X || Y を取り出す
fn point(s: &Session, public: ObjectHandle) -> Result<Vec<u8>> {
    match s.get_attributes(public, &[AttributeType::EcPoint])?.pop() {
        Some(Attribute::EcPoint(p)) => Ok(p[2..].to_vec()),
        other => Err(format!("CKA_EC_POINT を読めない: {other:?}").into()),
    }
}

/// 署名鍵の世代を作る。ラベルに世代を入れ、CKA_ID は公開鍵のハッシュ（第5章）
fn sign_pair(s: &Session, gen: &str) -> Result<(ObjectHandle, ObjectHandle, Vec<u8>)> {
    let name = format!("orders-sign-{gen}");
    let (public, private) = s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::EcParams(P256.to_vec()),
            Attribute::Verify(true),
            label(&name),
        ],
        &[
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            label(&name),
        ],
    )?; // C_GenerateKeyPair
    let ec_point = match s.get_attributes(public, &[AttributeType::EcPoint])?.pop() {
        Some(Attribute::EcPoint(p)) => p,
        other => return Err(format!("CKA_EC_POINT を読めない: {other:?}").into()),
    };
    let id = s.digest(&Mechanism::Sha1, &ec_point)?;
    for h in [public, private] {
        s.update_attributes(h, &[Attribute::Id(id.clone())])?;
    }
    Ok((public, private, id))
}

/// データ鍵を包む鍵（KEK）の世代を作る。値は外に出さない
fn kek(s: &Session, gen: &str) -> Result<ObjectHandle> {
    Ok(s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::ValueLen(32.into()),
            Attribute::Wrap(true),
            Attribute::Unwrap(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            label(&format!("orders-kek-{gen}")),
        ],
    )?)
}

/// アプリが持つ1件分：包んだデータ鍵・IV・暗号文と、どの世代の KEK で包んだか
struct Record {
    wrapped: Vec<u8>,
    iv: Vec<u8>,
    ct: Vec<u8>,
    gen: &'static str,
}

/// データ鍵を作って AES-GCM で暗号化し、データ鍵は KEK で包んで持つ（データ鍵の値はアプリに出ない）
fn seal(s: &Session, kek: ObjectHandle, gen: &'static str, plain: &[u8]) -> Result<Record> {
    let dk = s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Encrypt(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true), // 包めるように
        ],
    )?;
    let iv = s.generate_random_vec(12)?;
    let ct = s.encrypt(
        &Mechanism::AesGcm(GcmParams::new(&mut iv.clone(), AAD, 128.into())?),
        dk,
        plain,
    );
    let wrapped = s.wrap_key(&Mechanism::AesKeyWrap, kek, dk); // C_WrapKey
    s.destroy_object(dk)?; // セッションの中のデータ鍵は捨てる
    Ok(Record {
        wrapped: wrapped?,
        iv,
        ct: ct?,
        gen,
    })
}

/// 包んだデータ鍵を KEK でほどくときのテンプレート
fn data_key_template(rewrap: bool) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Decrypt(true),
        Attribute::Sensitive(true),
    ];
    if rewrap {
        t.push(Attribute::Extractable(true)); // 包み直すので、もう一度包める形でほどく
    }
    t
}

/// KEK でデータ鍵をほどき、暗号文を復号する
fn open(s: &Session, kek: ObjectHandle, r: &Record) -> Result<Vec<u8>> {
    let dk = s.unwrap_key(
        &Mechanism::AesKeyWrap,
        kek,
        &r.wrapped,
        &data_key_template(false),
    )?; // C_UnwrapKey
    let pt = s.decrypt(
        &Mechanism::AesGcm(GcmParams::new(&mut r.iv.clone(), AAD, 128.into())?),
        dk,
        &r.ct,
    );
    s.destroy_object(dk)?;
    Ok(pt?)
}

/// openssl があれば、外で（HSM を使わずに）署名を確かめる
fn openssl_verify(dir: &std::path::Path, spki: &[u8], data: &[u8], rs: &[u8]) -> Option<bool> {
    let der_int = |x: &[u8]| {
        let mut v: Vec<u8> = x.iter().copied().skip_while(|b| *b == 0).collect();
        if v.first().is_none_or(|b| b & 0x80 != 0) {
            v.insert(0, 0);
        }
        [vec![0x02, v.len() as u8], v].concat()
    };
    let (r, s) = rs.split_at(rs.len() / 2);
    let body = [der_int(r), der_int(s)].concat();
    let sig = [vec![0x30, body.len() as u8], body].concat();
    fs::write(dir.join("pub.der"), spki).ok()?;
    fs::write(dir.join("data.bin"), data).ok()?;
    fs::write(dir.join("sig.der"), sig).ok()?;
    let out = Command::new("openssl")
        .args(["dgst", "-sha256", "-keyform", "DER", "-verify"])
        .arg(dir.join("pub.der"))
        .arg("-signature")
        .arg(dir.join("sig.der"))
        .arg(dir.join("data.bin"))
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).contains("Verified OK"))
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let tmp = env::temp_dir().join(format!("pkcs11-rotation-{}", std::process::id()));
    fs::create_dir_all(&tmp)?;
    let lib = Pkcs11::new(&module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = prepare(&lib)?;
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&pin(USER_PIN)))?;

    // 1. いまの姿：2025 年の世代の署名鍵と KEK。データ鍵は KEK で包んでアプリが持つ
    let (pub25, priv25, id25) = sign_pair(&s, "2025")?;
    let kek25 = kek(&s, "2025")?;
    let doc1 = b"invoice 2025-12";
    let sig25 = s.sign(
        &Mechanism::Ecdsa,
        priv25,
        &s.digest(&Mechanism::Sha256, doc1)?,
    )?;
    let spki25 = [SPKI_P256.to_vec(), point(&s, pub25)?].concat(); // 相手に配ってある公開鍵
    let plains: Vec<Vec<u8>> = (1..=3)
        .map(|i| format!("order #100{i}").into_bytes())
        .collect();
    let mut records = Vec::new();
    for p in &plains {
        records.push(seal(&s, kek25, "2025", p)?);
    }
    assert_eq!(s.find_objects(&[Attribute::Id(id25.clone())])?.len(), 2);
    assert!(records.iter().all(|r| r.wrapped.len() == 40));
    println!("2025 の世代：署名鍵ペア（ID 共通）と KEK。データ 3 件は、データ鍵を KEK で包んで持つ（40 バイト）");

    // 2. 新しい世代を作る。作る前に、同じラベルがないことを確かめる
    assert!(s.find_objects(&[label("orders-sign-2026")])?.is_empty());
    assert!(s.find_objects(&[label("orders-kek-2026")])?.is_empty());
    let (pub26, priv26, id26) = sign_pair(&s, "2026")?;
    let kek26 = kek(&s, "2026")?;
    assert_ne!(id25, id26, "公開鍵が違うので ID も違う");
    assert_eq!(
        s.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?
            .len(),
        2,
        "古い世代と新しい世代が並ぶ"
    );
    println!("2026 の世代を作った。2025 の世代もまだ残っている");

    // 3. 新しい公開鍵を先に配る（相手が新しい署名を確かめられるようにしてから切り替える）
    let spki26 = [SPKI_P256.to_vec(), point(&s, pub26)?].concat();
    assert_eq!(spki26.len(), 91);
    assert_ne!(spki25, spki26);
    println!("2026 の公開鍵を SubjectPublicKeyInfo（91 バイト）で書き出した");

    // 4. 署名を新しい鍵に切り替える。アプリは「いまの世代」をラベルで引く
    let current = "2026";
    let mut found = s.find_objects(&[
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        label(&format!("orders-sign-{current}")),
    ])?;
    assert_eq!(found, vec![priv26]);
    let signer = found.remove(0);
    let doc2 = b"invoice 2026-01";
    let hash2 = s.digest(&Mechanism::Sha256, doc2)?;
    let sig26 = s.sign(&Mechanism::Ecdsa, signer, &hash2)?;
    s.verify(&Mechanism::Ecdsa, pub26, &hash2, &sig26)?;
    assert_eq!(
        rv(s.verify(&Mechanism::Ecdsa, pub25, &hash2, &sig26)),
        Some(RvError::SignatureInvalid),
        "古い公開鍵しか持たない相手は、新しい署名を確かめられない"
    );
    if let Some(ok) = openssl_verify(&tmp, &spki26, doc2, &sig26) {
        assert!(ok);
        println!("openssl: 2026 の署名を、配った 2026 の公開鍵で検証 → Verified OK");
    }
    println!("署名を 2026 の鍵に切り替えた");

    // 5. 古い鍵は「確かめるだけ」に：CKA_SIGN を FALSE にする
    s.update_attributes(priv25, &[Attribute::Sign(false)])?; // C_SetAttributeValue
    assert_eq!(
        rv(s.sign(&Mechanism::Ecdsa, priv25, &hash2)),
        Some(RvError::KeyFunctionNotPermitted)
    );
    println!("2025 の秘密鍵は CKA_SIGN = FALSE。署名しようとすると CKR_KEY_FUNCTION_NOT_PERMITTED");

    // 6. 過去の署名は、古い公開鍵で今も確かめられる
    s.verify(
        &Mechanism::Ecdsa,
        pub25,
        &s.digest(&Mechanism::Sha256, doc1)?,
        &sig25,
    )?;
    if let Some(ok) = openssl_verify(&tmp, &spki25, doc1, &sig25) {
        assert!(ok);
        println!("openssl: 2025 の署名を 2025 の公開鍵で検証 → Verified OK");
    }
    println!("2025 の署名は、2025 の公開鍵で今も確かめられる");

    // 7. 新しいデータは新しい KEK で包む
    records.push(seal(&s, kek26, "2026", b"order #1004")?);
    let r4 = records.last().ok_or("ない")?;
    assert_eq!(open(&s, kek26, r4)?, b"order #1004");
    assert!(
        open(&s, kek25, r4).is_err(),
        "違う KEK ではほどけない（包みの検査で失敗する）"
    );
    println!("新しいデータ #1004 は 2026 の KEK で包んだ。2025 の KEK ではほどけない");

    // 8. 古い KEK は「ほどくだけ」に：CKA_WRAP を FALSE にする
    s.update_attributes(kek25, &[Attribute::Wrap(false)])?; // C_SetAttributeValue
    assert!(
        seal(&s, kek25, "2025", b"order #1005").is_err(),
        "もう包めない"
    );
    assert_eq!(
        open(&s, kek25, &records[0])?,
        plains[0],
        "ほどくことはできる"
    );
    println!("2025 の KEK は CKA_WRAP = FALSE。包めないが、ほどける");

    // 9. 包み直す：古い KEK でほどき、新しい KEK で包む。データ鍵の値も暗号文も、アプリには出ない・変わらない
    let old_blob = records[0].wrapped.clone();
    let before: Vec<Vec<u8>> = records.iter().map(|r| r.ct.clone()).collect();
    for r in records.iter_mut().filter(|r| r.gen == "2025") {
        let dk = s.unwrap_key(
            &Mechanism::AesKeyWrap,
            kek25,
            &r.wrapped,
            &data_key_template(true),
        )?; // C_UnwrapKey
        let again = s.wrap_key(&Mechanism::AesKeyWrap, kek26, dk); // C_WrapKey
        s.destroy_object(dk)?;
        r.wrapped = again?;
        r.gen = "2026";
    }
    assert_eq!(
        records.iter().map(|r| r.ct.clone()).collect::<Vec<_>>(),
        before,
        "暗号文はそのまま"
    );
    assert_ne!(records[0].wrapped, old_blob);
    println!("データ鍵 3 件を 2026 の KEK で包み直した。暗号文は変えていない");

    // 10. 包み直しを確かめる：すべて新しい KEK で開け、古い KEK ではもう開けない
    for (r, p) in records
        .iter()
        .zip(plains.iter().chain([b"order #1004".to_vec()].iter()))
    {
        assert_eq!(r.gen, "2026");
        assert_eq!(&open(&s, kek26, r)?, p);
        assert!(open(&s, kek25, r).is_err());
    }
    println!("4 件とも 2026 の KEK で開けた");

    // 11. 古い世代を消す。包み直しが終わる前に KEK を消すと、そのデータは二度と開けない
    for h in s.find_objects(&[Attribute::Id(id25.clone())])? {
        s.destroy_object(h)?; // C_DestroyObject（公開鍵と秘密鍵）
    }
    s.destroy_object(kek25)?;
    assert!(s.find_objects(&[label("orders-sign-2025")])?.is_empty());
    assert!(s.find_objects(&[label("orders-kek-2025")])?.is_empty());
    assert!(
        s.unwrap_key(
            &Mechanism::AesKeyWrap,
            kek25,
            &old_blob,
            &data_key_template(false)
        )
        .is_err(),
        "包み直していない古い包みは、もう開けない"
    );
    // 過去の署名は、外にある 2025 の公開鍵で確かめられる（ここでは取り込み直して HSM でも確かめる）
    let back = s.create_object(&[
        Attribute::Token(false),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(P256.to_vec()),
        Attribute::EcPoint([vec![0x04, 0x41], spki25[26..].to_vec()].concat()),
        Attribute::Verify(true),
    ])?; // C_CreateObject
    s.verify(
        &Mechanism::Ecdsa,
        back,
        &s.digest(&Mechanism::Sha256, doc1)?,
        &sig25,
    )?;
    println!("2025 の世代を消した。過去の署名は、外にある 2025 の公開鍵で確かめられる");

    // 12. 後片付け。トークンに残るのは 2026 の世代だけ
    s.logout()?;
    s.close()?;
    let check = lib.open_ro_session(slot)?;
    check.login(UserType::User, Some(&pin(USER_PIN)))?;
    assert_eq!(check.find_objects(&[Attribute::Id(id26)])?.len(), 2);
    assert_eq!(check.find_objects(&[label("orders-kek-2026")])?.len(), 1);
    assert_eq!(
        check
            .find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY)])?
            .len(),
        1,
        "KEK は 2026 の1つだけ"
    );
    check.logout()?;
    check.close()?;
    lib.finalize()?;
    fs::remove_dir_all(&tmp)?;
    println!("OK: シナリオ「鍵の付け替え」が最後まで通った");
    Ok(())
}
