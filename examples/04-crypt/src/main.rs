//! 第4章 暗号化と復号：共通鍵（AES）の各モードと、公開鍵（RSA-OAEP）での暗号化を確かめる。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用トークンを用意すること。
//!   PKCS11_MODULE      … Cryptoki ライブラリのパス（既定: SoftHSM2）
//!   PKCS11_USER_PIN    … User PIN（既定: 1234）
//!   PKCS11_TOKEN_LABEL … 使うトークンのラベル（既定: demo）
//!
//! 鍵はすべてセッションオブジェクト（CKA_TOKEN=FALSE）なので、トークンには何も残らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const DATA: &[u8] = b"hello hsm"; // 9 バイト
const AAD: &[u8] = b"header"; // GCM で暗号化はしないが改ざんは検知したい付随データ

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

/// AES-256 の鍵（C_GenerateKey）。encrypt=false なら CKA_ENCRYPT を付けない
fn aes_key(s: &Session, encrypt: bool) -> Result<ObjectHandle> {
    let template = [
        Attribute::Token(false),
        Attribute::ValueLen(32.into()),
        Attribute::Encrypt(encrypt),
        Attribute::Decrypt(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    Ok(s.generate_key(&Mechanism::AesKeyGen, &template)?)
}

/// IV（初期化ベクトル）はトークンの乱数で毎回作る（C_GenerateRandom）
fn random_iv(s: &Session) -> Result<[u8; 16]> {
    let v = s.generate_random_vec(16)?;
    Ok(v.try_into().expect("16 バイト"))
}

fn gcm<'a>(iv: &'a mut [u8], aad: &'a [u8]) -> Result<Mechanism<'a>> {
    Ok(Mechanism::AesGcm(GcmParams::new(iv, aad, 128.into())?)) // タグ 128 ビット
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let pin = env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "1234".to_string());
    let label = env::var("PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "demo".to_string());

    let lib = Pkcs11::new(module)?;
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let slot = find_slot(&lib, &label)?;
    let s = lib.open_rw_session(slot)?;
    s.login(UserType::User, Some(&AuthPin::new(pin.into())))?;

    // 1・2. 共通鍵を作り、C_EncryptInit → C_Encrypt で暗号化、C_DecryptInit → C_Decrypt で戻す
    let key = aes_key(&s, true)?;
    let iv = random_iv(&s)?;
    let ct = s.encrypt(&Mechanism::AesCbcPad(iv), key, DATA)?;
    assert_eq!(s.decrypt(&Mechanism::AesCbcPad(iv), key, &ct)?, DATA);
    let no_enc = aes_key(&s, false)?;
    assert_eq!(
        rv(s.encrypt(&Mechanism::AesCbcPad(iv), no_enc, DATA)),
        Some(RvError::KeyFunctionNotPermitted)
    );
    println!(
        "AES-CBC-PAD: 9 バイト → {} バイト → 元に戻る。CKA_ENCRYPT のない鍵は断られる",
        ct.len()
    );

    // 4. ECB は同じ平文ブロックが同じ暗号文ブロックになる（模様が残る）。CBC はならない
    let two_blocks = [b'A'; 32];
    let ecb = s.encrypt(&Mechanism::AesEcb, key, &two_blocks)?;
    assert_eq!(ecb[..16], ecb[16..]);
    let cbc = s.encrypt(&Mechanism::AesCbc(iv), key, &two_blocks)?;
    assert_ne!(cbc[..16], cbc[16..]);
    println!("ECB: 同じ 16 バイトが同じ暗号文に。CBC: 違う暗号文に");

    // 5. 同じ鍵・同じ IV なら同じ暗号文。IV を毎回変えれば変わる（IV は秘密ではないので暗号文と一緒に送る）
    assert_eq!(s.encrypt(&Mechanism::AesCbcPad(iv), key, DATA)?, ct);
    let iv2 = random_iv(&s)?;
    assert_ne!(s.encrypt(&Mechanism::AesCbcPad(iv2), key, DATA)?, ct);
    println!("同じ IV → 同じ暗号文、IV を変える → 違う暗号文");

    // 6. パディングなしの CBC は 16 の倍数しか受け付けない。CBC_PAD は埋めてから暗号化する
    assert_eq!(
        rv(s.encrypt(&Mechanism::AesCbc(iv), key, DATA)),
        Some(RvError::DataLenRange)
    );
    assert_eq!(ct.len(), 16);
    println!(
        "CKM_AES_CBC に 9 バイト → CKR_DATA_LEN_RANGE。CKM_AES_CBC_PAD なら 16 バイトに埋める"
    );

    // 7. CBC は改ざんに気づかない：IV の1ビットを変えると、平文の1文字が黙って変わる
    let mut flipped = iv;
    flipped[0] ^= 0x01;
    let changed = s.decrypt(&Mechanism::AesCbcPad(flipped), key, &ct)?;
    assert_eq!(changed, b"iello hsm");
    println!(
        "IV を1ビット変えて復号 → {:?}（エラーにならない）",
        String::from_utf8_lossy(&changed)
    );

    // 8. GCM は暗号文にタグを付け、改ざんされていれば復号を拒む
    let mut giv = s.generate_random_vec(12)?;
    let sealed = s.encrypt(&gcm(&mut giv.clone(), AAD)?, key, DATA)?;
    assert_eq!(
        sealed.len(),
        DATA.len() + 16,
        "暗号文 9 バイト + タグ 16 バイト"
    );
    assert_eq!(s.decrypt(&gcm(&mut giv.clone(), AAD)?, key, &sealed)?, DATA);
    let mut tampered = sealed.clone();
    tampered[0] ^= 0x01;
    let r1 = rv(s.decrypt(&gcm(&mut giv.clone(), AAD)?, key, &tampered));
    let r2 = rv(s.decrypt(&gcm(&mut giv, b"headex")?, key, &sealed));
    assert!(
        r1.is_some() && r2.is_some(),
        "改ざんされた暗号文・付随データは復号できない"
    );
    println!(
        "GCM: 9 バイト → {} バイト（タグ込み）。改ざん → {r1:?} / 付随データの改ざん → {r2:?}",
        sealed.len()
    );

    // 9. 長いデータは分けて渡せる。途中では出力が 0 バイトのこともある（ブロックがそろうまでためる）
    s.encrypt_init(&Mechanism::AesCbcPad(iv), key)?;
    let mut parts = s.encrypt_update(b"hello ")?;
    let first = parts.len();
    parts.extend(s.encrypt_update(b"hsm")?);
    parts.extend(s.encrypt_final()?);
    assert_eq!(parts, ct);
    println!("分けて暗号化 = 一度に暗号化（最初の C_EncryptUpdate の出力は {first} バイト）");

    // 10. 公開鍵で暗号化、秘密鍵で復号（RSA-OAEP）。SoftHSM2 2.6.1 は SHA-1 の OAEP だけに対応
    let (pub_h, priv_h) = s.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Encrypt(true),
        ],
        &[
            Attribute::Token(false),
            Attribute::Decrypt(true),
            Attribute::Sensitive(true),
        ],
    )?;
    let sha256 = PkcsOaepParams::new(
        MechanismType::SHA256,
        PkcsMgfType::MGF1_SHA256,
        PkcsOaepSource::empty(),
    );
    let sha256_result = rv(s.encrypt(&Mechanism::RsaPkcsOaep(sha256), pub_h, DATA));
    assert!(
        sha256_result.is_some(),
        "SoftHSM2 2.6.1 は SHA-256 の OAEP を受け付けない"
    );
    let oaep = PkcsOaepParams::new(
        MechanismType::SHA1,
        PkcsMgfType::MGF1_SHA1,
        PkcsOaepSource::empty(),
    );
    let rsa1 = s.encrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, DATA)?;
    let rsa2 = s.encrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, DATA)?;
    assert_eq!(rsa1.len(), 256);
    assert_ne!(rsa1, rsa2, "OAEP は乱数を混ぜるので毎回違う");
    assert_eq!(
        s.decrypt(&Mechanism::RsaPkcsOaep(oaep), priv_h, &rsa1)?,
        DATA
    );
    assert_eq!(
        rv(s.decrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, &rsa1)),
        Some(RvError::KeyFunctionNotPermitted),
        "公開鍵では復号できない"
    );
    // 2048 ビット・SHA-1 なら 256 - 2×20 - 2 = 214 バイトまで
    assert_eq!(
        s.encrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, &[7u8; 214])?
            .len(),
        256
    );
    let too_long = rv(s.encrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, &[7u8; 215]));
    assert!(too_long.is_some());
    println!(
        "RSA-OAEP: 256 バイト・毎回違う。SHA-256 の OAEP → {sha256_result:?}、215 バイト → {too_long:?}"
    );

    s.logout()?;
    s.close()?; // セッションオブジェクトの鍵はここで消える
    lib.finalize()?;
    println!("OK: 第4章の記述どおりに動いた");
    Ok(())
}
