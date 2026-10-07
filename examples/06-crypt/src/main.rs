//! 第6章 暗号化と復号：共通鍵（AES の各モード・3DES）と、公開鍵（RSA-OAEP・RSA PKCS#1 v1.5、
//! 長いデータは AES 鍵を RSA で包む）での暗号化を確かめる。
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
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::env;
use std::os::raw::c_ulong;

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

/// 仕様の CK_AES_CTR_PARAMS。cryptoki 0.12 には AES-CTR の型がないので、仕様どおりに自分で定義して渡す
#[repr(C)]
struct CtrParams {
    counter_bits: c_ulong, // カウンタブロックのうち、カウンタとして増やすビット数
    cb: [u8; 16],          // カウンタブロックの初期値
}

fn ctr(p: &CtrParams) -> Mechanism<'_> {
    Mechanism::VendorDefined(VendorDefinedMechanism::new(MechanismType::AES_CTR, Some(p)))
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
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

    // 8. CTR はパディング不要（長さそのまま）。改ざんには気づかず、同じカウンタを使い回すと平文の XOR が漏れる
    let counter = CtrParams {
        counter_bits: 32,
        cb: random_iv(&s)?,
    };
    let ctr_ct = s.encrypt(&ctr(&counter), key, DATA)?;
    assert_eq!(ctr_ct.len(), DATA.len());
    assert_eq!(s.decrypt(&ctr(&counter), key, &ctr_ct)?, DATA);
    let mut ctr_flip = ctr_ct.clone();
    ctr_flip[0] ^= 0x01;
    assert_eq!(s.decrypt(&ctr(&counter), key, &ctr_flip)?, b"iello hsm");
    let other = s.encrypt(&ctr(&counter), key, b"HELLO HSM")?;
    assert_eq!(
        xor(&ctr_ct, &other),
        xor(DATA, b"HELLO HSM"),
        "暗号文どうしの XOR = 平文どうしの XOR"
    );
    println!(
        "CTR: 9 バイト → {} バイト。1ビット改ざんは素通り、カウンタの使い回しで平文の XOR が漏れる",
        ctr_ct.len()
    );

    // 9. GCM は暗号文にタグを付け、改ざんされていれば復号を拒む
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

    // 10. DES と 3DES：鍵の長さは固定（CKA_VALUE_LEN は書かない）、ブロックは 8 バイト
    let des_t = [
        Attribute::Token(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Sensitive(false), // パリティを見るためだけに値を読めるようにしている
        Attribute::Extractable(true),
    ];
    let des3 = s.generate_key(&Mechanism::Des3KeyGen, &des_t)?; // C_GenerateKey(CKM_DES3_KEY_GEN)
    let attrs = s.get_attributes(des3, &[AttributeType::KeyType, AttributeType::Value])?;
    assert!(attrs.contains(&Attribute::KeyType(KeyType::DES3)));
    let value = attrs
        .iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v.clone()),
            _ => None,
        })
        .ok_or("CKA_VALUE が読めない")?;
    assert_eq!(value.len(), 24, "3 鍵の 3DES は 24 バイト");
    assert!(
        value.iter().all(|b| b.count_ones() % 2 == 1),
        "各バイトは奇数パリティ"
    );
    let des2 = s.generate_key(&Mechanism::Des2KeyGen, &des_t)?; // 2 鍵の 3DES（16 バイト）
    assert!(s
        .get_attributes(des2, &[AttributeType::KeyType])?
        .contains(&Attribute::KeyType(KeyType::DES2)));
    let iv8: [u8; 8] = s.generate_random_vec(8)?.try_into().expect("8 バイト");
    let des_ct = s.encrypt(&Mechanism::Des3CbcPad(iv8), des3, DATA)?;
    assert_eq!(des_ct.len(), 16, "9 バイト → 8 の倍数の 16 バイト");
    assert_eq!(s.decrypt(&Mechanism::Des3CbcPad(iv8), des3, &des_ct)?, DATA);
    let des_ecb = s.encrypt(&Mechanism::Des3Ecb, des3, &[b'A'; 16])?;
    assert_eq!(
        des_ecb[..8],
        des_ecb[8..],
        "ECB の模様は 8 バイト単位で残る"
    );
    // 単一 DES：鍵は作れるが、SoftHSM2 2.6.1（この環境）は「暗号化できる」と答えても実際は拒む。
    // C_GetMechanismInfo でトークンに直接聞く（cryptoki の get_mechanism_list は DES 系を一覧から間引く）
    let des1 = s.generate_key(&Mechanism::DesKeyGen, &des_t)?;
    assert!(lib
        .get_mechanism_info(slot, MechanismType::DES_CBC_PAD)?
        .encrypt());
    let single = rv(s.encrypt(&Mechanism::DesCbcPad(iv8), des1, DATA));
    assert_eq!(single, Some(RvError::MechanismInvalid));
    println!(
        "3DES: 鍵 24 バイト（パリティ付き）、9 バイト → 16 バイト。単一 DES の暗号化 → {single:?}"
    );

    // 11. 長いデータは分けて渡せる。途中では出力が 0 バイトのこともある（ブロックがそろうまでためる）
    s.encrypt_init(&Mechanism::AesCbcPad(iv), key)?;
    let mut parts = s.encrypt_update(b"hello ")?;
    let first = parts.len();
    parts.extend(s.encrypt_update(b"hsm")?);
    parts.extend(s.encrypt_final()?);
    assert_eq!(parts, ct);
    println!("分けて暗号化 = 一度に暗号化（最初の C_EncryptUpdate の出力は {first} バイト）");

    // 12. 公開鍵で暗号化、秘密鍵で復号（RSA-OAEP）。OAEP で使えるハッシュはトークン次第
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
    let sha1 = PkcsOaepParams::new(
        MechanismType::SHA1,
        PkcsMgfType::MGF1_SHA1,
        PkcsOaepSource::empty(),
    );
    // SHA-256 が使えればそれを、使えなければ SHA-1 を使う
    let sha256_result = rv(s.encrypt(&Mechanism::RsaPkcsOaep(sha256), pub_h, DATA));
    let (oaep, hash_len) = if sha256_result.is_none() {
        (sha256, 32)
    } else {
        (sha1, 20)
    };
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
    // 2048 ビットなら 256 - 2×(ハッシュの長さ) - 2 バイトまで（SHA-1 なら 214、SHA-256 なら 190）
    let max = 256 - 2 * hash_len - 2;
    assert_eq!(
        s.encrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, &vec![7u8; max])?
            .len(),
        256
    );
    assert!(rv(s.encrypt(&Mechanism::RsaPkcsOaep(oaep), pub_h, &vec![7u8; max + 1])).is_some());
    println!("RSA-OAEP: 256 バイト・毎回違う。ハッシュ {hash_len} バイトなら {max} バイトまで");

    // 13. RSA PKCS#1 v1.5 の暗号化：古い詰め方。2048 ビットなら 256 - 11 = 245 バイトまで
    let v15 = s.encrypt(&Mechanism::RsaPkcs, pub_h, DATA)?;
    assert_eq!(v15.len(), 256);
    assert_ne!(
        v15,
        s.encrypt(&Mechanism::RsaPkcs, pub_h, DATA)?,
        "乱数で埋めるので毎回違う"
    );
    assert_eq!(s.decrypt(&Mechanism::RsaPkcs, priv_h, &v15)?, DATA);
    assert_eq!(
        s.encrypt(&Mechanism::RsaPkcs, pub_h, &[7u8; 245])?.len(),
        256
    );
    assert!(rv(s.encrypt(&Mechanism::RsaPkcs, pub_h, &[7u8; 246])).is_some());
    println!("RSA PKCS#1 v1.5: 256 バイト・毎回違う・245 バイトまで");

    // 14. 長いデータは AES で暗号化し、その AES 鍵を相手の公開鍵で包んで送る（C_WrapKey）
    let (wrap_pub, wrap_priv) = s.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Wrap(true), // 既定値はトークン次第なので、包むなら明示する
        ],
        &[
            Attribute::Token(false),
            Attribute::Unwrap(true),
            Attribute::Sensitive(true),
        ],
    )?;
    let data_key = s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Encrypt(true),
            Attribute::Extractable(true), // 包めるのは EXTRACTABLE の鍵だけ
        ],
    )?;
    let long = vec![0x61u8; 1000];
    let iv = [0x24u8; 16];
    let body = s.encrypt(&Mechanism::AesCbcPad(iv), data_key, &long)?;
    assert_eq!(body.len(), 1008);
    let wrapped = s.wrap_key(&Mechanism::RsaPkcsOaep(oaep), wrap_pub, data_key)?; // C_WrapKey
    assert_eq!(wrapped.len(), 256);
    // 受け取る側：秘密鍵で AES 鍵をほどき（C_UnwrapKey）、データを復号する
    let got = s.unwrap_key(
        &Mechanism::RsaPkcsOaep(oaep),
        wrap_priv,
        &wrapped,
        &[
            Attribute::Token(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Decrypt(true),
        ],
    )?;
    assert_eq!(s.decrypt(&Mechanism::AesCbcPad(iv), got, &body)?, long);
    println!("包んで送る: 1000 バイトを AES で暗号化（1008 バイト）、AES 鍵を RSA で包んで 256 バイト。ほどいて復号できた");

    s.logout()?;
    s.close()?; // セッションオブジェクトの鍵はここで消える
    lib.finalize()?;
    println!("OK: 第6章の記述どおりに動いた");
    Ok(())
}
