//! シナリオ「鍵の一生」：C_GetFunctionList から C_Finalize まで、1本の鍵を最初から最後まで追う。
//! 2台の HSM（テスト用のトークン hsm-a と hsm-b）で、
//! 作る → 使う → 証明書 → 探す → 別の HSM へ移す → 確かめる → 元を消す を通す。
//!
//! 実行前に scripts/setup-softhsm.sh でテスト用の SoftHSM2 を用意すること（空きスロットを使う）。
//!   PKCS11_MODULE … Cryptoki ライブラリのパス（既定: SoftHSM2）
//! 証明書と署名は openssl コマンドでも確かめる（PATH にあれば）。
//!
//! hsm-a / hsm-b は、1回目は空きスロットに作り、2回目からは初期化し直す。demo トークンには触らない。

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, PublicKeyData, SerialNumber, SignatureAlgorithm,
    SigningKey, PKCS_ECDSA_P256_SHA256,
};
use std::env;
use std::fs;
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const SO_PIN: &str = "5678";
const USER_PIN: &str = "1111";
/// P-256 の OID（1.2.840.10045.3.1.7）を DER にしたもの
const P256: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const DATA: &[u8] = b"order #1001: 3 items";
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

fn find_slot(lib: &Pkcs11, label: &str) -> Result<Option<Slot>> {
    for slot in lib.get_slots_with_token()? {
        if lib.get_token_info(slot)?.label() == label {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// HSM を1台用意する（第1章）：トークンを初期化して User PIN を決める
fn prepare(lib: &Pkcs11, name: &str) -> Result<Slot> {
    let slot = match find_slot(lib, name)? {
        Some(slot) => slot, // 2回目からは前回のものを初期化し直す
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
    lib.init_token(slot, &pin(SO_PIN), name)?; // C_InitToken
    let so = lib.open_rw_session(slot)?;
    so.login(UserType::So, Some(&pin(SO_PIN)))?;
    so.init_pin(&pin(USER_PIN))?; // C_InitPIN
    so.logout()?;
    so.close()?;
    Ok(slot)
}

/// 属性を1つ読む
fn read(s: &Session, h: ObjectHandle, ty: AttributeType) -> Result<Attribute> {
    s.get_attributes(h, &[ty])?
        .pop()
        .ok_or_else(|| format!("{ty:?} を読めない").into())
}

fn bytes(a: Attribute) -> Vec<u8> {
    match a {
        Attribute::EcPoint(v) | Attribute::Modulus(v) | Attribute::PublicExponent(v) => v,
        _ => Vec::new(),
    }
}

fn flag(s: &Session, h: ObjectHandle, ty: AttributeType) -> Result<bool> {
    Ok(match read(s, h, ty)? {
        Attribute::Local(b) | Attribute::AlwaysSensitive(b) | Attribute::NeverExtractable(b) => b,
        a => return Err(format!("想定外の属性 {a:?}").into()),
    })
}

/// DER の INTEGER（先頭の 0 を詰め、最上位ビットが立っていれば 0 を足す）
fn der_int(x: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = x.iter().copied().skip_while(|b| *b == 0).collect();
    if v.first().is_none_or(|b| b & 0x80 != 0) {
        v.insert(0, 0);
    }
    [vec![0x02, v.len() as u8], v].concat()
}

/// PKCS#11 の ECDSA 署名（r と s を並べた 64 バイト）を、証明書や openssl が使う DER にする
fn der_sig(rs: &[u8]) -> Vec<u8> {
    let (r, s) = rs.split_at(rs.len() / 2);
    let body = [der_int(r), der_int(s)].concat();
    [vec![0x30, body.len() as u8], body].concat()
}

/// HSM の中の秘密鍵で証明書に署名するための橋渡し（rcgen に「署名だけ外でやる鍵」として渡す）
struct HsmSigner<'a> {
    s: &'a Session,
    key: ObjectHandle,
    point: Vec<u8>, // 公開鍵（04 || X || Y の 65 バイト）
}

impl PublicKeyData for HsmSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for HsmSigner<'_> {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let hsm = || -> cryptoki::error::Result<Vec<u8>> {
            let hash = self.s.digest(&Mechanism::Sha256, msg)?; // C_Digest
            self.s.sign(&Mechanism::Ecdsa, self.key, &hash) // C_Sign（CKM_ECDSA）
        };
        hsm()
            .map(|rs| der_sig(&rs))
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

/// openssl があれば呼んで、出力を返す（なければ None）
fn openssl(args: &[&str]) -> Option<String> {
    let out = Command::new("openssl").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).into_owned())
}

fn main() -> Result<()> {
    let module =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());
    let tmp = env::temp_dir().join(format!("pkcs11-lifecycle-{}", std::process::id()));
    fs::create_dir_all(&tmp)?;
    let path = |name: &str| tmp.join(name).to_string_lossy().into_owned();

    // 1. ライブラリを読み込み、C_GetFunctionList で関数の表を受け取る（cryptoki の Pkcs11::new の中身）
    {
        use cryptoki_sys::{CK_C_Initialize, CKR_OK, CK_FUNCTION_LIST};
        // v3.0 以降のライブラリは C_GetInterface も持ち、cryptoki はそちらを先に探す（持つかはライブラリ次第）
        let raw = unsafe { cryptoki_sys::Pkcs11::new(&module)? }; // dlopen
        let mut list: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
        assert_eq!(unsafe { raw.C_GetFunctionList(&mut list) }, CKR_OK); // C_GetFunctionList
        let table = unsafe { &*list };
        let count = (std::mem::size_of::<CK_FUNCTION_LIST>()
            - std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize))
            / std::mem::size_of::<CK_C_Initialize>();
        assert_eq!(count, 68, "v2.40 の関数の表には 68 個の関数が並ぶ");
        assert!(table.C_Initialize.is_some() && table.C_WrapKey.is_some());
        println!(
            "C_GetFunctionList: 表の版 {}.{}、関数 {count} 個",
            table.version.major, table.version.minor
        );
    }
    let lib = Pkcs11::new(&module)?; // 同じことをして、表を中に持つ

    // 2. C_Initialize。2台の HSM（トークン）を用意する
    lib.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?; // C_Initialize
    let slot_a = prepare(&lib, "hsm-a")?;
    let slot_b = prepare(&lib, "hsm-b")?;
    assert_ne!(slot_a, slot_b);
    let a = lib.open_rw_session(slot_a)?; // C_OpenSession
    a.login(UserType::User, Some(&pin(USER_PIN)))?; // C_Login
    println!("HSM を2台用意した: hsm-a と hsm-b");

    // 3. HSM-A で、名前を決めて鍵を作る。あとで移すので「包む形でだけ出せる」設定にする
    let (sign_pub, sign_priv) = a.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::EcParams(P256.to_vec()),
            Attribute::Verify(true),
            label("orders-sign"),
        ],
        &[
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),   // 値はそのままでは読めない
            Attribute::Extractable(true), // 包めば出せる（移すため）
            Attribute::Sign(true),
            label("orders-sign"),
        ],
    )?;
    let point = bytes(read(&a, sign_pub, AttributeType::EcPoint)?); // DER の OCTET STRING
    let raw_point = point[2..].to_vec(); // 04 || X || Y
    assert_eq!(raw_point.len(), 65);
    let sign_id = a.digest(&Mechanism::Sha1, &point)?; // 第5章：公開鍵のハッシュを CKA_ID に
    for h in [sign_pub, sign_priv] {
        a.update_attributes(h, &[Attribute::Id(sign_id.clone())])?;
    }
    let data_id = a.generate_random_vec(8)?;
    let data_key = a.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true),
            Attribute::ValueLen(32.into()),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Id(data_id.clone()),
            label("orders-data"),
        ],
    )?;
    assert!(flag(&a, sign_priv, AttributeType::Local)?);
    assert!(flag(&a, sign_priv, AttributeType::AlwaysSensitive)?);
    assert!(!flag(&a, sign_priv, AttributeType::NeverExtractable)?);
    println!("HSM-A に orders-sign（EC 鍵ペア）と orders-data（AES-256）を作った");

    // 4. 使う：データを AES-GCM で暗号化し、ECDSA で署名する
    let iv = a.generate_random_vec(12)?;
    let sealed = a.encrypt(
        &Mechanism::AesGcm(GcmParams::new(&mut iv.clone(), AAD, 128.into())?),
        data_key,
        DATA,
    )?;
    let hash = a.digest(&Mechanism::Sha256, DATA)?;
    let sig_a = a.sign(&Mechanism::Ecdsa, sign_priv, &hash)?;
    a.verify(&Mechanism::Ecdsa, sign_pub, &hash, &sig_a)?;
    assert_eq!(
        sealed.len(),
        DATA.len() + 16,
        "GCM はデータの長さ + タグ 16 バイト"
    );
    assert_eq!(sig_a.len(), 64);
    println!(
        "暗号文 {} バイト、署名 {} バイト",
        sealed.len(),
        sig_a.len()
    );

    // 5. 証明書を作る。PKCS#11 に証明書を作る関数はない。中身はアプリが組み、署名だけ HSM で行う
    let mut params = CertificateParams::default();
    let mut serial = a.generate_random_vec(16)?; // シリアル番号は HSM の乱数で（C_GenerateRandom）
    serial[0] &= 0x7F; // 正の数にする
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "orders-sign");
    let signer = HsmSigner {
        s: &a,
        key: sign_priv,
        point: raw_point.clone(),
    };
    let cert = params.self_signed(&signer)?; // 署名のときだけ HsmSigner::sign → C_Sign
    let cert_der = cert.der().to_vec();
    // 主体（Subject）の DER：SEQUENCE { SET { SEQUENCE { OID 2.5.4.3（CN）, UTF8String } } }
    let cn = b"orders-sign";
    let atv = [
        &[0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, cn.len() as u8][..],
        cn,
    ]
    .concat();
    let rdn = [vec![0x30, atv.len() as u8], atv].concat();
    let set = [vec![0x31, rdn.len() as u8], rdn].concat();
    let subject = [vec![0x30, set.len() as u8], set].concat();
    let count = |needle: &[u8]| {
        cert_der
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count()
    };
    assert_eq!(count(&subject), 2, "自己署名なので発行者と主体が同じ");
    assert_eq!(count(&raw_point), 1, "HSM-A の公開鍵が入っている");
    fs::write(path("cert.pem"), cert.pem())?;
    if let Some(out) = openssl(&["verify", "-CAfile", &path("cert.pem"), &path("cert.pem")]) {
        assert!(out.contains(": OK"), "{out}");
        println!("openssl verify: OK");
    }
    println!(
        "証明書 {} バイト（CN=orders-sign、署名は HSM-A）",
        cert_der.len()
    );

    // 6. 証明書をトークンに入れる。鍵ペアと同じ CKA_ID で結ぶ
    let cert_attrs = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
        Attribute::Token(true),
        Attribute::Id(sign_id.clone()),
        Attribute::Subject(subject.clone()),
        Attribute::Value(cert_der.clone()),
        label("orders-sign"),
    ];
    a.create_object(&cert_attrs)?; // C_CreateObject

    // 7. CKA_ID で探すと、公開鍵・秘密鍵・証明書の3つが見つかる
    let found = a.find_objects(&[Attribute::Id(sign_id.clone())])?;
    assert_eq!(found.len(), 3);
    let cert_a = a.find_objects(&[
        Attribute::Id(sign_id.clone()),
        Attribute::Class(ObjectClass::CERTIFICATE),
    ])?;
    assert_eq!(cert_a.len(), 1);
    println!("CKA_ID で3つ見つかった（公開鍵・秘密鍵・証明書）");

    // 8. 移す準備：HSM-B で「受け取り用」の RSA 鍵ペアを作り、公開鍵だけを HSM-A に渡す
    let b = lib.open_rw_session(slot_b)?;
    b.login(UserType::User, Some(&pin(USER_PIN)))?;
    let (recv_pub, recv_priv) = b.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &[
            Attribute::Token(false),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Wrap(true),
        ],
        &[
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Unwrap(true),
        ],
    )?;
    let modulus = bytes(read(&b, recv_pub, AttributeType::Modulus)?);
    let exponent = bytes(read(&b, recv_pub, AttributeType::PublicExponent)?);
    let recv_in_a = a.create_object(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(false),
        Attribute::Modulus(modulus),
        Attribute::PublicExponent(exponent),
        Attribute::Wrap(true),
    ])?;
    println!("HSM-B の受け取り用公開鍵（RSA-2048）を HSM-A に入れた");

    // 9. 包む（C_WrapKey）：運搬用の AES 鍵を HSM-B の公開鍵で包み、その運搬用の鍵で中身を包む
    let carrier = a.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Wrap(true),
        ],
    )?;
    let oaep = Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
        MechanismType::SHA1, // OAEP で使えるハッシュはトークン次第（第6章）
        PkcsMgfType::MGF1_SHA1,
        PkcsOaepSource::empty(),
    ));
    let wrapped_carrier = a.wrap_key(&oaep, recv_in_a, carrier)?;
    let wrapped_sign = a.wrap_key(&Mechanism::AesKeyWrapPad, carrier, sign_priv)?;
    let wrapped_data = a.wrap_key(&Mechanism::AesKeyWrap, carrier, data_key)?;
    assert_eq!(wrapped_carrier.len(), 256);
    assert_eq!(
        wrapped_sign.len(),
        80,
        "P-256 の秘密鍵（PKCS#8）を 8 の倍数に詰めて包んだもの"
    );
    assert_eq!(wrapped_data.len(), 40, "32 バイトの鍵 + 8 バイト");
    // 書き出せない（CKA_EXTRACTABLE=FALSE）の鍵は、包むこともできない
    let stuck = a.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::ValueLen(32.into()),
            Attribute::Extractable(false),
        ],
    )?;
    assert_eq!(
        rv(a.wrap_key(&Mechanism::AesKeyWrap, carrier, stuck)),
        Some(RvError::KeyUnextractable)
    );
    println!(
        "包んだ: 運搬用の鍵 {} バイト、秘密鍵 {} バイト、AES 鍵 {} バイト。書き出せない鍵 → CKR_KEY_UNEXTRACTABLE",
        wrapped_carrier.len(),
        wrapped_sign.len(),
        wrapped_data.len()
    );

    // 10. ほどく（C_UnwrapKey）：HSM-B で運搬用の鍵を取り出し、それで秘密鍵と AES 鍵を取り出す
    let carrier_b = b.unwrap_key(
        &oaep,
        recv_priv,
        &wrapped_carrier,
        &[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Unwrap(true),
        ],
    )?;
    let sign_priv_b = b.unwrap_key(
        &Mechanism::AesKeyWrapPad,
        carrier_b,
        &wrapped_sign,
        &[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Sign(true),
            Attribute::Id(sign_id.clone()),
            label("orders-sign"),
        ],
    )?;
    let data_b = b.unwrap_key(
        &Mechanism::AesKeyWrap,
        carrier_b,
        &wrapped_data,
        &[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Id(data_id.clone()),
            label("orders-data"),
        ],
    )?;
    // 公開鍵と証明書は秘密ではないので、属性をそのまま渡して作る
    let sign_pub_b = b.create_object(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::EcParams(P256.to_vec()),
        Attribute::EcPoint(point.clone()),
        Attribute::Verify(true),
        Attribute::Id(sign_id.clone()),
        label("orders-sign"),
    ])?;
    b.create_object(&cert_attrs)?;
    assert_eq!(b.find_objects(&[Attribute::Id(sign_id.clone())])?.len(), 3);
    println!("HSM-B でほどいた。公開鍵と証明書はそのまま入れた");

    // 11. 移した鍵の印：HSM の中で生まれた・ずっと秘密だった、という証明は引き継がれない
    for ty in [
        AttributeType::Local,
        AttributeType::AlwaysSensitive,
        AttributeType::NeverExtractable,
    ] {
        assert!(!flag(&b, sign_priv_b, ty)?, "{ty:?} は FALSE になる");
    }
    println!("HSM-B の秘密鍵: CKA_LOCAL / ALWAYS_SENSITIVE / NEVER_EXTRACTABLE はどれも FALSE");

    // 12. 移った先で確かめる：移す前の暗号文を復号でき、HSM-B の署名を元の証明書で検証できる
    let opened = b.decrypt(
        &Mechanism::AesGcm(GcmParams::new(&mut iv.clone(), AAD, 128.into())?),
        data_b,
        &sealed,
    )?;
    assert_eq!(opened, DATA);
    let sig_b = b.sign(&Mechanism::Ecdsa, sign_priv_b, &hash)?;
    b.verify(&Mechanism::Ecdsa, sign_pub_b, &hash, &sig_b)?;
    a.verify(&Mechanism::Ecdsa, sign_pub, &hash, &sig_b)?; // HSM-A の公開鍵でも通る（同じ鍵）
    fs::write(path("data.bin"), DATA)?;
    fs::write(path("sig.der"), der_sig(&sig_b))?;
    if let Some(out) = openssl(&["x509", "-in", &path("cert.pem"), "-pubkey", "-noout"]) {
        fs::write(path("pub.pem"), out)?;
        let out = openssl(&[
            "dgst",
            "-sha256",
            "-verify",
            &path("pub.pem"),
            "-signature",
            &path("sig.der"),
            &path("data.bin"),
        ])
        .unwrap_or_default();
        assert!(out.contains("Verified OK"), "{out}");
        println!("openssl: HSM-B の署名を、移す前に作った証明書の公開鍵で検証 → Verified OK");
    }
    println!("HSM-B で復号 → 元のデータ。HSM-B の署名は HSM-A の公開鍵でも通る");

    // 13. 元を消す（C_DestroyObject）。運搬用の鍵などのセッションオブジェクトは、閉じれば消える
    for h in a.find_objects(&[Attribute::Id(sign_id.clone())])? {
        a.destroy_object(h)?;
    }
    a.destroy_object(data_key)?;
    assert!(a
        .find_objects(&[Attribute::Id(sign_id.clone())])?
        .is_empty());
    assert!(a.find_objects(&[label("orders-data")])?.is_empty());
    assert_eq!(b.find_objects(&[Attribute::Id(sign_id)])?.len(), 3);
    println!("HSM-A から消した。鍵と証明書は HSM-B にだけある");

    // 14. 後片付け：C_Logout → C_CloseSession → C_Finalize
    a.logout()?;
    b.logout()?;
    a.close()?;
    b.close()?;
    lib.finalize()?;
    fs::remove_dir_all(&tmp)?;
    println!("OK: シナリオ「鍵の一生」が最後まで通った");
    Ok(())
}
