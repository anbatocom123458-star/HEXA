//! HEXA cryptography subsystem.
//!
//! Real, established primitives only (never invented cryptography):
//! AES-256-GCM and ChaCha20-Poly1305 AEAD, SHA-2/SHA-3/BLAKE2/BLAKE3
//! hashes, Argon2id/scrypt/PBKDF2/HKDF, Ed25519, X25519, an OS CSPRNG,
//! the versioned binary .hexa container format, and the one-time-key
//! secure key lifecycle.

pub mod error;
pub mod encoding;
pub mod random;
pub mod hash;
pub mod aead;
pub mod kdf;
pub mod sign;
pub mod exch;
pub mod secret;
pub mod key;
pub mod format;
pub mod cipher;
pub mod registry;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::AeadId;
    use crate::cipher::{decrypt_bytes, encrypt_layers, KeySource, LayerPolicy};
    use crate::error::CryptoError;

    fn hex(s: &str) -> Vec<u8> {
        encoding::hex_decode(s).unwrap()
    }
    fn hx(b: &[u8]) -> String {
        encoding::hex_encode(b)
    }

    // ---------- hashes (known vectors) ----------

    #[test]
    fn sha256_known_vector() {
        // NIST FIPS 180-4: SHA-256("abc")
        assert_eq!(hx(&hash::sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hx(&hash::sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha512_and_sha3_known_vectors() {
        assert_eq!(
            hx(&hash::sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hx(&hash::sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hx(&hash::blake2b512(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    // ---------- AEAD (known vectors) ----------

    #[test]
    fn aes256gcm_nist_vector() {
        // All-zero key/IV/PT: GCM spec test case 13 (McGrew-Viega).
        // Cross-verified against OpenSSL (via Node crypto) and RustCrypto.
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let sealed = aead::encrypt(AeadId::Aes256Gcm, &key, &nonce, &pt, b"").unwrap();
        assert_eq!(hx(&sealed.ciphertext_tag), concat!(
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ));
        let out = aead::decrypt(AeadId::Aes256Gcm, &key, &nonce, &sealed.ciphertext_tag, b"").unwrap();
        assert_eq!(out.as_slice(), &pt);
    }

    #[test]
    fn chacha20poly1305_rfc8439_vector() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = aead::encrypt(AeadId::ChaCha20Poly1305, &key, &nonce, pt, &aad).unwrap();
        // RFC 8439 §2.8.2 expected ciphertext + tag (114 + 16 bytes).
        // Cross-verified against OpenSSL (via Node crypto) and RustCrypto.
        assert_eq!(hx(&sealed.ciphertext_tag), concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691",
        ));
        let out = aead::decrypt(AeadId::ChaCha20Poly1305, &key, &nonce, &sealed.ciphertext_tag, &aad).unwrap();
        assert_eq!(out.as_slice(), &pt[..]);
    }

    // ---------- KDF (known vectors) ----------

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = kdf::hkdf_sha256_extract_expand(&salt, &ikm, &info, 42).unwrap();
        assert_eq!(
            hx(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn argon2id_reference_vector() {
        // RFC 9106 §5.3 test vector: v19, Argon2id, t=3, m=32 KiB, p=4,
        // password = 0x01 * 32, salt = 0x02 * 16.
        // Verified against the reference C implementation (argon2-cffi).
        let pwd = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let params = kdf::Argon2Params { m_cost_kib: 32, t_cost: 3, p_cost: 4 };
        let key = kdf::argon2id_key(&pwd, &salt, &params).unwrap();
        assert_eq!(
            hx(&*key),
            "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e"
        );
    }

    #[test]
    fn pbkdf2_rejects_low_iterations() {
        let err = kdf::pbkdf2_sha256_key(b"pw", b"0123456789abcdef", &kdf::Pbkdf2Params { iterations: 1000 }).unwrap_err();
        assert_eq!(err.code(), "EKDF-004");
    }

    // ---------- signatures / exchange (known vectors) ----------

    #[test]
    fn ed25519_rfc8032_test_vector_1() {
        // RFC 8032 TEST 1: empty message.
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let mut s = [0u8; 32];
        s.copy_from_slice(&seed);
        let sk = sign::SigningKey::from_seed(s).unwrap();
        assert_eq!(hx(&sk.public_bytes()), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = sk.sign(b"").unwrap();
        assert_eq!(hx(&sig), concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert!(sign::verify(b"", &sig, &sk.public_bytes()).is_ok());
        // Tampered message must fail.
        assert!(sign::verify(b"x", &sig, &sk.public_bytes()).is_err());
    }

    #[test]
    fn x25519_rfc7748_dh_vector() {
        let alice_priv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        let mut ap = [0u8; 32];
        ap.copy_from_slice(&alice_priv);
        let alice = exch::ExchangeSecret::from_bytes(ap);
        assert_eq!(hx(&alice.public_bytes()), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let mut bp = [0u8; 32];
        bp.copy_from_slice(&bob_pub);
        let shared = alice.diffie_hellman(&bp).unwrap();
        assert_eq!(hx(&*shared), expected);
    }

    // ---------- encodings ----------

    #[test]
    fn base64_and_hex_round_trip() {
        let data = b"HEXA encoding test \x00\xff\x10";
        assert_eq!(encoding::base64_decode(&encoding::base64_encode(data)).unwrap(), data);
        assert_eq!(encoding::base64url_decode(&encoding::base64url_encode(data)).unwrap(), data);
        assert_eq!(encoding::hex_decode(&encoding::hex_encode(data)).unwrap(), data);
        assert!(encoding::hex_decode("0").is_err());
        assert!(encoding::hex_decode("zz").is_err());
    }

    // ---------- .hexa container: round trip + one-time key ----------

    #[test]
    fn round_trip_single_layer_raw_key() {
        let pt = b"attack at dawn";
        let (file, mut handle) = cipher::encrypt_with_generated_key(pt, 1, AeadId::Aes256Gcm, "round-trip", &LayerPolicy::default()).unwrap();
        let shown = handle.display_once().unwrap();
        assert!(shown.starts_with("HX-"));
        let key = key::parse_display(&shown).unwrap();
        let out = decrypt_bytes(&file, &KeySource::RawKey(key.to_vec())).unwrap();
        assert_eq!(out.as_slice(), pt);
        // The same handle cannot display again.
        let err = handle.display_once().unwrap_err();
        assert_eq!(err.code(), "EKEY-004");
        assert_eq!(err, key::recovery_refused());
    }

    #[test]
    fn round_trip_password_and_layers() {
        let pt = vec![42u8; 10_000];
        let file = encrypt_layers(
            &pt,
            KeySource::Password(b"correct horse battery staple".to_vec()),
            3,
            AeadId::ChaCha20Poly1305,
            "k=v;notes=ok",
            &LayerPolicy::default(),
        ).unwrap();
        let parsed = format::parse(&file).unwrap();
        assert_eq!(parsed.layer_count, 3);
        assert_eq!(parsed.metadata, "k=v;notes=ok");
        assert_eq!(parsed.kdf, Some(kdf::KdfId::Argon2id));
        let out = decrypt_bytes(&file, &KeySource::Password(b"correct horse battery staple".to_vec())).unwrap();
        assert_eq!(out.as_slice(), &pt);
    }

    #[test]
    fn layer_keys_are_independent() {
        // Two encryptions of the same plaintext with the same key must differ
        // (fresh nonces and salts) and never reuse a key across layers.
        let pt = b"same plaintext";
        let a = encrypt_layers(pt, KeySource::Password(b"pw".to_vec()), 2, AeadId::Aes256Gcm, "", &LayerPolicy::default()).unwrap();
        let b = encrypt_layers(pt, KeySource::Password(b"pw".to_vec()), 2, AeadId::Aes256Gcm, "", &LayerPolicy::default()).unwrap();
        assert_ne!(a, b);
        let pa = format::parse(&a).unwrap();
        assert_ne!(pa.layers[0].nonce, pa.layers[1].nonce);
    }

    // ---------- .hexa container: malformed input must fail safely ----------

    fn sample_file() -> Vec<u8> {
        encrypt_layers(
            b"secret payload",
            KeySource::RawKey(vec![7u8; 32]),
            2,
            AeadId::Aes256Gcm,
            "meta",
            &LayerPolicy::default(),
        ).unwrap()
    }

    #[test]
    fn wrong_key_fails_generically() {
        let file = sample_file();
        let err = decrypt_bytes(&file, &KeySource::RawKey(vec![8u8; 32])).unwrap_err();
        assert_eq!(err, CryptoError::auth_failed());
    }

    #[test]
    fn wrong_password_fails_generically() {
        let file = encrypt_layers(b"x", KeySource::Password(b"right".to_vec()), 1, AeadId::Aes256Gcm, "", &LayerPolicy::default()).unwrap();
        let err = decrypt_bytes(&file, &KeySource::Password(b"wrong".to_vec())).unwrap_err();
        assert_eq!(err, CryptoError::auth_failed());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut file = sample_file();
        let n = file.len();
        file[n - 20] ^= 0x01; // flip a byte inside the payload
        assert!(decrypt_bytes(&file, &KeySource::RawKey(vec![7u8; 32])).is_err());
    }

    #[test]
    fn tampered_header_fails() {
        let mut file = sample_file();
        file[34] ^= 0x01; // flip a salt byte (headers are AAD on every layer)
        assert!(decrypt_bytes(&file, &KeySource::RawKey(vec![7u8; 32])).is_err());
    }

    #[test]
    fn truncated_file_fails_safely() {
        // Spec §50: truncated or malformed .hexa files must never crash.
        // A cut in the header region fails to parse; a cut in the payload
        // region may parse but MUST fail authentication on decrypt.
        let file = sample_file();
        for cut in [1usize, 5, 30, 100, file.len() / 2, file.len() - 1] {
            let result = format::parse(&file[..cut]);
            match result {
                Err(_) => {}
                Ok(parsed) => {
                    let dec = cipher::decrypt_file(&parsed, &KeySource::RawKey(vec![7u8; 32]));
                    assert!(dec.is_err(), "truncated file at {} must not decrypt", cut);
                }
            }
        }
    }

    #[test]
    fn garbage_and_wrong_magic_fail() {
        assert!(format::parse(b"").is_err());
        assert!(format::parse(b"not a hexa file at all").is_err());
        let mut f = sample_file();
        f[0] = b'X';
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-001");
    }

    #[test]
    fn unknown_algorithm_and_kdf_ids_fail() {
        // Header: magic(6) ver(7) flags(8) algo(9) kdf(10) saltlen(11)
        // nonce(12..24) layers(24..28) metalen(28..32) kdfparam(32..36).
        let mut f = sample_file();
        f[8] = 0xFE; // algorithm id
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-004");
        let mut f = sample_file();
        f[9] = 0x7F; // kdf id
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-004");
        let mut f = sample_file();
        f[7] = 0x00; // flags: authenticated bit cleared
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-003");
    }

    #[test]
    fn oversized_layer_count_fails() {
        let mut f = sample_file();
        f[23..27].copy_from_slice(&u32::MAX.to_be_bytes()); // layer_count
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-007");
        f[23..27].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-007");
    }

    #[test]
    fn invalid_metadata_utf8_fails() {
        let mut f = sample_file();
        let meta_start = 35 + f[10] as usize; // header + salt
        f[meta_start + 1] = 0xFF; // corrupt the metadata bytes
        assert_eq!(format::parse(&f).unwrap_err().code(), "EHEX-006");
    }

    #[test]
    fn layer_policy_blocks_extreme_counts() {
        let err = encrypt_layers(
            b"x",
            KeySource::RawKey(vec![1u8; 32]),
            167_293,
            AeadId::Aes256Gcm,
            "",
            &LayerPolicy::default(),
        ).unwrap_err();
        assert_eq!(err.code(), "ECRYPT-001");
    }

    #[test]
    fn zero_layers_rejected() {
        assert!(encrypt_layers(b"x", KeySource::RawKey(vec![1u8; 32]), 0, AeadId::Aes256Gcm, "", &LayerPolicy::default()).is_err());
    }

    #[test]
    fn key_source_mismatch_is_explicit() {
        let file = sample_file(); // raw-key file
        let err = decrypt_bytes(&file, &KeySource::Password(b"pw".to_vec())).unwrap_err();
        assert_eq!(err.code(), "EKEY-001");
    }

    // ---------- one-time key lifecycle ----------

    #[test]
    fn one_time_key_display_exactly_once() {
        let mut gk = key::GeneratedKey::generate().unwrap();
        assert!(gk.display_available());
        let shown = gk.display_once().unwrap();
        assert!(shown.starts_with("HX-") && shown.len() > 40);
        assert!(!gk.display_available());
        assert_eq!(gk.display_once().unwrap_err().code(), "EKEY-004");
        // The displayed key parses back to working key material.
        let parsed = key::parse_display(&shown).unwrap();
        assert_eq!(parsed.len(), 32);
        // But a *new* attempt through any API never recovers the first key.
        let second = key::GeneratedKey::generate().unwrap();
        let mut second = second;
        assert_ne!(second.display_once().unwrap(), shown);
    }

    #[test]
    fn key_bit_validation() {
        assert!(key::validate_key_bits(256).is_ok());
        assert!(key::validate_key_bits(128).is_ok());
        assert!(key::validate_key_bits(1234).is_err());
        assert_eq!(key::generate_symmetric(256).unwrap().len(), 32);
        assert!(key::generate_symmetric(0).is_err());
    }

    // ---------- secret memory ----------

    #[test]
    fn secret_redacts_and_destroys() {
        let mut s = secret::Secret::create(vec![1u8, 2, 3]);
        assert_eq!(format!("{:?}", s), "Secret(REDACTED)");
        assert_eq!(format!("{}", s), "REDACTED");
        assert_eq!(s.use_value(|v| v.len()), 3);
        s.destroy();
        assert!(s.is_destroyed());
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(secret::ct_eq(b"abc", b"abc"));
        assert!(!secret::ct_eq(b"abc", b"abd"));
        assert!(!secret::ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn cost_estimator_warns_on_extreme_layers() {
        let (secs, warns) = cipher::estimate_cost(167_293, 1_000_000);
        assert!(secs > 30.0);
        assert!(!warns.is_empty());
        let (small, w2) = cipher::estimate_cost(1, 100);
        assert!(small < 1.0);
        assert!(w2.is_empty());
    }

    // ---------- deterministic full-format vectors (Phase 2) ----------
    // Cross-implementation regression pins generated by tests/reference/
    // (independent Python oracle) and stored in
    // tests/vectors/crypto-vectors.json. All inputs are fixed test data
    // (never real secrets). These tests pass if and only if the file bytes
    // produced with fixed key/salt/nonce parse and decrypt exactly.

    fn vector_aes_hello() -> Vec<u8> {
        hex(concat!(
            "48455841310a010101001018191a1b1c1d1e1f20212223000000010000002c00",
            "000000000102030405060708090a0b0c0d0e0f763d313b616c676f3d61657332",
            "35362d67636d3b6c61796572733d313b6f726967696e616c5f73697a653d3501",
            "0c0d0e0f10111213141516170a4f6befe6971c1b191e5a555821cf43bde94b81",
            "be48455841454e4431",
        ))
    }

    fn vector_chacha_hello() -> Vec<u8> {
        hex(concat!(
            "48455841310a010102001018191a1b1c1d1e1f20212223000000010000003300",
            "000000000102030405060708090a0b0c0d0e0f763d313b616c676f3d63686163",
            "686132302d706f6c79313330353b6c61796572733d313b6f726967696e616c5f",
            "73697a653d35020c0d0e0f10111213141516178b6e44bc04552da7a0a8b0f77e",
            "7c205fe80b9bc9aa48455841454e4431",
        ))
    }

    #[test]
    fn vector_aes256gcm_hello_parses_and_decrypts() {
        let file = vector_aes_hello();
        let parsed = format::parse(&file).unwrap();
        assert_eq!(parsed.format_version, 1);
        assert_eq!(parsed.algorithm, AeadId::Aes256Gcm);
        assert_eq!(parsed.kdf, None);                       // raw-key file
        assert_eq!(parsed.layer_count, 1);
        assert_eq!(parsed.layers[0].algorithm, AeadId::Aes256Gcm);
        assert_eq!(parsed.layers[0].nonce.len(), 12);
        // The fixed test key is bytes 00..1f (see tests/vectors/README).
        let key = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                       16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
        let plain = cipher::decrypt_bytes(&file, &KeySource::RawKey(key)).unwrap();
        assert_eq!(String::from_utf8(plain.as_slice().to_vec()).unwrap().as_str(), "hello");
    }

    #[test]
    fn vector_chacha20poly1305_hello_parses_and_decrypts() {
        let file = vector_chacha_hello();
        let parsed = format::parse(&file).unwrap();
        assert_eq!(parsed.algorithm, AeadId::ChaCha20Poly1305);
        let key = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                       16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
        let plain = cipher::decrypt_bytes(&file, &KeySource::RawKey(key)).unwrap();
        assert_eq!(String::from_utf8(plain.as_slice().to_vec()).unwrap().as_str(), "hello");
    }

    #[test]
    fn vector_wrong_key_rejected() {
        let file = vector_aes_hello();
        // Same file, deliberately wrong 32-byte key: generic auth failure.
        let err = cipher::decrypt_bytes(&file, &KeySource::RawKey(vec![8u8; 32])).unwrap_err();
        assert_eq!(err.code(), "EKEY-003");
    }

    #[test]
    fn vector_tampered_file_rejected() {
        // (a) flip one byte of the AEAD tag (trailer is the last 8 bytes);
        // (b) flip one metadata byte (metadata is AAD on every layer).
        let key = || {
            vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        };
        let mut f = vector_aes_hello();
        let last = f.len() - 9;
        f[last] ^= 0x01;
        assert!(cipher::decrypt_bytes(&f, &KeySource::RawKey(key())).is_err());
        let mut g = vector_aes_hello();
        g[35 + 16] ^= 0x01; // first metadata byte (offset 35 + salt_len 16)
        assert!(cipher::decrypt_bytes(&g, &KeySource::RawKey(key())).is_err());
    }

    #[test]
    fn vector_truncated_file_rejected() {
        let key = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                       16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
        let file = vector_aes_hello();
        let cuts = [1usize, 14, 50, file.len() - 9, file.len() - 4];
        for cut in cuts {
            let result = format::parse(&file[..cut]);
            match result {
                Err(_) => {}
                Ok(parsed) => assert!(
                    cipher::decrypt_file(&parsed, &KeySource::RawKey(key.clone())).is_err(),
                    "truncated vector file at {} must not decrypt",
                    cut
                ),
            }
        }
    }
}
