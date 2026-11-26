//! Message-level tests: spec examples, strictness, roundtrip and mutation properties.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use proptest::prelude::*;
use serde_json::{Value, json};

use crate::*;

fn dec_host(v: &Value) -> Result<HostMessage, Error> {
    decode_host_message(&serde_json::to_vec(v).unwrap())
}
fn dec_helper(v: &Value) -> Result<HelperMessage, Error> {
    decode_helper_message(&serde_json::to_vec(v).unwrap())
}

fn identity_json() -> Value {
    json!({"proto": "ssh", "user": "user", "host": "homelab", "port": null, "path": null, "index": 0})
}

// ---------------------------------------------------------------------------------------
// Spec examples
// ---------------------------------------------------------------------------------------

#[test]
fn spec_examples_decode() {
    let cred = "AAECAw==";
    let hello = dec_host(
        &json!({"type": "hello", "version": 1, "app_name": "petschaft",
        "host_name": "mac", "transport": "auto", "credential": cred}),
    )
    .unwrap();
    match hello {
        HostMessage::Hello(h) => {
            assert_eq!(h.credential.unwrap().as_bytes(), &[0, 1, 2, 3]);
            assert_eq!(h.transport, Transport::Auto);
        }
        other => panic!("{other:?}"),
    }
    dec_host(&json!({"type": "pairing_code", "code": "620567"})).unwrap();
    let sign = dec_host(
        &json!({"type": "sign_identity", "id": 1, "identity": identity_json(),
        "curve": "ed25519", "challenge_hidden": "AAEC", "challenge_visual": "pets: Login homelab",
        "passphrase": "standard"}),
    )
    .unwrap();
    assert!(matches!(sign, HostMessage::SignIdentity(ref s) if s.challenge_hidden == [0, 1, 2]));

    dec_helper(&json!({"type": "event", "event": "button"})).unwrap();
    dec_helper(&json!({"type": "event", "event": "pairing_code_required"})).unwrap();
    dec_helper(&json!({"type": "ready",
        "device": {"model": "Safe 7", "internal_model": "T3W1", "firmware": "2.13.1",
                   "passphrase_protection": true},
        "credential": cred}))
    .unwrap();
    dec_helper(
        &json!({"type": "signed", "id": 1, "public_key": b64(&[0; 33]),
        "signature": b64(&[0; 65])}),
    )
    .unwrap();
    dec_helper(&json!({"type": "error", "id": 1, "code": "cancelled",
        "message": "rejected on device", "fatal": false}))
    .unwrap();
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------------------
// Strictness
// ---------------------------------------------------------------------------------------

#[test]
fn rejects_unknown_type_and_fields() {
    assert!(dec_helper(&json!({"type": "bogus"})).is_err());
    assert!(dec_helper(&json!({"event": "button"})).is_err());
    assert!(dec_helper(&json!({"type": "event", "event": "button", "extra": 1})).is_err());
    assert!(dec_helper(&json!({"type": "event", "event": "dance"})).is_err());
    // Host messages are not helper messages and vice versa.
    assert!(dec_helper(&json!({"type": "pairing_code", "code": "123456"})).is_err());
    assert!(dec_host(&json!({"type": "event", "event": "button"})).is_err());
    // Unknown field in a nested object.
    let mut id = identity_json();
    id["extra"] = json!(1);
    assert!(
        dec_host(&json!({"type": "sign_identity", "id": 1, "identity": id,
        "curve": "ed25519", "challenge_hidden": "", "challenge_visual": "", "passphrase": "ask"}))
        .is_err()
    );
    let ready = json!({"type": "ready", "credential": null,
        "device": {"model": "m", "internal_model": "i", "firmware": "f",
                   "passphrase_protection": false, "serial": "x"}});
    assert!(dec_helper(&ready).is_err());
}

#[test]
fn rejects_unknown_error_code() {
    let e = json!({"type": "error", "id": null, "code": "oops", "message": "", "fatal": true});
    assert!(dec_helper(&e).is_err());
}

#[test]
fn null_fields_must_be_present() {
    // `credential: null` is fine, a missing `credential` is not.
    assert!(
        dec_host(
            &json!({"type": "hello", "version": 1, "app_name": "a", "host_name": "b",
        "transport": "usb", "credential": null})
        )
        .is_ok()
    );
    assert!(
        dec_host(
            &json!({"type": "hello", "version": 1, "app_name": "a", "host_name": "b",
        "transport": "usb"})
        )
        .is_err()
    );
    assert!(
        dec_helper(&json!({"type": "error", "code": "internal", "message": "", "fatal": true}))
            .is_err()
    );
    let mut id = identity_json();
    id.as_object_mut().unwrap().remove("port");
    assert!(
        dec_host(&json!({"type": "sign_identity", "id": 1, "identity": id,
        "curve": "ed25519", "challenge_hidden": "", "challenge_visual": "", "passphrase": "ask"}))
        .is_err()
    );
}

#[test]
fn framing_level_rejections() {
    assert!(matches!(
        decode_helper_message(b"[\"event\", \"button\"]"),
        Err(Error::NotAnObject)
    ));
    assert!(matches!(
        decode_helper_message(b"\"x\""),
        Err(Error::NotAnObject)
    ));
    assert!(matches!(
        decode_helper_message(b"{\"type\":\"event\",\"event\":\"button\"} {}"),
        Err(Error::Json { .. })
    ));
    assert!(matches!(
        decode_helper_message(b"{\"type\":\"event\",\"event\":\"button\",\"event\":\"button\"}"),
        Err(Error::Json { .. })
    ));
    assert!(matches!(
        decode_helper_message(b"{\"type\":\"event\",\"type\":\"event\",\"event\":\"button\"}"),
        Err(Error::Json { .. })
    ));
    assert!(matches!(
        decode_helper_message(b"{\"type\":\"event\",\"event\":\"\xff\"}"),
        Err(Error::InvalidUtf8)
    ));
    // Whitespace around the object is part of the JSON grammar and accepted.
    assert!(decode_helper_message(b" \n{\"type\":\"event\",\"event\":\"button\"}\n").is_ok());
}

#[test]
fn numbers_are_strict() {
    for id in [
        json!(0),
        json!(-1),
        json!(1.0),
        json!(4294967296u64),
        json!("1"),
    ] {
        let m = json!({"type": "signed", "id": id, "public_key": b64(&[0; 33]),
            "signature": b64(&[0; 65])});
        assert!(dec_helper(&m).is_err(), "{m}");
    }
    let hello = |v: Value| {
        json!({"type": "hello", "version": v, "app_name": "a", "host_name": "b",
        "transport": "usb", "credential": null})
    };
    assert!(dec_host(&hello(json!(2))).is_err());
    assert!(dec_host(&hello(json!(0))).is_err());
}

#[test]
fn base64_is_canonical_standard() {
    let signed =
        |pk: &str| json!({"type": "signed", "id": 1, "public_key": pk, "signature": b64(&[0; 65])});
    let good = b64(&[7; 33]);
    assert!(dec_helper(&signed(&good)).is_ok());
    // Unpadded, URL-safe alphabet, embedded whitespace, non-canonical trailing bits.
    let cred = |c: &str| {
        json!({"type": "ready", "credential": c, "device": {"model": "m",
        "internal_model": "i", "firmware": "f", "passphrase_protection": false}})
    };
    assert!(dec_helper(&cred("AAECAw==")).is_ok());
    for bad in [
        "AAECAw",
        "AAECAw=",
        "AA-_",
        "AAEC Aw==",
        "AAECAx==",
        "====",
        "@@@@",
    ] {
        assert!(dec_helper(&cred(bad)).is_err(), "{bad}");
    }
}

#[test]
fn credential_limits() {
    assert!(Credential::new(vec![]).is_err());
    assert!(Credential::new(vec![1; 4096]).is_ok());
    assert!(Credential::new(vec![1; 4097]).is_err());
    let ready = |n: usize| {
        json!({"type": "ready", "credential": b64(&vec![9u8; n]), "device": {"model": "m",
        "internal_model": "i", "firmware": "f", "passphrase_protection": false}})
    };
    assert!(dec_helper(&ready(4096)).is_ok());
    assert!(dec_helper(&ready(4097)).is_err());
    assert!(dec_helper(&ready(0)).is_err());
}

#[test]
fn always_fatal_codes() {
    for (code, must_be_fatal) in [
        ("bad_request", true),
        ("device_not_found", true),
        ("device_not_initialized", true),
        ("pairing_failed", true),
        ("internal", true),
        ("cancelled", false),
        ("passphrase_unavailable", false),
        ("device_error", false),
    ] {
        let e = |fatal: bool| json!({"type": "error", "id": null, "code": code, "message": "m", "fatal": fatal});
        assert!(dec_helper(&e(true)).is_ok(), "{code}");
        assert_eq!(dec_helper(&e(false)).is_ok(), !must_be_fatal, "{code}");
    }
}

#[test]
fn gpg_nist256p1_needs_32_byte_digest() {
    let mut id = identity_json();
    id["proto"] = json!("gpg");
    let m = |len: usize, curve: &str| {
        json!({"type": "sign_identity", "id": 1, "identity": id.clone(), "curve": curve,
        "challenge_hidden": b64(&vec![1u8; len]), "challenge_visual": "", "passphrase": "ask"})
    };
    assert!(dec_host(&m(32, "nist256p1")).is_ok());
    assert!(dec_host(&m(31, "nist256p1")).is_err());
    assert!(dec_host(&m(33, "nist256p1")).is_err());
    assert!(dec_host(&m(0, "nist256p1")).is_err());
    assert!(dec_host(&m(31, "ed25519")).is_ok());
}

#[test]
fn challenge_visual_rules() {
    assert!(validate::is_challenge_visual(""));
    assert!(validate::is_challenge_visual("pets: Login über Ünïcødé ✓"));
    assert!(validate::is_challenge_visual(&"ä".repeat(128)));
    assert!(!validate::is_challenge_visual(&"ä".repeat(129)));
    for bad in [
        "a\nb",
        "a\u{1b}[31m",
        "\u{7f}",
        "\u{85}",
        "x\u{202e}gpj.exe",
        "\u{200b}",
        "\u{2028}",
        "non\u{a0}breaking",
        "\u{e000}",
        "\u{10fffd}",
        "\u{ffff}",
        "\u{1fffe}",
        "\u{e0041}",
    ] {
        assert!(!validate::is_challenge_visual(bad), "{bad:?}");
    }
}

#[test]
fn debug_is_redacted() {
    let c = Credential::new(vec![0xAB; 16]).unwrap();
    let hello = HostMessage::Hello(Hello {
        version: 1,
        app_name: "petschaft".into(),
        host_name: "mac".into(),
        transport: Transport::Auto,
        credential: Some(c),
    });
    let s = format!("{hello:?}");
    assert!(
        !s.contains("171") && !s.contains("ab") && !s.contains("AB"),
        "{s}"
    );
    assert!(s.contains("redacted"));
    let code = PairingCode {
        code: "620567".into(),
    };
    assert!(!format!("{code:?}").contains("620567"));
}

#[test]
fn errors_do_not_echo_peer_data() {
    let secret = "U0VDUkVUU0VDUkVU";
    let cases = [
        json!({"type": "ready", "credential": secret, "device": secret}),
        json!({"type": secret}),
        json!({"type": "event", "event": secret}),
        json!({"type": "event", "event": "button", secret: 1}),
        json!({"type": "ready", "credential": format!("{secret}!"), "device": {"model": "m",
            "internal_model": "i", "firmware": "f", "passphrase_protection": false}}),
    ];
    for c in cases {
        let e = dec_helper(&c).unwrap_err().to_string();
        assert!(!e.contains(secret), "{e}");
    }
}

// ---------------------------------------------------------------------------------------
// Strategies for valid messages
// ---------------------------------------------------------------------------------------

fn token() -> impl Strategy<Value = String> {
    "[!-.0-9;-?A-~]{1,128}"
}
fn name() -> impl Strategy<Value = String> {
    "[!-~]{1,64}"
}
fn device_string() -> impl Strategy<Value = String> {
    "[ -~]{1,64}"
}
fn visual() -> impl Strategy<Value = String> {
    prop::collection::vec(
        any::<char>().prop_filter("display char", |c| {
            validate::is_challenge_visual(&c.to_string())
        }),
        0..=128,
    )
    .prop_map(|v| v.into_iter().collect())
}
fn credential() -> impl Strategy<Value = Credential> {
    prop::collection::vec(any::<u8>(), 1..=4096).prop_map(|v| Credential::new(v).unwrap())
}

fn identity() -> impl Strategy<Value = Identity> {
    (
        prop_oneof![Just(Proto::Ssh), Just(Proto::Gpg)],
        prop::option::of(token()),
        token(),
        prop::option::of("[0-9]{1,5}"),
        prop::option::of("/[!-?A-~]{0,127}"),
        any::<u32>(),
    )
        .prop_map(|(proto, user, host, port, path, index)| Identity {
            proto,
            user,
            host,
            port,
            path,
            index,
        })
}

fn sign_identity() -> impl Strategy<Value = SignIdentity> {
    (
        1..=u32::MAX,
        identity(),
        prop_oneof![Just(Curve::Ed25519), Just(Curve::Nist256p1)],
        prop::collection::vec(any::<u8>(), 0..=512),
        visual(),
        prop_oneof![Just(Passphrase::Standard), Just(Passphrase::Ask)],
    )
        .prop_map(
            |(id, identity, curve, mut challenge_hidden, challenge_visual, passphrase)| {
                if identity.proto == Proto::Gpg && curve == Curve::Nist256p1 {
                    challenge_hidden.resize(32, 0x5A);
                }
                SignIdentity {
                    id,
                    identity,
                    curve,
                    challenge_hidden,
                    challenge_visual,
                    passphrase,
                }
            },
        )
}

fn host_message() -> impl Strategy<Value = HostMessage> {
    prop_oneof![
        (
            name(),
            name(),
            prop_oneof![
                Just(Transport::Usb),
                Just(Transport::Ble),
                Just(Transport::Auto)
            ],
            prop::option::of(credential()),
        )
            .prop_map(|(app_name, host_name, transport, credential)| {
                HostMessage::Hello(Hello {
                    version: 1,
                    app_name,
                    host_name,
                    transport,
                    credential,
                })
            }),
        "[0-9]{6}".prop_map(|code| HostMessage::PairingCode(PairingCode { code })),
        sign_identity().prop_map(HostMessage::SignIdentity),
    ]
}

fn error_code() -> impl Strategy<Value = ErrorCode> {
    prop_oneof![
        Just(ErrorCode::BadRequest),
        Just(ErrorCode::DeviceNotFound),
        Just(ErrorCode::DeviceNotInitialized),
        Just(ErrorCode::PairingFailed),
        Just(ErrorCode::Cancelled),
        Just(ErrorCode::PassphraseUnavailable),
        Just(ErrorCode::DeviceError),
        Just(ErrorCode::Internal),
    ]
}

fn helper_message() -> impl Strategy<Value = HelperMessage> {
    prop_oneof![
        prop_oneof![
            Just(EventKind::Button),
            Just(EventKind::PairingCodeRequired)
        ]
        .prop_map(|event| HelperMessage::Event(Event { event })),
        (
            device_string(),
            device_string(),
            device_string(),
            any::<bool>(),
            prop::option::of(credential())
        )
            .prop_map(
                |(model, internal_model, firmware, passphrase_protection, credential)| {
                    HelperMessage::Ready(Ready {
                        device: DeviceInfo {
                            model,
                            internal_model,
                            firmware,
                            passphrase_protection,
                        },
                        credential,
                    })
                }
            ),
        (
            1..=u32::MAX,
            prop::collection::vec(any::<u8>(), 33),
            prop::collection::vec(any::<u8>(), 65)
        )
            .prop_map(|(id, public_key, signature)| HelperMessage::Signed(Signed {
                id,
                public_key,
                signature
            })),
        (
            prop::option::of(1..=u32::MAX),
            error_code(),
            prop::collection::vec(any::<char>(), 0..=256),
            any::<bool>()
        )
            .prop_map(
                |(id, code, message, fatal)| HelperMessage::Error(ErrorResponse {
                    id,
                    code,
                    message: message.into_iter().collect(),
                    fatal: fatal || code.always_fatal(),
                })
            ),
    ]
}

// ---------------------------------------------------------------------------------------
// Mutations: each produces a message violating exactly one rule.
// ---------------------------------------------------------------------------------------

fn bad_token() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        "[!-.0-9;-?A-~]{129,200}",
        "[!-.0-9;-?A-~]{0,10}[/@: \\x00\\x7fé][!-.0-9;-?A-~]{0,10}",
    ]
}

#[derive(Debug, Clone)]
enum SignMutation {
    Id0,
    User(String),
    Host(String),
    Port(String),
    Path(String),
    ChallengeTooLong(usize),
    GpgNistWrongLen(usize),
    Visual(String),
}

fn sign_mutation() -> impl Strategy<Value = SignMutation> {
    prop_oneof![
        Just(SignMutation::Id0),
        bad_token().prop_map(SignMutation::User),
        bad_token().prop_map(SignMutation::Host),
        prop_oneof![
            Just(String::new()),
            "[0-9]{6,8}",
            "[0-9]{0,2}[a-z +-][0-9]{0,2}"
        ]
        .prop_map(SignMutation::Port),
        prop_oneof![
            Just(String::new()),
            "[!-.0-~][!-?A-~]{0,20}",
            "/[!-?A-~]{0,10}[@ \\n][!-?A-~]{0,10}",
            "/[!-?A-~]{128,140}"
        ]
        .prop_map(SignMutation::Path),
        (513usize..2000).prop_map(SignMutation::ChallengeTooLong),
        (0usize..512)
            .prop_filter("not 32", |n| *n != 32)
            .prop_map(SignMutation::GpgNistWrongLen),
        prop_oneof![
            "[a-z]{0,5}[\\x00-\\x1f\\x7f-\\x{9f}\\x{202a}-\\x{202e}][a-z]{0,5}",
            "[a-zä]{129,140}"
        ]
        .prop_map(SignMutation::Visual),
    ]
}

fn apply(m: &mut SignIdentity, mutation: SignMutation) {
    match mutation {
        SignMutation::Id0 => m.id = 0,
        SignMutation::User(s) => m.identity.user = Some(s),
        SignMutation::Host(s) => m.identity.host = s,
        SignMutation::Port(s) => m.identity.port = Some(s),
        SignMutation::Path(s) => m.identity.path = Some(s),
        SignMutation::ChallengeTooLong(n) => m.challenge_hidden = vec![0; n],
        SignMutation::GpgNistWrongLen(n) => {
            m.identity.proto = Proto::Gpg;
            m.curve = Curve::Nist256p1;
            m.challenge_hidden = vec![0; n];
        }
        SignMutation::Visual(s) => m.challenge_visual = s,
    }
}

/// Encoding must refuse, and a peer that skips validation must be rejected on decode.
fn assert_rejected_both_ways_host(msg: &HostMessage) -> Result<(), TestCaseError> {
    prop_assert!(encode_host_message(msg).is_err());
    let raw = serde_json::to_vec(msg).unwrap();
    prop_assert!(decode_host_message(&raw).is_err());
    Ok(())
}
fn assert_rejected_both_ways_helper(msg: &HelperMessage) -> Result<(), TestCaseError> {
    prop_assert!(encode_helper_message(msg).is_err());
    let raw = serde_json::to_vec(msg).unwrap();
    prop_assert!(decode_helper_message(&raw).is_err());
    Ok(())
}

proptest! {
    #[test]
    fn host_roundtrip(msg in host_message()) {
        let mut stream = Vec::new();
        write_host_message(&mut stream, &msg).unwrap();
        let mut cur = std::io::Cursor::new(stream);
        prop_assert_eq!(read_host_message(&mut cur).unwrap().unwrap(), msg);
        prop_assert!(read_host_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn helper_roundtrip(msg in helper_message()) {
        let bytes = encode_helper_message(&msg).unwrap();
        prop_assert_eq!(decode_helper_message(&bytes).unwrap(), msg);
    }

    #[test]
    fn decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = decode_host_message(&bytes);
        let _ = decode_helper_message(&bytes);
        let mut cur = std::io::Cursor::new(&bytes);
        while let Ok(Some(_)) = read_helper_message(&mut cur) {}
    }

    #[test]
    fn json_shaped_garbage_never_panics(
        key in "[a-z_]{1,22}",
        val in prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            any::<i64>().prop_map(Value::from),
            any::<f64>().prop_map(Value::from),
            ".{0,40}".prop_map(Value::from),
        ],
        ty in prop_oneof![Just("hello"), Just("ready"), Just("signed"), Just("error"),
                          Just("event"), Just("sign_identity"), Just("pairing_code")],
    ) {
        let v = json!({"type": ty, key: val});
        let bytes = serde_json::to_vec(&v).unwrap();
        prop_assert!(decode_host_message(&bytes).is_err());
        prop_assert!(decode_helper_message(&bytes).is_err());
    }

    #[test]
    fn sign_identity_mutations_rejected(base in sign_identity(), mutation in sign_mutation()) {
        let mut m = base;
        apply(&mut m, mutation);
        assert_rejected_both_ways_host(&HostMessage::SignIdentity(m))?;
    }

    #[test]
    fn hello_mutations_rejected(
        app in name(),
        which in 0u8..5,
        bad_name in prop_oneof![Just(String::new()), "[!-~]{65,80}", "[a-z]{0,3}[\\x00-\\x20\\x7fé][a-z]{0,3}"],
        version in (0u32..).prop_filter("not 1", |v| *v != 1),
        cred_len in prop_oneof![Just(0usize), 4097usize..5000],
    ) {
        let mut h = Hello { version: 1, app_name: app.clone(), host_name: app,
            transport: Transport::Ble, credential: None };
        match which {
            0 => h.version = version,
            1 => h.app_name = bad_name,
            2 => h.host_name = bad_name,
            // Bypass the validating constructor to build an out-of-range credential.
            _ => h.credential = Some(serde_json::from_value(json!(b64(&vec![1u8; cred_len]))).unwrap()),
        }
        assert_rejected_both_ways_host(&HostMessage::Hello(h))?;
    }

    #[test]
    fn pairing_code_mutations_rejected(code in prop_oneof![
        "[0-9]{0,5}", "[0-9]{7,10}", "[0-9]{0,3}[^0-9][0-9]{0,2}",
    ].prop_filter("not 6 digits", |c| !validate::is_pairing_code(c))) {
        assert_rejected_both_ways_host(&HostMessage::PairingCode(PairingCode { code }))?;
    }

    #[test]
    fn helper_mutations_rejected(
        base in helper_message(),
        bad_len in prop_oneof![0usize..33, 34usize..100],
        long_msg in "[a-z]{257,300}",
        bad_dev in prop_oneof![Just(String::new()), "[ -~]{65,80}", "[a-z]{0,3}[\\x00-\\x1fä][a-z]{0,3}"],
        field in 0u8..3,
    ) {
        let mut m = base;
        match &mut m {
            HelperMessage::Event(_) => return Ok(()),
            HelperMessage::Ready(r) => match field {
                0 => r.device.model = bad_dev,
                1 => r.device.internal_model = bad_dev,
                _ => r.device.firmware = bad_dev,
            },
            HelperMessage::Signed(s) => match field {
                0 => s.id = 0,
                1 => s.public_key = vec![2; bad_len],
                _ => s.signature = vec![0; bad_len + 32],
            },
            HelperMessage::Error(e) => match field {
                0 => e.id = Some(0),
                1 => e.message = long_msg,
                _ => { e.code = ErrorCode::Internal; e.fatal = false; }
            },
        }
        assert_rejected_both_ways_helper(&m)?;
    }
}
