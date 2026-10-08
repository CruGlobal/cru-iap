//! The cross-language check that the rejection vocabulary and the IAP control
//! queries have not drifted. This suite compares all four siblings against
//! Rust's lists, so whichever language a contributor adds a reason in, at
//! least one suite goes red until the others catch up.

use cru_iap::reasons::{self, REASONS};
use cru_iap::{HEADER, IAP_JWKS_URL, LOGIN_QUERY, LOGOUT_QUERY, is_known_reason};
use regex::Regex;

use crate::support::{Signer, iap_claims, reason, repo_file, verify_with};

fn quoted_in_block(source: &str, pattern: &str) -> Vec<String> {
    let block = Regex::new(pattern)
        .unwrap()
        .captures(source)
        .unwrap_or_else(|| panic!("no REASONS block for {pattern}"));
    Regex::new(r#""([^"]+)""#)
        .unwrap()
        .captures_iter(&block[1])
        .map(|quoted| quoted[1].to_string())
        .collect()
}

fn assert_same_vocabulary(language: &str, theirs: Vec<String>) {
    assert_eq!(
        theirs, REASONS,
        "{language}'s reasons have drifted from Rust's"
    );
}

#[test]
fn matches_the_ruby_gem() {
    let source = repo_file("lib/cru_iap/token_verifier.rb");
    assert_same_vocabulary(
        "Ruby",
        quoted_in_block(&source, r"(?s)REASONS = \[(.*?)\]\.freeze"),
    );
}

#[test]
fn matches_the_typescript_package() {
    let source = repo_file("src/reasons.ts");
    assert_same_vocabulary(
        "TypeScript",
        quoted_in_block(&source, r"(?s)export const REASONS = \[(.*?)\] as const;"),
    );
}

#[test]
fn matches_the_python_package() {
    let source = repo_file("cru_iap/reasons.py");
    assert_same_vocabulary(
        "Python",
        quoted_in_block(&source, r"(?s)REASONS: tuple\[str, \.\.\.\] = \((.*?)\n\)"),
    );
}

#[test]
fn matches_the_go_package() {
    // Go's list holds constant names, so resolve each through its const block.
    let source = repo_file("cruiap/reasons.go");
    let names = Regex::new(r"(?s)var Reasons = \[\]string\{(.*?)\}")
        .unwrap()
        .captures(&source)
        .unwrap()[1]
        .to_string();
    let theirs = Regex::new(r"Reason\w+")
        .unwrap()
        .find_iter(&names)
        .map(|name| {
            let constant =
                Regex::new(&format!(r#"(?m)^\s*{} = "([^"]+)""#, name.as_str())).unwrap();
            constant
                .captures(&source)
                .unwrap_or_else(|| panic!("no const for {}", name.as_str()))[1]
                .to_string()
        })
        .collect();
    assert_same_vocabulary("Go", theirs);
}

#[test]
fn the_iap_control_queries_match_across_languages() {
    for (language, file, login, logout) in [
        (
            "Ruby",
            "lib/cru_iap/urls.rb",
            r#"LOGIN_QUERY = "([^"]+)""#,
            r#"LOGOUT_QUERY = "([^"]+)""#,
        ),
        (
            "TypeScript",
            "src/urls.ts",
            r#"LOGIN_QUERY = "([^"]+)""#,
            r#"LOGOUT_QUERY = "([^"]+)""#,
        ),
        (
            "Python",
            "cru_iap/urls.py",
            r#"LOGIN_QUERY = "([^"]+)""#,
            r#"LOGOUT_QUERY = "([^"]+)""#,
        ),
        (
            "Go",
            "cruiap/urls.go",
            r#"LoginQuery = "([^"]+)""#,
            r#"LogoutQuery = "([^"]+)""#,
        ),
    ] {
        let source = repo_file(file);
        for (pattern, want) in [(login, LOGIN_QUERY), (logout, LOGOUT_QUERY)] {
            let found = &Regex::new(pattern)
                .unwrap()
                .captures(&source)
                .unwrap_or_else(|| panic!("{pattern} not in {file}"))[1];
            assert_eq!(found, want, "{language}");
        }
    }
}

#[test]
fn is_known_reason_accepts_the_list_and_suffixes_only() {
    assert!(REASONS.iter().all(|known| is_known_reason(known)));
    assert!(is_known_reason("signature_error:whatever the library said"));
    assert!(!is_known_reason("something_invented"));
    assert!(!is_known_reason("iap_jwt:suffixed"));
}

#[tokio::test]
async fn bad_iss_is_reachable_only_behind_the_library_check() {
    let signer = Signer::new();
    for iss in ["", "https://evil.example", "https://accounts.google.com"] {
        let result = verify_with(&signer, iap_claims(serde_json::json!({ "iss": iss }))).await;
        assert_eq!(reason(&result), reasons::ISSUER_MISMATCH, "iss {iss:?}");
    }
}

#[test]
fn the_jwks_url_is_the_jwk_endpoint_not_the_pem_one() {
    assert!(IAP_JWKS_URL.ends_with("-jwk"));
}

#[test]
fn the_wire_header_name_is_what_infra_expects() {
    assert!(HEADER.eq_ignore_ascii_case("X-Goog-Iap-Jwt-Assertion"));
}
