use std::collections::HashMap;

use cru_iap::reasons::DEV_BYPASS;
use cru_iap::{
    CLOUD_MARKERS, DEV_BYPASS_EMAIL_VAR, DEV_BYPASS_NAME_VAR, Identity, dev_bypass_with,
};

fn bypass(env: &[(&str, &str)]) -> Option<Identity> {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    dev_bypass_with(|name| env.get(name).cloned())
}

#[test]
fn unset_means_no_bypass() {
    assert_eq!(bypass(&[]), None);
    assert_eq!(bypass(&[(DEV_BYPASS_EMAIL_VAR, "  ")]), None);
}

#[test]
fn names_the_developer() {
    let identity = bypass(&[
        (DEV_BYPASS_EMAIL_VAR, " You@Cru.org "),
        (DEV_BYPASS_NAME_VAR, " You "),
    ])
    .unwrap();
    assert_eq!(identity.email, "you@cru.org");
    assert_eq!(identity.name.as_deref(), Some("You"));
    assert_eq!(identity.reason, DEV_BYPASS);
    assert_eq!(identity.payload, None);
}

#[test]
fn a_blank_name_is_none() {
    assert_eq!(
        bypass(&[(DEV_BYPASS_EMAIL_VAR, "you@cru.org")])
            .unwrap()
            .name,
        None
    );
}

#[test]
fn refuses_when_an_audience_is_configured() {
    assert_eq!(
        bypass(&[
            (DEV_BYPASS_EMAIL_VAR, "you@cru.org"),
            ("IAP_AUDIENCE", "/projects/1/x")
        ]),
        None
    );
}

#[test]
fn refuses_in_every_managed_runtime() {
    for marker in CLOUD_MARKERS {
        assert_eq!(
            bypass(&[(DEV_BYPASS_EMAIL_VAR, "you@cru.org"), (marker, "anything")]),
            None,
            "{marker}"
        );
    }
}

#[test]
fn refuses_what_is_not_an_address() {
    for raw in [
        "you",
        "you@cru",
        "sts.google.com:you@cru.org",
        "principal://x/subject/you@cru.org",
        "a b@cru.org",
    ] {
        assert_eq!(bypass(&[(DEV_BYPASS_EMAIL_VAR, raw)]), None, "{raw}");
    }
}
