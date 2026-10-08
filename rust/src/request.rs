use http::HeaderMap;

/// The header IAP injects. Exposed for infra config and test fixtures;
/// application code should call `verify_request` rather than name it.
pub const HEADER: &str = "x-goog-iap-jwt-assertion";

/// The raw assertion carried by `headers`, or `None`.
///
/// A repeated header is treated as absent rather than resolved to one of the
/// values: two assertions is not a shape IAP produces, so guessing which to
/// trust would be worse than failing closed. Same for a value that is not
/// visible ASCII.
pub fn assertion_from(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(HEADER).iter();
    let only = values.next()?;
    if values.next().is_some() {
        return None;
    }
    only.to_str().ok()
}
