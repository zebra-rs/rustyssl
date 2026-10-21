//! The HTTP helpers of `apps/lib/apps.c`: `app_http_get_asn1` and `app_http_post_asn1` (with
//! `app_http_tls_cb`, in `rustyssl_ossl::http`).

use rustyssl_ossl::Bio;
use rustyssl_ossl::http::{self, Headers, Post, SslCtx};

/// `app_http_get_asn1(url, proxy, no_proxy, ssl_ctx, headers, timeout, expected_ct, it)`:
/// the response's `BIO`, which `parse` decodes (it gets NULL, as `ASN1_item_d2i_bio` does,
/// when the transfer failed).
#[allow(clippy::too_many_arguments)]
pub fn app_http_get_asn1<T>(
    url: Option<&str>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    ssl_ctx: Option<&SslCtx>,
    headers: &Headers,
    timeout: i64,
    expected_content_type: Option<&str>,
    parse: impl FnOnce(Option<&Bio>) -> Option<T>,
) -> Option<T> {
    let Some(url) = url else {
        http::raise_null(None);
        return None;
    };
    let u = http::parse_url(url)?;
    if u.use_ssl && ssl_ctx.is_none() {
        http::raise_null(Some("missing SSL_CTX"));
        return None;
    }
    if !u.use_ssl && ssl_ctx.is_some() {
        http::raise_invalid("SSL_CTX given but use_ssl == 0");
        return None;
    }
    let use_proxy = http::adapt_proxy(proxy, no_proxy, &u.host, u.use_ssl);
    let prog = super::opt::prog();
    let mem = http::get(
        url,
        &u.host,
        &u.port,
        proxy,
        no_proxy,
        ssl_ctx,
        use_proxy,
        headers,
        timeout,
        expected_content_type,
        &prog,
    );
    parse(mem.as_ref())
}

/// `app_http_post_asn1`: posts `req` (DER, in a memory `BIO`), the response decoded by
/// `parse` (NULL when the transfer failed).
pub fn app_http_post_asn1<T>(
    p: &Post<'_>,
    req: Option<Bio>,
    parse: impl FnOnce(Option<&Bio>) -> Option<T>,
) -> Option<T> {
    let req = req?;
    let rsp = http::post(p, &req);
    drop(req);
    parse(rsp.as_ref())
}
