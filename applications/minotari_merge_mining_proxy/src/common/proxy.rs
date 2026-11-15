//  Copyright 2021, The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Helper functions for converting [responses](Response) and reading bounded HTTP bodies.

use bytes::{BufMut, Bytes, BytesMut};
use http_body::Body;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited, combinators::BoxBody};
use hyper::{
    HeaderMap,
    Response,
    StatusCode,
    Version,
    header::{self, HeaderName, HeaderValue},
    http::response,
};
use serde_json as json;
use tari_common::MAX_GRPC_MESSAGE_SIZE;

use crate::{error::MmProxyError, proxy::service::ProxyBody};

/// Maximum allowed HTTP POST request body size accepted by the merge mining proxy (8 MiB, matching
/// [`MAX_GRPC_MESSAGE_SIZE`]).
pub const MAX_PROXY_REQUEST_BODY_BYTES: usize = MAX_GRPC_MESSAGE_SIZE;

/// Maximum allowed HTTP GET request body size accepted by the merge mining proxy (4 KiB).
pub const MAX_GET_REQUEST_BODY_BYTES: usize = 4 * 1024;

const JSON_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/json");

pub async fn convert_json_to_hyper_json_response(
    resp: json::Value,
    code: StatusCode,
) -> Result<Response<json::Value>, MmProxyError> {
    let resp = Response::builder()
        .version(Version::HTTP_11)
        .status(code)
        .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .body(resp)?;
    Ok(resp)
}

/// Build body response from json.
///
/// # Errors
///
/// Return error when body is invalid.
pub fn json_response(status: StatusCode, body: &json::Value) -> Result<Response<ProxyBody>, MmProxyError> {
    let (body, len) = encode_json_body(body)?;
    Response::builder()
        .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(header::CONTENT_LENGTH, len)
        .status(status)
        .body(body)
        .map_err(Into::into)
}

fn encode_json_body(body: &json::Value) -> Result<(ProxyBody, usize), MmProxyError> {
    let bytes = BytesMut::new();
    let mut writer = bytes.writer();
    json::to_writer(&mut writer, body)?;
    let bytes = writer.into_inner().freeze();
    let len = bytes.len();
    let body = BoxBody::new(Full::new(bytes));
    Ok((body, len))
}

/// Strip hop-by-hop and stale representation framing headers before replacing an upstream response body with freshly
/// serialized JSON bytes of known length.
fn sanitize_replaced_body_headers(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|val| val.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }

    headers.remove(header::CONNECTION);
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::UPGRADE);
    headers.remove(header::CONTENT_ENCODING);
    headers.remove(header::CONTENT_RANGE);
}

/// Convert parts and content into body response.
pub fn into_response(mut parts: response::Parts, content: &json::Value) -> Result<Response<ProxyBody>, MmProxyError> {
    let (body, size) = encode_json_body(content)?;
    sanitize_replaced_body_headers(&mut parts.headers);
    // Ensure that the content length header is correct
    parts.headers.insert(header::CONTENT_LENGTH, size.into());
    parts.headers.insert(header::CONTENT_TYPE, JSON_CONTENT_TYPE);
    Ok(Response::from_parts(parts, body))
}

/// Convert json response to body response.
pub fn into_body_from_response(resp: Response<json::Value>) -> Result<Response<ProxyBody>, MmProxyError> {
    let (parts, body) = resp.into_parts();
    into_response(parts, &body)
}

/// Validate `Content-Length` headers prior to streaming the request body, rejecting RFC 9112 smuggling combinations,
/// malformed values, conflicting duplicate headers, and declared lengths above `max_bytes`.
pub fn validate_content_length(headers: &HeaderMap, max_bytes: usize) -> Result<(), MmProxyError> {
    if headers.contains_key(header::TRANSFER_ENCODING) && headers.contains_key(header::CONTENT_LENGTH) {
        return Err(MmProxyError::InvalidMonerodRequest(
            "Both Transfer-Encoding and Content-Length headers are present".to_string(),
        ));
    }

    let mut canonical_digits: Option<&str> = None;
    for raw in headers.get_all(header::CONTENT_LENGTH) {
        let s = raw
            .to_str()
            .map_err(|_| MmProxyError::InvalidMonerodRequest("Invalid Content-Length header encoding".to_string()))?
            .trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(MmProxyError::InvalidMonerodRequest(
                "Malformed Content-Length header value".to_string(),
            ));
        }
        let normalized = s.trim_start_matches('0');
        let normalized = if normalized.is_empty() { "0" } else { normalized };
        if let Some(prev) = canonical_digits {
            if prev != normalized {
                return Err(MmProxyError::InvalidMonerodRequest(
                    "Conflicting Content-Length headers".to_string(),
                ));
            }
        } else {
            canonical_digits = Some(normalized);
        }
    }

    if let Some(digits) = canonical_digits {
        let len = digits
            .parse::<usize>()
            .map_err(|_| MmProxyError::RequestBodyTooLarge { max_bytes })?;
        if len > max_bytes {
            return Err(MmProxyError::RequestBodyTooLarge { max_bytes });
        }
    }

    Ok(())
}

/// Stream-read an HTTP body up to `max_bytes`, aborting immediately if the declared size hint or accumulated frames
/// exceed the limit.
pub async fn read_body_until_end<B>(body: B, max_bytes: usize) -> Result<Bytes, MmProxyError>
where
    B: Body + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let collected = Limited::new(body, max_bytes).collect().await.map_err(|err| {
        if err.downcast_ref::<LengthLimitError>().is_some() {
            MmProxyError::RequestBodyTooLarge { max_bytes }
        } else {
            MmProxyError::InvalidMonerodRequest(format!("Failed to read body until the end: {err}"))
        }
    })?;
    Ok(collected.to_bytes())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub mod test {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use futures::stream;
    use http_body::Frame;
    use http_body_util::StreamBody;

    use super::*;

    #[tokio::test]
    async fn test_convert_json_to_hyper_json_response() {
        let resp = json::json!({"test key":"test value"});
        let code = StatusCode::from_u16(200).unwrap();
        let hyper = convert_json_to_hyper_json_response(resp.clone(), code).await.unwrap();
        assert_eq!(hyper.status(), code);
        assert_eq!(hyper.body(), &resp);
        assert_eq!(hyper.version(), Version::HTTP_11);
    }

    #[tokio::test]
    async fn test_json_response_and_read_body_until_end() {
        let status = StatusCode::from_u16(200).unwrap();
        let body = json::json!({"test key":"test value"});
        let response = json_response(status, &body.clone()).unwrap();
        assert_eq!(response.status(), status);
        assert!(response.headers().contains_key("content-type"));
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(response.headers().contains_key("content-length"));
        assert_eq!(response.headers()["content-length"], body.to_string().len().to_string());
        let bytes = read_body_until_end(response.into_body(), MAX_PROXY_REQUEST_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), serde_json::to_vec(&body).unwrap().as_slice());
    }

    #[test]
    pub fn test_into_body_from_response() {
        let body = json::json!({"test key": "test value"});
        let resp = Response::new(body.clone());
        let response = into_body_from_response(resp).unwrap();
        assert!(response.headers().contains_key("content-type"));
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(response.headers().contains_key("content-length"));
        assert_eq!(response.headers()["content-length"], body.to_string().len().to_string());
    }

    #[test]
    fn into_response_strips_stale_framing_and_hop_by_hop_headers() {
        let body = json::json!({"status": "OK"});
        let upstream = Response::builder()
            .status(StatusCode::OK)
            .header(header::TRANSFER_ENCODING, "chunked")
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONNECTION, "keep-alive, x-upstream-hop")
            .header("keep-alive", "timeout=5")
            .header("x-upstream-hop", "secret")
            .header("x-monerod-version", "0.18")
            .body(body)
            .unwrap();

        let response = into_body_from_response(upstream).unwrap();
        assert!(!response.headers().contains_key(header::TRANSFER_ENCODING));
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert!(!response.headers().contains_key(header::CONNECTION));
        assert!(!response.headers().contains_key("keep-alive"));
        assert!(!response.headers().contains_key("x-upstream-hop"));
        assert_eq!(
            response
                .headers()
                .get("x-monerod-version")
                .and_then(|v| v.to_str().ok()),
            Some("0.18")
        );
    }

    #[test]
    fn validate_content_length_enforces_rfc_and_size_bounds() {
        let mut ok_headers = HeaderMap::new();
        ok_headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("1024"));
        assert!(validate_content_length(&ok_headers, 2048).is_ok());

        // Oversized Content-Length is rejected prior to body streaming
        assert!(matches!(
            validate_content_length(&ok_headers, 512),
            Err(MmProxyError::RequestBodyTooLarge { max_bytes: 512 })
        ));

        // Signed or non-digit Content-Length values are rejected
        for bad in ["+10", "-1", "12abc", ""] {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_LENGTH, HeaderValue::from_str(bad).unwrap());
            assert!(matches!(
                validate_content_length(&h, 1024),
                Err(MmProxyError::InvalidMonerodRequest(_))
            ));
        }

        // Conflicting duplicate Content-Length headers are rejected
        let mut conflicting = HeaderMap::new();
        conflicting.append(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        conflicting.append(header::CONTENT_LENGTH, HeaderValue::from_static("20"));
        assert!(matches!(
            validate_content_length(&conflicting, 1024),
            Err(MmProxyError::InvalidMonerodRequest(_))
        ));

        // Transfer-Encoding + Content-Length combination is rejected
        let mut smuggle = HeaderMap::new();
        smuggle.insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        smuggle.insert(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        assert!(matches!(
            validate_content_length(&smuggle, 1024),
            Err(MmProxyError::InvalidMonerodRequest(_))
        ));
    }

    #[tokio::test]
    async fn read_body_until_end_aborts_streaming_chunks_past_limit() {
        let polled_chunks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&polled_chunks);
        let stream = stream::iter((0..10usize).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(&[b'x'; 64])))
        }));
        let body = StreamBody::new(stream);

        let err = read_body_until_end(body, 100).await.unwrap_err();
        assert!(matches!(err, MmProxyError::RequestBodyTooLarge { max_bytes: 100 }));
        assert_eq!(polled_chunks.load(Ordering::SeqCst), 2);
    }
}
