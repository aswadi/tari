//  Copyright 2020, The Tari Project
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

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock, atomic::AtomicBool},
    time::Duration,
};

use bytes::Bytes;
use http_body::Body;
use http_body_util::{Full, combinators::BoxBody};
use hyper::{
    Method,
    Request,
    Response,
    StatusCode,
    Uri,
    body::Incoming,
    header::{self, HeaderValue},
    service::Service,
};
use jsonrpc::error::StandardError;
use minotari_app_utilities::parse_miner_input::{BaseNodeGrpcClient, ShaP2PoolGrpcClient};
use serde_json::json;
use tari_common_types::tari_address::TariAddress;
use tari_core::{consensus::BaseNodeConsensusManager, proof_of_work::randomx_factory::RandomXFactory};
use tokio::{sync::Semaphore, time::timeout};
use tracing::{error, trace, warn};

use crate::{
    block_template_data::BlockTemplateRepository,
    common::{json_rpc, proxy},
    config::MergeMiningProxyConfig,
    error::MmProxyError,
    proxy::{inner::InnerService, monerod_method::parse_monerod_rpc_method},
};

const LOG_TARGET: &str = "minotari_mm_proxy::proxy::service";

/// Maximum concurrent in-flight HTTP requests processed by the merge mining proxy.
pub(crate) const MAX_IN_FLIGHT_PROXY_REQUESTS: usize = 64;

/// Maximum time allowed to receive a complete client request body.
const DEFAULT_BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum allowed `path_and_query` length on incoming proxy HTTP requests.
const MAX_REQUEST_URI_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct MergeMiningProxyService {
    inner: InnerService,
    in_flight_requests: Arc<Semaphore>,
    body_read_timeout: Duration,
}

impl MergeMiningProxyService {
    pub fn try_create(
        config: MergeMiningProxyConfig,
        http_client: reqwest::Client,
        base_node_client: BaseNodeGrpcClient,
        p2pool_client: Option<ShaP2PoolGrpcClient>,
        block_templates: BlockTemplateRepository,
        randomx_factory: RandomXFactory,
        wallet_payment_address: TariAddress,
    ) -> Result<Self, MmProxyError> {
        trace!(target: LOG_TARGET, "Config: {:?}", config);
        let consensus_manager = BaseNodeConsensusManager::builder(config.network).build()?;
        // Assign the slowest response monerod server as the last assigned monerod server
        let last_assigned_monerod_url = config.monerod_url.last().cloned();
        Ok(Self {
            inner: InnerService {
                config: Arc::new(config),
                block_templates,
                http_client,
                base_node_client,
                p2pool_client,
                initial_sync_achieved: Arc::new(AtomicBool::new(false)),
                current_monerod_server: Arc::new(RwLock::new(None)),
                last_assigned_monerod_url: Arc::new(RwLock::new(last_assigned_monerod_url)),
                randomx_factory,
                consensus_manager,
                wallet_payment_address,
            },
            in_flight_requests: Arc::new(Semaphore::new(MAX_IN_FLIGHT_PROXY_REQUESTS)),
            body_read_timeout: DEFAULT_BODY_READ_TIMEOUT,
        })
    }

    async fn serve_request<B>(self, request: Request<B>) -> Response<ProxyBody>
    where
        B: Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let Ok(_permit) = Arc::clone(&self.in_flight_requests).try_acquire_owned() else {
            warn!(target: LOG_TARGET, "Shedding proxy HTTP request: concurrency limit reached");
            return json_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                StandardError::InternalError,
                Some("Too many concurrent requests"),
                false,
                false,
            );
        };

        let (parts, body) = request.into_parts();
        if let Err((status, reason)) = validate_request_target(&parts.method, &parts.uri) {
            warn!(target: LOG_TARGET, "Rejected proxy HTTP request target: {reason}");
            let allow_get_post = status == StatusCode::METHOD_NOT_ALLOWED;
            return json_error_response(
                status,
                StandardError::InvalidRequest,
                Some(reason),
                false,
                allow_get_post,
            );
        }

        let max_body_bytes = if parts.method == Method::GET {
            proxy::MAX_GET_REQUEST_BODY_BYTES
        } else {
            proxy::MAX_PROXY_REQUEST_BODY_BYTES
        };

        if let Err(err) = proxy::validate_content_length(&parts.headers, max_body_bytes) {
            return body_read_error_response(&err);
        }

        let bytes = match timeout(self.body_read_timeout, proxy::read_body_until_end(body, max_body_bytes)).await {
            Ok(Ok(b)) => b,
            Ok(Err(err)) => return body_read_error_response(&err),
            Err(_) => {
                warn!(target: LOG_TARGET, "Timed out reading proxy HTTP request body");
                return json_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    StandardError::InvalidRequest,
                    Some("Timed out reading request body"),
                    true,
                    false,
                );
            },
        };

        let request = Request::from_parts(parts, bytes);
        let monerod_method = parse_monerod_rpc_method(request.method(), request.uri(), request.body());

        match self.inner.handle(monerod_method, request).await {
            Ok(resp) => resp,
            Err(MmProxyError::InvalidMonerodRequest(_)) => json_error_response(
                StatusCode::BAD_REQUEST,
                StandardError::InvalidRequest,
                Some("Invalid request"),
                false,
                false,
            ),
            Err(err) => {
                error!(target: LOG_TARGET, "Method \"{}\" failed handling request: {:?}", monerod_method, err);
                json_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    StandardError::InternalError,
                    None,
                    false,
                    false,
                )
            },
        }
    }
}

fn body_read_error_response(err: &MmProxyError) -> Response<ProxyBody> {
    warn!(target: LOG_TARGET, "Method: Unknown, Failed to read request: {:?}", err);
    match err {
        MmProxyError::RequestBodyTooLarge { .. } => json_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            StandardError::InvalidRequest,
            Some("Request body exceeds maximum allowed size"),
            true,
            false,
        ),
        _ => json_error_response(
            StatusCode::BAD_REQUEST,
            StandardError::InvalidRequest,
            Some("Invalid request body"),
            true,
            false,
        ),
    }
}

fn json_error_response(
    status: StatusCode,
    err: StandardError,
    details: Option<&str>,
    close_connection: bool,
    allow_get_post: bool,
) -> Response<ProxyBody> {
    let payload = json_rpc::standard_error_response(None, err, details.map(|d| json!({ "details": d })));
    let mut resp = proxy::json_response(status, &payload).unwrap_or_else(|_| {
        let fallback = Bytes::from_static(
            b"{\"id\":-1,\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}",
        );
        let mut r = Response::new(BoxBody::new(Full::new(fallback)));
        *r.status_mut() = status;
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        r
    });
    if close_connection {
        resp.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    if allow_get_post {
        resp.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
    }
    resp
}

fn decode_hex_pair(iter: &mut std::str::Bytes<'_>) -> Option<u8> {
    let hi = char::from(iter.next()?).to_digit(16)?;
    let lo = char::from(iter.next()?).to_digit(16)?;
    u8::try_from((hi << 4) | lo).ok()
}

fn decode_and_validate_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') || path.contains("//") {
        return Err("Invalid request URI path");
    }

    let mut decoded = Vec::with_capacity(path.len());
    let mut iter = path.bytes();
    while let Some(b) = iter.next() {
        if b == b'\\' || b.is_ascii_control() {
            return Err("Invalid character in request URI path");
        }
        if b == b'%' {
            let unescaped = decode_hex_pair(&mut iter).ok_or("Malformed percent-encoding in request URI path")?;
            if unescaped == b'/' || unescaped == b'\\' || unescaped.is_ascii_control() {
                return Err("Disallowed percent-encoded separator or control byte in request URI path");
            }
            decoded.push(unescaped);
        } else {
            decoded.push(b);
        }
    }

    for segment in decoded.split(|b| *b == b'/').skip(1) {
        if segment == b"." || segment == b".." {
            return Err("Path traversal segment is not allowed in request URI");
        }
    }

    Ok(())
}

fn validate_query(query: &str) -> Result<(), &'static str> {
    let mut iter = query.bytes();
    while let Some(b) = iter.next() {
        if b.is_ascii_control() {
            return Err("Control character in request URI query");
        }
        if b == b'%' {
            let unescaped = decode_hex_pair(&mut iter).ok_or("Malformed percent-encoding in request URI query")?;
            if unescaped.is_ascii_control() {
                return Err("Disallowed control byte in request URI query");
            }
        }
    }
    Ok(())
}

fn validate_request_target(method: &Method, uri: &Uri) -> Result<(), (StatusCode, &'static str)> {
    if !matches!(*method, Method::GET | Method::POST) {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Only GET and POST methods are supported",
        ));
    }

    let pq_len = uri.path_and_query().map_or(0, |pq| pq.as_str().len());
    if pq_len == 0 || pq_len > MAX_REQUEST_URI_BYTES {
        return Err((StatusCode::BAD_REQUEST, "Invalid or oversized request URI"));
    }

    decode_and_validate_path(uri.path()).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;
    if let Some(query) = uri.query() {
        validate_query(query).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;
    }

    Ok(())
}

pub type ProxyBody = BoxBody<Bytes, Infallible>;

impl Service<Request<Incoming>> for MergeMiningProxyService {
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<ProxyBody>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let svc = self.clone();
        Box::pin(async move { Ok(svc.serve_request(request).await) })
    }
}

#[cfg(test)]
mod test {
    use futures::stream;
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};
    use minotari_node_grpc_client::grpc::base_node_client::BaseNodeClient;
    use minotari_wallet_grpc_client::ClientAuthenticationInterceptor;
    use tari_common::configuration::StringList;
    use tonic::transport::Endpoint;

    use super::*;

    fn create_test_service() -> MergeMiningProxyService {
        let mut config = MergeMiningProxyConfig::default();
        config.monerod_url = StringList::from(vec!["http://127.0.0.1:1".to_string()]);
        config.monerod_connection_timeout = Duration::from_millis(20);

        let channel = Endpoint::from_static("http://127.0.0.1:18142").connect_lazy();
        let interceptor = ClientAuthenticationInterceptor::create(&config.base_node_grpc_authentication).unwrap();
        let base_node_client = BaseNodeClient::with_interceptor(channel, interceptor);

        MergeMiningProxyService::try_create(
            config,
            reqwest::Client::new(),
            base_node_client,
            None,
            BlockTemplateRepository::new(),
            RandomXFactory::new(1),
            TariAddress::default(),
        )
        .unwrap()
    }

    async fn response_json(resp: Response<ProxyBody>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn rejects_unsupported_http_methods_with_405_and_allow_header() {
        let svc = create_test_service();
        for method in [Method::PUT, Method::DELETE, Method::OPTIONS, Method::PATCH] {
            let req = Request::builder()
                .method(method)
                .uri("/json_rpc")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = svc.clone().serve_request(req).await;
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(
                resp.headers().get(header::ALLOW).and_then(|v| v.to_str().ok()),
                Some("GET, POST")
            );
        }
    }

    #[tokio::test]
    async fn rejects_path_traversal_and_encoded_separators_before_upstream_dispatch() {
        let svc = create_test_service();
        let bad_uris = [
            "//evil.example/json_rpc",
            "/../admin",
            "/monero/../../admin",
            "/%2e%2e/admin",
            "/%2E%2E/admin",
            "/json_rpc%2fadmin",
            "/json_rpc%5cadmin",
            "/json_rpc//extra",
            "/json_rpc?bad=%1b",
            "/json_rpc?bad=%0a",
        ];

        for bad_uri in bad_uris {
            let req = Request::builder()
                .method(Method::POST)
                .uri(bad_uri)
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let resp = svc.clone().serve_request(req).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "URI should fail: {bad_uri}");
        }

        let oversized_uri = format!("/{}", "a".repeat(MAX_REQUEST_URI_BYTES));
        let req = Request::builder()
            .method(Method::GET)
            .uri(oversized_uri)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = svc.serve_request(req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        assert!(validate_request_target(&Method::POST, &Uri::from_static("/json_rpc")).is_ok());
        assert!(validate_request_target(&Method::GET, &Uri::from_static("/get_height")).is_ok());
    }

    #[tokio::test]
    async fn rejects_oversized_post_and_get_bodies_with_413_and_connection_close() {
        let svc = create_test_service();

        // Declared Content-Length above POST limit is rejected immediately with 413 + Connection: close
        let declared_too_large = proxy::MAX_PROXY_REQUEST_BODY_BYTES.saturating_add(1).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/json_rpc")
            .header(header::CONTENT_LENGTH, declared_too_large)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = svc.clone().serve_request(req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers().get(header::CONNECTION).and_then(|v| v.to_str().ok()),
            Some("close")
        );

        // Chunked GET body exceeding MAX_GET_REQUEST_BODY_BYTES without Content-Length is rejected with 413
        let stream = stream::iter((0..6usize).map(|_| Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b'a'; 1024])))));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/get_height")
            .body(StreamBody::new(stream))
            .unwrap();
        let resp = svc.serve_request(req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers().get(header::CONNECTION).and_then(|v| v.to_str().ok()),
            Some("close")
        );
    }

    #[tokio::test]
    async fn aborts_stalled_request_body_with_408_request_timeout() {
        let mut svc = create_test_service();
        svc.body_read_timeout = Duration::from_millis(40);

        let stalled = StreamBody::new(stream::pending::<Result<Frame<Bytes>, Infallible>>());
        let req = Request::builder()
            .method(Method::POST)
            .uri("/json_rpc")
            .body(stalled)
            .unwrap();

        let resp = svc.serve_request(req).await;
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            resp.headers().get(header::CONNECTION).and_then(|v| v.to_str().ok()),
            Some("close")
        );
    }

    #[tokio::test]
    async fn sheds_excess_concurrent_requests_with_429_too_many_requests() {
        let svc = create_test_service();
        let _permits = svc
            .in_flight_requests
            .acquire_many(u32::try_from(MAX_IN_FLIGHT_PROXY_REQUESTS).unwrap())
            .await
            .unwrap();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/json_rpc")
            .body(Full::new(Bytes::from_static(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_version\"}",
            )))
            .unwrap();
        let resp = svc.clone().serve_request(req).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn internal_errors_do_not_leak_sensitive_details_in_500_response() {
        let svc = create_test_service();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/json_rpc")
            .body(Full::new(Bytes::from_static(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_version\"}",
            )))
            .unwrap();

        let resp = svc.serve_request(req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_json(resp).await;
        assert_eq!(
            body.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str()),
            Some("Internal error")
        );
        assert!(
            body.get("error")
                .and_then(|e| e.get("data"))
                .is_none_or(serde_json::Value::is_null)
        );
        let serialized = body.to_string();
        assert!(!serialized.contains("127.0.0.1"));
        assert!(!serialized.contains("No reachable servers"));
    }
}
