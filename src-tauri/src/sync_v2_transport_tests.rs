//! End-to-end protocol test against a disposable HTTPS WebDAV collection.
//! The server intentionally has no ETag or conditional-write implementation.

use super::*;
use base64::engine::general_purpose::STANDARD;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use std::{
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

#[derive(Clone)]
struct RequestRecord {
    method: String,
    depth: Option<String>,
    has_condition: bool,
    authenticated: bool,
}

#[derive(Default)]
struct DavState {
    objects: BTreeMap<String, Vec<u8>>,
    requests: Vec<RequestRecord>,
}

struct DisposableDav {
    address: SocketAddr,
    ca_der: Vec<u8>,
    state: Arc<Mutex<DavState>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DisposableDav {
    fn new() -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let server_tls = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf_cert.der().clone(), ca_cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(DavState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            for incoming in listener.incoming() {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = incoming else { break };
                let tls = Arc::clone(&server_tls);
                let state = Arc::clone(&thread_state);
                thread::spawn(move || handle_request(stream, tls, state));
            }
        });
        Self {
            address,
            ca_der: ca_cert.der().as_ref().to_vec(),
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn client(&self) -> WebDavV2Client {
        let ca = reqwest::Certificate::from_der(&self.ca_der).unwrap();
        // A test-only certificate authority is trusted by this client alone.
        // Production construction and HTTPS validation remain unchanged.
        WebDavV2Client {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .min_tls_version(TlsVersion::TLS_1_2)
                .add_root_certificate(ca)
                .no_proxy()
                .http1_only()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            endpoint: Url::parse(&format!("https://localhost:{}/vault/", self.address.port()))
                .unwrap(),
            username: "test".to_owned(),
            app_password: Zeroizing::new("test-password".to_owned()),
        }
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for DisposableDav {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_request(stream: TcpStream, config: Arc<ServerConfig>, state: Arc<Mutex<DavState>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let Ok(connection) = ServerConnection::new(config) else {
        return;
    };
    let mut tls_stream = StreamOwned::new(connection, stream);
    let mut reader = BufReader::new(&mut tls_stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut content_length = 0usize;
    let mut depth = None;
    let mut has_condition = false;
    let mut authenticated = false;
    let expected_auth = format!("Basic {}", STANDARD.encode("test:test-password"));
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.parse().unwrap_or(0),
                "depth" => depth = Some(value.to_owned()),
                "if-match" | "if-none-match" | "if-unmodified-since" => has_condition = true,
                "authorization" => authenticated = value == expected_auth,
                _ => {}
            }
        }
    }
    if content_length > MAX_EVENT_BYTES {
        return;
    }
    let mut body = vec![0; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    drop(reader);

    let (status, content_type, response) = {
        let mut state = state.lock().unwrap();
        state.requests.push(RequestRecord {
            method: method.clone(),
            depth: depth.clone(),
            has_condition,
            authenticated,
        });
        if !authenticated {
            ("401 Unauthorized", "text/plain", Vec::new())
        } else if method == "PROPFIND" && path == "/vault/" {
            if depth.as_deref() == Some("0") {
                (
                    "207 Multi-Status",
                    "application/xml",
                    collection_listing().into_bytes(),
                )
            } else if depth.as_deref() == Some("1") {
                (
                    "207 Multi-Status",
                    "application/xml",
                    object_listing(&state.objects).into_bytes(),
                )
            } else {
                ("400 Bad Request", "text/plain", Vec::new())
            }
        } else if let Some(name) = path.strip_prefix("/vault/") {
            if name.is_empty() || name.contains('/') {
                ("404 Not Found", "text/plain", Vec::new())
            } else {
                match method.as_str() {
                    "GET" => match state.objects.get(name) {
                        Some(bytes) => ("200 OK", "application/octet-stream", bytes.clone()),
                        None => ("404 Not Found", "text/plain", Vec::new()),
                    },
                    "PUT" => {
                        let created = state.objects.insert(name.to_owned(), body).is_none();
                        (
                            if created {
                                "201 Created"
                            } else {
                                "204 No Content"
                            },
                            "text/plain",
                            Vec::new(),
                        )
                    }
                    _ => ("405 Method Not Allowed", "text/plain", Vec::new()),
                }
            }
        } else {
            ("404 Not Found", "text/plain", Vec::new())
        }
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let _ = tls_stream.write_all(headers.as_bytes());
    let _ = tls_stream.write_all(&response);
    let _ = tls_stream.flush();
}

fn collection_listing() -> String {
    "<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>".to_owned()
}

fn object_listing(objects: &BTreeMap<String, Vec<u8>>) -> String {
    let mut xml = collection_listing().replace("</d:multistatus>", "");
    for (name, bytes) in objects {
        xml.push_str(&format!(
            "<d:response><d:href>/vault/{name}</d:href><d:propstat><d:prop><d:getcontentlength>{}</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
            bytes.len()
        ));
    }
    xml.push_str("</d:multistatus>");
    xml
}

fn entry(id: &str, title: &str, revision: u64) -> VaultEntry {
    VaultEntry {
        id: id.to_owned(),
        title: title.to_owned(),
        username: "user".to_owned(),
        password: format!("password-{title}"),
        url: String::new(),
        purpose: String::new(),
        notes: String::new(),
        tags: vec![],
        favorite: false,
        created_at: 1,
        updated_at: revision,
        password_updated_at: revision,
        revision,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn create_join_and_concurrent_uploads_converge_without_etags() {
    let server = DisposableDav::new();
    let client = server.client();
    let material = RecoveryMaterial::generate().unwrap();
    let id = Uuid::new_v4().to_string();
    let base = SyncContent {
        entries: vec![entry(&id, "base", 1)],
        tombstones: vec![],
    };
    let mut a =
        LocalState::prepare_initial(&client, &material, &Uuid::new_v4().to_string(), &base, 1, 1)
            .unwrap();
    client.upload(a.pending.as_ref().unwrap()).await.unwrap();
    // Retrying the same event must read back the original, without a second PUT.
    client.upload(a.pending.as_ref().unwrap()).await.unwrap();
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        1
    );
    assert!(!a.stage_followup_after_verified_upload(&base, 1, 2).unwrap());
    let initial = client.fetch(&material, Some(&a)).await.unwrap();
    assert_eq!(initial.event_count, 1);
    assert_eq!(initial.content.entries[0].password, "password-base");
    a.accept_view(&initial, 1, 2).unwrap();

    let (mut b, joined_content) = LocalState::prepare_join(
        &client,
        &material,
        &Uuid::new_v4().to_string(),
        &initial,
        &base,
        1,
        3,
    )
    .unwrap();
    assert!(b.pending.is_none());
    assert_eq!(joined_content.entries[0].password, "password-base");

    let a_content = SyncContent {
        entries: vec![entry(&id, "A", 2)],
        tombstones: vec![],
    };
    let b_content = SyncContent {
        entries: vec![entry(&id, "B", 2)],
        tombstones: vec![],
    };
    assert!(a.prepare_local_changes(&a_content, 2, 4).unwrap());
    assert!(b.prepare_local_changes(&b_content, 2, 4).unwrap());
    let (a_upload, b_upload) = tokio::join!(
        client.upload(a.pending.as_ref().unwrap()),
        client.upload(b.pending.as_ref().unwrap())
    );
    a_upload.unwrap();
    b_upload.unwrap();
    assert!(!a
        .stage_followup_after_verified_upload(&a_content, 2, 5)
        .unwrap());
    assert!(!b
        .stage_followup_after_verified_upload(&b_content, 2, 5)
        .unwrap());
    let a_view = client.fetch(&material, Some(&a)).await.unwrap();
    let b_view = client.fetch(&material, Some(&b)).await.unwrap();
    assert_eq!(a_view.fingerprint(), b_view.fingerprint());
    assert_eq!(a_view.event_count, 3);
    let passwords = a_view
        .content
        .entries
        .iter()
        .map(|entry| entry.password.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(passwords, BTreeSet::from(["password-A", "password-B"]));
    a.accept_view(&a_view, 2, 6).unwrap();
    b.accept_view(&b_view, 2, 6).unwrap();

    let requests = server.requests();
    assert!(requests.iter().all(|request| request.authenticated));
    assert!(requests.iter().all(|request| !request.has_condition));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "PUT")
            .count(),
        3
    );
    assert!(requests
        .iter()
        .any(|request| request.method == "PROPFIND" && request.depth.as_deref() == Some("0")));
    assert!(requests
        .iter()
        .any(|request| request.method == "PROPFIND" && request.depth.as_deref() == Some("1")));
    assert!(requests.iter().any(|request| request.method == "GET"));
}
