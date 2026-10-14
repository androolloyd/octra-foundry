//! `forge create` — compile + sign + deploy against in-process backend.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn create_in_process_returns_deploy_address() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.hex");
    fs::write(&key_path, "11".repeat(32)).unwrap();
    let src_path = dir.path().join("Demo.aml");
    fs::write(
        &src_path,
        "program Demo {\n  fn foo(x: int): bool { return true }\n}\n",
    )
    .unwrap();
    cmd()
        .args(["forge", "create"])
        .arg(&src_path)
        .arg("--key")
        .arg(&key_path)
        .arg("--rpc-url")
        .arg("inprocess://octPROG")
        .assert()
        .success()
        .stdout(contains("\"address\""))
        .stdout(contains("oct"));
}

/// A native-shaped RPC response fixture. In-process create skips receipt waiting,
/// so it cannot catch a falsely successful deployment confirmation.
fn native_create_case(status: &str, receipt: serde_json::Value, no_wait: bool) {
    use serde_json::{json, Value};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/rpc", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let submitted = Arc::new(Mutex::new(None));
    let server_submitted = Arc::clone(&submitted);
    let status = status.to_owned();
    let server = std::thread::spawn(move || {
        while !server_stop.load(Ordering::Relaxed) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut data = Vec::new();
            let header_end = loop {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buf[..n]);
                if let Some(offset) = data.windows(4).position(|x| x == b"\r\n\r\n") {
                    break offset + 4;
                }
            };
            let headers = String::from_utf8_lossy(&data[..header_end]);
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            while data.len() < header_end + length {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buf[..n]);
            }
            let request: Value = serde_json::from_slice(&data[header_end..]).unwrap();
            let result = match request["method"].as_str().unwrap() {
                "octra_compileAml" => json!({"bytecode":"T0NUQg==", "compiler":"fixture"}),
                "octra_balance" => json!({"nonce":5, "pending_nonce":8}),
                "octra_computeContractAddress" => json!({"address":"octPREDICTED"}),
                "octra_submit" => {
                    *server_submitted.lock().unwrap() = Some(request["params"][0].clone());
                    json!({"tx_hash":"ab".repeat(32), "status":"accepted"})
                }
                "octra_transaction" => json!({"status":status, "reason":"fixture rejection"}),
                "contract_receipt" => receipt.clone(),
                other => panic!("unexpected RPC {other}"),
            };
            let body = json!({"jsonrpc":"2.0", "id":request["id"], "result":result}).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
        }
    });
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("key"), "11".repeat(32)).unwrap();
    fs::write(
        dir.path().join("Demo.aml"),
        "contract Demo { fn ping(): bool { return true } }",
    )
    .unwrap();
    let mut command = cmd();
    command
        .args(["forge", "create"])
        .arg(dir.path().join("Demo.aml"))
        .arg("--key")
        .arg(dir.path().join("key"))
        .args(["--rpc-url", &url, "--wait-secs", "0"]);
    if no_wait {
        command.arg("--no-wait");
    }
    let output = command.output().unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    assert_eq!(submitted.lock().unwrap().as_ref().unwrap()["nonce"], 9);
    if no_wait {
        assert!(output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["confirmed"], false);
        assert_eq!(result["address"], "octPREDICTED");
    } else {
        assert!(
            !output.status.success(),
            "unconfirmed deployment reported success"
        );
        assert!(
            output.stdout.is_empty(),
            "failed deployment emitted success JSON"
        );
    }
}

#[test]
fn default_create_rejects_staged_unconfirmed_transaction() {
    native_create_case("accepted", serde_json::Value::Null, false);
}
#[test]
fn default_create_rejects_failed_execution_receipt() {
    native_create_case(
        "confirmed",
        serde_json::json!({"success":false, "error":"revert"}),
        false,
    );
}
#[test]
fn default_create_rejects_receipt_without_actual_address() {
    native_create_case("confirmed", serde_json::json!({"success":true}), false);
}
#[test]
fn explicit_no_wait_reports_prediction_as_unconfirmed() {
    native_create_case("accepted", serde_json::Value::Null, true);
}
