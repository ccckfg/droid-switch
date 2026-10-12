//! Local HTTP fixtures; tests never contact WorkOS or Factory.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

pub struct Server {
    pub url: String,
    handle: JoinHandle<Vec<String>>,
}

impl Server {
    pub fn start(responses: Vec<(u16, Value)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, value) in responses {
                let deadline = Instant::now() + Duration::from_secs(8);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "expected mock HTTP request was not sent"
                            );
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                requests.push(read_request(&mut stream));
                let body = value.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });
        Self { url, handle }
    }

    pub fn finish(self) -> Vec<String> {
        self.handle.join().unwrap()
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = stream.read(&mut buffer).unwrap();
        assert!(n > 0, "incomplete HTTP request");
        data.extend_from_slice(&buffer[..n]);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            let length = headers
                .lines()
                .find_map(|s| s.strip_prefix("content-length:"))
                .map(|s| s.trim().parse::<usize>().unwrap())
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8(data).unwrap()
}
