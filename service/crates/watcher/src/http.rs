//! Small bounded HTTP/1.1 parser for the enclave TLS endpoint.
use std::io::{self, Read};

const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 4096;

pub struct Request {
    pub method: String,
    pub target: String,
    pub body: Vec<u8>,
}

pub fn read_request(reader: &mut impl Read) -> io::Result<Request> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP request");
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HEADER {
            return Err(bad());
        }
        reader.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).map_err(|_| bad())?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let parts: Vec<_> = lines.next().ok_or_else(bad)?.split(' ').collect();
    if parts.len() != 3
        || !matches!(parts[0], "GET" | "POST")
        || parts[2] != "HTTP/1.1"
        || !parts[1].starts_with('/')
        || parts[1].bytes().any(|b| b <= 0x20 || b >= 0x7f)
    {
        return Err(bad());
    }
    let mut length = None;
    let mut content_type = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(bad());
        }
        let value = value.trim();
        if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(bad());
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            length = Some(value.parse::<usize>().map_err(|_| bad())?);
        }
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value).is_some() {
                return Err(bad());
            }
        }
    }
    let len = length.unwrap_or(0);
    if len > MAX_BODY
        || (parts[0] == "GET" && len != 0)
        || (parts[0] == "POST" && (length.is_none() || content_type != Some("application/json")))
    {
        return Err(bad());
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(Request {
        method: parts[0].into(),
        target: parts[1].into(),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_parser_accepts_body_and_rejects_ambiguous_framing() {
        let mut r = &b"POST /v1/deposit-intents HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"[..];
        let request = read_request(&mut r).unwrap();
        assert_eq!(
            (
                request.method.as_str(),
                request.target.as_str(),
                request.body.as_slice()
            ),
            ("POST", "/v1/deposit-intents", &b"{}"[..])
        );
        for raw in [
            "POST /v1/deposit-intents HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
            "POST /v1/deposit-intents HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n",
            "POST /v1/deposit-intents HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 4097\r\n\r\n",
            "GET /health HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
        ] { assert!(read_request(&mut raw.as_bytes()).is_err()); }
        assert!(read_request(
            &mut format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_HEADER)).as_bytes()
        )
        .is_err());
        assert!(read_request(&mut &b"POST /v1/deposit-intents HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}"[..]).is_err());
    }
}
