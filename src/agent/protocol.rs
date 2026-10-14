//! Line-oriented wire protocol for the `pqp` passphrase agent.
//!
//! Every request is a single `\n`-terminated ASCII line, and every response
//! is a single `\n`-terminated ASCII line. Passphrases are base64-encoded
//! (standard alphabet) so arbitrary bytes survive framing without escaping.
//!
//! # Requests
//!
//! | Line | Meaning |
//! |---|---|
//! | `PING` | Liveness check |
//! | `PUT <key-id> <base64>` | Cache a passphrase for a key |
//! | `GET <key-id>` | Retrieve a cached passphrase |
//! | `DEL <key-id>` | Forget a cached passphrase |
//! | `CLEAR` | Forget every cached passphrase |
//! | `EXIT` | Ask the agent to shut down |
//!
//! # Responses
//!
//! | Line | Meaning |
//! |---|---|
//! | `OK [detail]` | Success |
//! | `DATA <base64>` | A cached passphrase (reply to `GET`) |
//! | `ERR <message>` | Failure |

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// A request sent by a client to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Check that the agent is alive.
    Ping,
    /// Cache `passphrase` under `key_id`.
    Put { key_id: String, passphrase: Vec<u8> },
    /// Retrieve the passphrase cached under `key_id`.
    Get { key_id: String },
    /// Forget the passphrase cached under `key_id`.
    Del { key_id: String },
    /// Forget every cached passphrase.
    Clear,
    /// Ask the agent to shut down.
    Exit,
}

/// A response sent by the agent to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Success, with an optional human-readable detail string.
    Ok(Option<String>),
    /// A cached passphrase payload.
    Data(Vec<u8>),
    /// Failure, with a human-readable reason.
    Err(String),
}

impl Request {
    /// Serialize the request into a protocol line (without the trailing
    /// newline).
    pub fn encode(&self) -> String {
        match self {
            Request::Ping => "PING".to_string(),
            Request::Put { key_id, passphrase } => {
                format!("PUT {} {}", key_id, STANDARD.encode(passphrase))
            }
            Request::Get { key_id } => format!("GET {}", key_id),
            Request::Del { key_id } => format!("DEL {}", key_id),
            Request::Clear => "CLEAR".to_string(),
            Request::Exit => "EXIT".to_string(),
        }
    }

    /// Parse a protocol line into a request.
    pub fn parse(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts.first().copied().unwrap_or("") {
            "PING" => Ok(Request::Ping),
            "CLEAR" => Ok(Request::Clear),
            "EXIT" => Ok(Request::Exit),
            "GET" => {
                let key_id = parts.get(1).copied().ok_or("GET requires a key id")?;
                Ok(Request::Get {
                    key_id: key_id.to_string(),
                })
            }
            "DEL" => {
                let key_id = parts.get(1).copied().ok_or("DEL requires a key id")?;
                Ok(Request::Del {
                    key_id: key_id.to_string(),
                })
            }
            "PUT" => {
                let key_id = parts.get(1).copied().ok_or("PUT requires a key id")?;
                let encoded = parts.get(2).copied().ok_or("PUT requires a passphrase")?;
                let passphrase = STANDARD
                    .decode(encoded)
                    .map_err(|e| format!("invalid base64 passphrase: {}", e))?;
                Ok(Request::Put {
                    key_id: key_id.to_string(),
                    passphrase,
                })
            }
            other => Err(format!("unknown request: {}", other)),
        }
    }
}

impl Response {
    /// Serialize the response into a protocol line (without the trailing
    /// newline).
    pub fn encode(&self) -> String {
        match self {
            Response::Ok(None) => "OK".to_string(),
            Response::Ok(Some(detail)) => format!("OK {}", detail),
            Response::Data(bytes) => format!("DATA {}", STANDARD.encode(bytes)),
            Response::Err(message) => format!("ERR {}", message),
        }
    }

    /// Parse a protocol line into a response.
    pub fn parse(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        match parts.first().copied().unwrap_or("") {
            "OK" => Ok(Response::Ok(parts.get(1).map(|s| s.to_string()))),
            "DATA" => {
                let encoded = parts.get(1).copied().ok_or("DATA requires a payload")?;
                let bytes = STANDARD
                    .decode(encoded)
                    .map_err(|e| format!("invalid base64 payload: {}", e))?;
                Ok(Response::Data(bytes))
            }
            "ERR" => Ok(Response::Err(
                parts.get(1).copied().unwrap_or("").to_string(),
            )),
            other => Err(format!("unknown response: {}", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_request_roundtrip(request: Request) {
        let parsed = Request::parse(&request.encode()).unwrap();
        assert_eq!(parsed, request);
    }

    fn assert_response_roundtrip(response: Response) {
        let parsed = Response::parse(&response.encode()).unwrap();
        assert_eq!(parsed, response);
    }

    #[test]
    fn test_request_roundtrip_ping() {
        assert_request_roundtrip(Request::Ping);
    }

    #[test]
    fn test_request_roundtrip_clear() {
        assert_request_roundtrip(Request::Clear);
    }

    #[test]
    fn test_request_roundtrip_exit() {
        assert_request_roundtrip(Request::Exit);
    }

    #[test]
    fn test_request_roundtrip_get_del() {
        assert_request_roundtrip(Request::Get {
            key_id: "0123456789abcdef".into(),
        });
        assert_request_roundtrip(Request::Del {
            key_id: "0123456789abcdef".into(),
        });
    }

    #[test]
    fn test_request_roundtrip_put() {
        assert_request_roundtrip(Request::Put {
            key_id: "0123456789abcdef".into(),
            passphrase: b"correct horse battery staple".to_vec(),
        });
    }

    #[test]
    fn test_request_roundtrip_put_binary() {
        assert_request_roundtrip(Request::Put {
            key_id: "ffffffffffffffff".into(),
            passphrase: vec![0u8, 1, 2, 255, 254, 10, 13],
        });
    }

    #[test]
    fn test_request_roundtrip_put_empty() {
        assert_request_roundtrip(Request::Put {
            key_id: "0123456789abcdef".into(),
            passphrase: Vec::new(),
        });
    }

    #[test]
    fn test_request_parse_rejects_unknown() {
        assert!(Request::parse("FROBNICATE").is_err());
        assert!(Request::parse("").is_err());
    }

    #[test]
    fn test_request_parse_rejects_missing_args() {
        assert!(Request::parse("GET").is_err());
        assert!(Request::parse("DEL").is_err());
        assert!(Request::parse("PUT 0123456789abcdef").is_err());
    }

    #[test]
    fn test_request_parse_rejects_bad_base64() {
        assert!(Request::parse("PUT 0123456789abcdef !!!not-base64!!!").is_err());
    }

    #[test]
    fn test_response_roundtrip_ok() {
        assert_response_roundtrip(Response::Ok(None));
        assert_response_roundtrip(Response::Ok(Some("pqp-agent/1".into())));
        assert_response_roundtrip(Response::Ok(Some("two words".into())));
    }

    #[test]
    fn test_response_roundtrip_data() {
        assert_response_roundtrip(Response::Data(b"passphrase".to_vec()));
        assert_response_roundtrip(Response::Data(Vec::new()));
    }

    #[test]
    fn test_response_roundtrip_err() {
        assert_response_roundtrip(Response::Err("not found".into()));
    }

    #[test]
    fn test_response_parse_rejects_unknown() {
        assert!(Response::parse("WHATEVER").is_err());
        assert!(Response::parse("").is_err());
        assert!(Response::parse("DATA").is_err());
    }
}
