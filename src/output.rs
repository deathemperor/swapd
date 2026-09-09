use crate::errors::SwapdError;
use serde::Serialize;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    error: ErrorBody<'a>,
}
#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a crate::errors::ErrorCode,
    message: &'a str,
}

pub fn emit_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string(value).expect("serializable"));
}

pub fn emit_error(err: &SwapdError, json: bool) {
    if json {
        emit_json(&ErrorEnvelope {
            schema_version: SCHEMA_VERSION,
            error: ErrorBody {
                code: &err.code,
                message: &err.message,
            },
        });
    } else {
        eprintln!("error: {}", err.message);
    }
}
