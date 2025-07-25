use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct _ResponseBody<T: Serialize> {
    status_code: u16,
    data: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct _ErrorResponse {
    pub msg: String,
}
