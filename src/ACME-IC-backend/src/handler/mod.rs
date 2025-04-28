use anyhow::{anyhow, Result};
use ic_http_certification::{
    HeaderField, HttpRequest, HttpResponse, HttpResponseBuilder, HttpUpdateRequest,
    HttpUpdateResponse, StatusCode,
};

mod types;

pub type R<T> = std::result::Result<T, GenericError>;
pub type UpdateResponse<'a> = HttpUpdateResponse<'a>;
pub type RegularResponse<'a> = HttpResponse<'a>;
pub type UpdateRequest<'a> = HttpUpdateRequest<'a>;
pub type RegularRequest<'a> = HttpRequest<'a>;

#[derive(Debug, Clone)]
pub enum Method {
    GET,
    POST,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::GET => "GET",
            Method::POST => "POST",
        }
    }

    pub fn from_str(str_: &str) -> Result<Self> {
        match str_ {
            "GET" => Ok(Self::GET),
            "POST" => Ok(Self::POST),
            _ => Err(anyhow!("unsupported method")),
        }
    }
}

pub trait RequestMarker {
    type Response: ResponseMarker;

    fn raw_body(&self) -> &[u8];

    fn req_method(&self) -> Result<Method>;

    fn url(&self) -> &str;
}

pub trait ResponseMarker {
    fn status_code(&self) -> StatusCode;
    fn headers(&self) -> &[HeaderField];
    fn body(&self) -> &[u8];
}

impl<'a> RequestMarker for UpdateRequest<'a> {
    type Response = UpdateResponse<'a>;

    fn raw_body(&self) -> &[u8] {
        self.body()
    }

    fn req_method(&self) -> Result<Method> {
        Method::from_str(self.method().as_str())
    }

    fn url(&self) -> &str {
        self.url()
    }
}

impl<'a> ResponseMarker for UpdateResponse<'a> {
    fn status_code(&self) -> StatusCode {
        self.status_code()
    }

    fn headers(&self) -> &[HeaderField] {
        self.headers()
    }

    fn body(&self) -> &[u8] {
        self.body()
    }
}

impl<'a> RequestMarker for RegularRequest<'a> {
    type Response = RegularResponse<'a>;

    fn raw_body(&self) -> &[u8] {
        self.body()
    }

    fn req_method(&self) -> Result<Method> {
        Method::from_str(self.method().as_str())
    }

    fn url(&self) -> &str {
        self.url()
    }
}
impl<'a> ResponseMarker for RegularResponse<'a> {
    fn status_code(&self) -> StatusCode {
        self.status_code()
    }

    fn headers(&self) -> &[HeaderField] {
        self.headers()
    }

    fn body(&self) -> &[u8] {
        self.body()
    }
}

pub struct GenericError {
    err: anyhow::Error,
    code: StatusCode,
}

impl GenericError {
    fn forbidden(err: anyhow::Error) -> Self {
        Self {
            err,
            code: StatusCode::FORBIDDEN,
        }
    }

    fn bad_request(err: anyhow::Error) -> Self {
        Self {
            err,
            code: StatusCode::BAD_REQUEST,
        }
    }
}

pub struct HandleOutcome<Data> {
    data: Data,
    status_code: StatusCode,
}
pub trait Handler<'d> {
    const PATH: &'static str;
    const METHOD: Method;

    type RawRequest: RequestMarker;
    type RequestPayload: serde::Deserialize<'d>;
    type ResponsePayload: serde::Serialize;

    fn build_error_resp(err: GenericError) -> <Self::RawRequest as RequestMarker>::Response {
        todo!()
    }

    fn validate_raw_request(req: &'d Self::RawRequest) -> R<Self::RequestPayload> {
        let raw = req.req_method().map_err(GenericError::bad_request)?;
        Ok(
            serde_json::from_slice::<Self::RequestPayload>(req.raw_body())
                .map_err(|_| anyhow!("unexpected payload encopuntered"))
                .map_err(GenericError::bad_request)?,
        )
    }

    fn accept(req: Self::RawRequest) -> <Self::RawRequest as RequestMarker>::Response {
        match Self::validate_raw_request(&req) {
            Ok(arg) => Self::handle(arg),
            Err(e) => Self::build_error_resp(e),
        }
    }

    fn build_success_resp(
        data: HandleOutcome<Self::ResponsePayload>,
    ) -> <Self::RawRequest as RequestMarker>::Response {
        let body = serde_json::to_vec_pretty(&data.data).unwrap();

        // TODO: HEADERS
        HttpResponseBuilder::new()
            .with_status_code(data.status_code)
            .with_body(body)
            .with_upgrade(false);
        todo!()
    }

    fn handle(req: Self::RequestPayload) -> R<HandleOutcome<Self::ResponsePayload>>;
}
