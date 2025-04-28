use ic_http_certification::{HttpRequest, HttpResponse, HttpUpdateRequest, HttpUpdateResponse};

pub type UpdateResponse<'a> = HttpUpdateResponse<'a>;
pub type RegularResponse<'a> = HttpResponse<'a>;
pub type UpdateRequest<'a> = HttpUpdateRequest<'a>;
pub type RegularRequest<'a> = HttpRequest<'a>;

mod types;

pub trait RequestMarker {
    type Response: ResponseMarker;
}

pub trait ResponseMarker {}

impl<'a> RequestMarker for UpdateRequest<'a> {
    type Response = UpdateResponse<'a>;
}

impl<'a> ResponseMarker for UpdateResponse<'a> {}

impl<'a> RequestMarker for RegularRequest<'a> {
    type Response = RegularResponse<'a>;
}
impl<'a> ResponseMarker for RegularResponse<'a> {}

pub trait Handler {
    const PATH: &'static str;

    type Request: RequestMarker;

    fn handle(req: Self::Request) -> <Self::Request as RequestMarker>::Response;
}
