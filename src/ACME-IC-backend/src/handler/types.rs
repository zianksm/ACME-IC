use serde::{Deserialize, Serialize};

// Basic types shared across multiple endpoints
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identifier {
    pub r#type: String, // Using r# prefix for the 'type' keyword
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Error {
    pub r#type: String,
    pub title: String,
    pub detail: String,
    pub status: u16,
    pub instance: Option<String>,
}

// Directory endpoint types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    pub meta: Option<DirectoryMeta>,
}

// Account endpoint types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwkPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>, // Only used for ES256K
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwsHeader {
    pub alg: String,
    pub url: String,
    pub nonce: String,
    pub kid: Option<String>,
    pub jwk: Option<JwkPublicKey>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwsRequestObject {
    pub protected: String, // Base64url-encoded header
    pub payload: String,   // Base64url-encoded payload
    pub signature: String, // Base64url-encoded signature
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewAccountRequest {
    pub terms_of_service_agreed: bool,
    pub contact: Option<Vec<String>>,
    pub external_account_binding: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub status: String,
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: bool,
    pub orders: String,
    pub created_at: Option<String>, // ISO 8601 timestamp
    pub initial_ip: Option<String>,
}

// Order endpoint types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewOrderRequest {
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>, // ISO 8601 timestamp
    pub not_after: Option<String>,  // ISO 8601 timestamp
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Order {
    pub status: String,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

// Authorization endpoint types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Challenge {
    pub r#type: String,
    pub url: String,
    pub token: String,
    pub status: String,
    pub validated: Option<String>, // ISO 8601 timestamp
    pub error: Option<Error>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Authorization {
    pub status: String,
    pub expires: Option<String>,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

// Finalize order endpoint types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FinalizeRequest {
    pub csr: String, // Base64url-encoded CSR
}

// Revoke certificate endpoint types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RevocationRequest {
    pub certificate: String, // Base64url-encoded DER certificate
    pub reason: Option<u8>,  // RFC 5280 revocation reason code
}

// Key authorization components
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyAuthorizationComputed {
    pub token: String,
    pub thumbprint: String,
    pub key_authorization: String,
}

// HTTP challenge helpers
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HttpChallengePath {
    pub domain: String,
    pub token: String,
    pub key_authorization: String,
    pub file_path: String,
    pub validation_url: String,
}

// Client configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientConfig {
    pub server_url: String,
    pub email: Option<String>,
    pub webroot_path: Option<String>,
    pub domains: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    pub account_key_path: String,
    pub agree_tos: bool,
    pub verbose: bool,
}

// ACME client state
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientState {
    pub directory: Directory,
    pub account_url: Option<String>,
    pub current_nonce: Option<String>,
}

// Certificate information
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Certificate {
    pub domains: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub pem: String,
    pub der: String,
    pub issued_at: String,
}

// Server configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerConfig {
    pub port: u16,
    pub hostname: String,
    pub ca_key_path: String,
    pub ca_cert_path: String,
    pub data_dir: String,
    pub challenge_timeout: u64, // Seconds
    pub challenge_attempts: u8,
    pub cert_validity_days: u32,
    pub rate_limit: RateLimit,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub accounts_per_hour: u32,
    pub challenges_per_hour: u32,
    pub certificates_per_week: u32,
}

// Server-side account management
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredAccount {
    pub id: String,
    pub public_key: JwkPublicKey,
    pub contact: Vec<String>,
    pub status: String,
    pub created_at: String,
    pub initial_ip: String,
    pub last_seen_ip: String,
    pub last_seen_at: String,
}

// CSR components
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CsrInfo {
    pub common_name: String,
    pub organization: Option<String>,
    pub organization_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub domains: Vec<String>,
}

// Implementation types (optional, for actual implementation)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AcmeServerError {
    BadNonce,
    BadCsr,
    BadSignatureAlgorithm,
    AccountDoesNotExist,
    UnauthorizedForOrder,
    InvalidChallenge,
    DatabaseError,
    ValidationError,
    CertificateNotFound,
    OrderNotFound,
    RateLimited,
    InvalidContact,
    MalformedRequest,
}

// Additional utility types for request/response tracking
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NonceResponse {
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmptyRequest {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmptyResponse {}
