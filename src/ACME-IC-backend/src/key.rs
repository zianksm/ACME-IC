use std::{
    cell::RefCell,
    rc::Rc,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use ic_cdk::api::management_canister::ecdsa::{
    self, ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyResponse,
    SignWithEcdsaArgument, SignWithEcdsaResponse,
};

use ic_stable_structures::Storable;
use k256::{
    ecdsa::DerSignature, elliptic_curve::PublicKey, pkcs8::SubjectPublicKeyInfo, Secp256k1,
};
use signature::Keypair;
use tiny_keccak::{Hasher, Keccak};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    certificate::CertificateInner,
    der::{
        asn1::{BitString, GeneralizedTime},
        pem::LineEnding,
        DateTime, Encode, EncodePem,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{self, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding},
    time::{Time, Validity},
};

// TODO proper CNAME
const ROOT_NAME: &'static str = "CN=IC ENCRYPT";
const ROOT_SERIAL_NUMBER: u64 = 0;
/// 1 year in nanoseconds. This does not take into account the extra 1 day in a leap year
const ONE_YEAR_VALIDITY_NANOS: u64 = 31536000000000000;

#[cfg(feature = "local")]
const ECDSA_KEY_ID: EcdsaKeyIds = EcdsaKeyIds::TestKeyLocalDevelopment;
#[cfg(feature = "staging")]
const ECDSA_KEY_ID: EcdsaKeyIds = EcdsaKeyIds::TestKey1;
#[cfg(feature = "prod")]
const ECDSA_KEY_ID: EcdsaKeyIds = EcdsaKeyIds::ProductionKey1;

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AcmeKey {
    domain: Name,
    serial_number: u64,
}

impl AcmeKey {
    pub fn new(domain: Name, serial_number: u64) -> Self {
        Self {
            domain,
            serial_number,
        }
    }

    pub fn id(&self) -> Vec<u8> {
        let mut buff = Vec::new();

        let mut hasher = Keccak::v512();

        self.domain.encode_to_slice(&mut buff).unwrap();

        hasher.update(&buff);
        hasher.update(&self.serial_number.to_bytes_checked());

        buff.clear();

        hasher.finalize(&mut buff);

        buff
    }

    pub fn is_root(&self) -> bool {
        self.domain.is_empty()
    }

    pub fn hash_mesage(msg: &[u8], mut buff: &mut [u8]) {
        let mut hasher = Keccak::v512();

        hasher.update(msg);

        hasher.finalize(buff);
    }
}

#[derive(Clone, Debug)]
pub struct AcmeVerifyingKey(PublicKey<Secp256k1>);

impl spki::EncodePublicKey for AcmeVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        self.0.to_public_key_der()
    }
}

impl signature::Keypair for AcmeKey {
    type VerifyingKey = AcmeVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        let pub_key_req = ecdsa::EcdsaPublicKeyArgument {
            canister_id: Some(ic_cdk::id()),
            derivation_path: vec![self.id()],
            key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
        };

        let pub_key = Rc::new(RefCell::new(EcdsaPublicKeyResponse::default()));
        let pub_key_transport = pub_key.clone();

        let fut = async move {
            let (response,) = ecdsa_public_key(pub_key_req).await.unwrap();

            *pub_key_transport.borrow_mut() = response;
        };

        ic_cdk::spawn(fut);

        let pub_key = Rc::into_inner(pub_key).unwrap().into_inner();

        let pub_key = k256::PublicKey::from_sec1_bytes(&pub_key.public_key).unwrap();

        AcmeVerifyingKey(pub_key)
    }
}

impl DynSignatureAlgorithmIdentifier for AcmeKey {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        let verifying_key = self.verifying_key();
        let subject_public_key_info = SubjectPublicKeyInfo::from_key(verifying_key).unwrap();

        Ok(subject_public_key_info.algorithm)
    }
}

impl signature::Signer<Asn1EncodedSignature> for AcmeKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Asn1EncodedSignature, signature::Error> {
        let id = self.id();
        let mut message_hash = Vec::with_capacity(32);

        Self::hash_mesage(msg, &mut message_hash);

        let arg = SignWithEcdsaArgument {
            message_hash,
            derivation_path: vec![id],
            key_id: ECDSA_KEY_ID.to_key_id(),
        };

        let sig = Rc::new(RefCell::new(SignWithEcdsaResponse::default()));
        let sig_transport = sig.clone();

        let fut = async move {
            let (response,) = sign_with_ecdsa(arg).await.unwrap();

            *sig_transport.borrow_mut() = response;
        };

        ic_cdk::spawn(fut);

        let sig = Rc::into_inner(sig).unwrap().into_inner().signature;

        Ok(k256::ecdsa::Signature::try_from(sig.as_slice())
            .unwrap()
            .to_der()
            .into())
    }
}

#[derive(Clone)]
pub struct Asn1EncodedSignature(DerSignature);

impl Asn1EncodedSignature {
    pub fn new(s: DerSignature) -> Self {
        Self(s)
    }
}

impl From<DerSignature> for Asn1EncodedSignature {
    fn from(value: DerSignature) -> Self {
        Self::new(value)
    }
}

impl SignatureBitStringEncoding for Asn1EncodedSignature {
    fn to_bitstring(&self) -> spki::der::Result<BitString> {
        Ok(BitString::from_bytes(self.0.as_bytes()).unwrap())
    }
}

pub struct Certificate {
    key: AcmeKey,
}

impl Certificate {
    pub fn root() -> Self {
        let name = Name::from_str(ROOT_NAME).unwrap();

        Self {
            key: AcmeKey::new(name, ROOT_SERIAL_NUMBER),
        }
    }

    pub fn root_name() -> Name {
        Name::from_str(ROOT_NAME).unwrap()
    }

    pub fn profile(&self) -> Profile {
        if self.key.is_root() {
            return Profile::Root;
        }

        // TODO we dont support subCA certificate for now
        Profile::Leaf {
            issuer: Self::root_name(),
            enable_key_agreement: true,
            enable_key_encipherment: true,
        }
    }

    pub fn build_leaf(self) -> String {
        let verifying_key = self.key.verifying_key();

        let profile = self.profile();
        let key = self.key;

        let serial_number = SerialNumber::from(key.serial_number);
        let validity = Self::generate_validity_info();
        let subject = key.domain.to_owned();
        let subject_public_key_info = SubjectPublicKeyInfo::from_key(verifying_key).unwrap();

        let cert = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            subject_public_key_info,
            &key,
        )
        .unwrap();

        let cert = cert.build().unwrap();

        // since we're in a fokin blockchain, just default to unix LF for now
        cert.to_pem(LineEnding::LF).unwrap()
    }

    fn generate_validity_info() -> Validity {
        let now = Duration::from_nanos(ic_cdk::api::time());
        let expiry = now + Duration::from_nanos(ONE_YEAR_VALIDITY_NANOS);

        let not_before = Time::GeneralTime(GeneralizedTime::from_unix_duration(now).unwrap());
        let not_after = Time::GeneralTime(GeneralizedTime::from_unix_duration(expiry).unwrap());

        let validity = Validity {
            not_before,
            not_after,
        };

        validity
    }

    pub fn build_root() -> Self {
        todo!()
    }
}
