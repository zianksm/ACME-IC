use std::{cell::RefCell, rc::Rc, str::FromStr, sync::Arc};

use ic_cdk::api::management_canister::ecdsa::{
    self, ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyResponse,
};
use ic_stable_structures::Storable;
use k256::{elliptic_curve::PublicKey, Secp256k1};
use tiny_keccak::{Hasher, Keccak};
use x509_cert::{builder::Profile, certificate::CertificateInner, der::Encode, name::Name, spki};

const ROOT_NAME: &'static str = "CN=IC ENCRYPT";
const ROOT_SERIAL_NUMBER: u128 = 0;

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
    serial_number: u128,
}

impl AcmeKey {
    pub fn new(domain: Name, serial_number: u128) -> Self {
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
        let pub_key_clone = pub_key.clone();

        let fut = async move {
            let (response,) = ecdsa_public_key(pub_key_req).await.unwrap();

            *pub_key_clone.borrow_mut() = response;
        };

        ic_cdk::spawn(fut);

        let pub_key = Rc::into_inner(pub_key).unwrap().into_inner();

        let pub_key = k256::PublicKey::from_sec1_bytes(&pub_key.public_key).unwrap();

        AcmeVerifyingKey(pub_key)
    }
}

pub struct Certificate {
    key: AcmeKey,
}

impl Certificate {
    pub fn root() -> Self {
        Self {
            key: AcmeKey::new(vec![], ROOT_SERIAL_NUMBER),
        }
    }

    pub fn root_name() -> Name {
        Name::from_str(ROOT_NAME)
    }

    pub fn profile(&self) -> Profile {
        if self.key.is_root() {
            return Profile::Root;
        }

        // we dont support subCA certificate for now
        Profile::Leaf {
            issuer: Self::root_name(),
            enable_key_agreement: true,
            enable_key_encipherment: true,
        }
    }

    pub fn build_leaf() -> Self {
        // get serial number from somewhere
        // determine vailidity -> findout how, hardcode to 1 year for now
        // subject is the acme key domain

        todo!()
    }

    pub fn build_root() -> Self {
        todo!()
    }
}
