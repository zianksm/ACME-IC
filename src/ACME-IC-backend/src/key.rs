use std::{cell::RefCell, rc::Rc, sync::Arc};

use ic_cdk::api::management_canister::ecdsa::{
    self, ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyResponse,
};
use k256::{elliptic_curve::PublicKey, Secp256k1};
use tiny_keccak::{Hasher, Keccak};
use x509_cert::spki;

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
pub struct AcmeSigningKey {
    domains: Vec<String>,
}

impl AcmeSigningKey {
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains }
    }

    pub fn id(&self) -> Vec<u8> {
        let mut buff = Vec::new();

        let mut hasher = Keccak::v512();

        let concat = self
            .domains
            .clone()
            .into_iter()
            .reduce(|p, s| p + &s)
            .unwrap();

        hasher.update(concat.as_bytes());

        hasher.finalize(&mut buff);

        buff
    }
}

#[derive(Clone, Debug)]
pub struct AcmeVerifyingKey(PublicKey<Secp256k1>);

impl spki::EncodePublicKey for AcmeVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        self.0.to_public_key_der()
    }
}

impl signature::Keypair for AcmeSigningKey {
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

        let pub_key = Rc::into_inner(pub_key).unwrap().into_inner();

        ic_cdk::spawn(fut);

        let pub_key = k256::PublicKey::from_sec1_bytes(&pub_key.public_key).unwrap();

        AcmeVerifyingKey(pub_key)
    }
}
