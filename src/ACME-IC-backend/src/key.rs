use x509_cert::spki;

pub struct AcmeSigningKey;

#[derive(Clone, Debug)]
pub struct AcmeVerifyingKey;

impl spki::EncodePublicKey for AcmeVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        todo!()
    }
}

impl signature::Keypair for AcmeSigningKey {
    type VerifyingKey = AcmeVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        todo!()
    }
}
