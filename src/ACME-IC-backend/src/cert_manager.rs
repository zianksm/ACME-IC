use std::ops::Add;

use ic_stable_structures::StableCell;
use x509_cert::name::Name;

use crate::{key::AcmeKey, mem::Memory};

pub struct CertificateManager {
    serial_number_registry: StableCell<u64, Memory>,
}

impl CertificateManager {
    fn _inc_serial_number(&mut self) -> u64 {
        let current = self.serial_number_registry.get().to_owned();

        self.serial_number_registry.set(current.add(1)).unwrap();

        current.to_owned()
    }

    pub fn generate_cert(&mut self, domain: Name) -> String {
        let serial_number = self._inc_serial_number();

        let key = AcmeKey::new(domain, serial_number);
        crate::key::Certificate::new(key).build()
    }
}
