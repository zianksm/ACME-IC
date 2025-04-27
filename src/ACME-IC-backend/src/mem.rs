use std::{any::Any, cell::RefCell, rc::Rc};

use crate::cert_manager::CertificateManager;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableMinHeap,
};

macro_rules! mem_id {
    (
        $($rest:ty;)*) => {
        mem_id!(@internal 0_u8; $($rest;)*);
    };



    (@internal $counter:expr; $ident:ty; $($rest:ty;)*) => {
        impl StorageItem for $ident {
            const ID: u8= $counter ;
        }

        mem_id!(@internal $counter + 1; $($rest;)*);


    };

    (@internal $counter:expr;) => {
        pub const TOTAL_MEMORY_ID_USED: u8 = $counter;
     };
    }

mem_id!(Mem; CertificateManager;);

pub trait StorageItem {
    const ID: u8;

    fn memory_id() -> MemoryId {
        MemoryId::new(Self::ID)
    }
}

pub trait StorageRegistry {
    fn get(&self, id: MemoryId) -> Memory;
}

pub type Memory = VirtualMemory<DefaultMemoryImpl>;

pub struct Mem {
    mgr: MemoryManager<DefaultMemoryImpl>,
    registry: StableMinHeap<u8, Memory>,
}

impl StorageRegistry for Mem {
    fn get(&self, id: MemoryId) -> Memory {
        self._get(id)
    }
}

impl Mem {
    fn _get(&self, id: MemoryId) -> Memory {
        self.mgr.get(id)
    }

    // fn _is_unique(&self, id: MemoryId) ->bool{

    // }

    // fn _register()

    pub fn init() -> Self {
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        let registry = StableMinHeap::init(mgr.get(Self::memory_id()))
            .expect("registry initialization must successfull");

        Self { mgr, registry }
    }
}
