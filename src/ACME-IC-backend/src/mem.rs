use std::{any::Any, cell::RefCell, rc::Rc};

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableMinHeap,
};

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

impl StorageItem for Mem {
    const ID: u8 = 0;
}

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

    fn _is_unique(&self, id: MemoryId) ->bool{

    }

    fn _register()

    pub fn init() -> Self {
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        let registry = StableMinHeap::init(mgr.get(Self::memory_id()))
            .expect("registry initialization must successfull");

        Self { mgr, registry }
    }
}
