mod array;
mod hash;
mod lru;
mod queue;
use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::{ffi::CStr, fmt::Debug, ops::Range};

use crate::{
    linux_bpf::{bpf_attr, BpfMapType},
    BpfError, KernelAuxiliaryOps, Result,
};

#[inline]
/// Round up `x` to the nearest multiple of `align`.
fn round_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

pub type BpfCallBackFn = fn(key: &[u8], value: &[u8], ctx: *const u8) -> i32;
pub trait BpfMapCommonOps: Send + Sync + Debug {
    /// Lookup an element in the map.
    ///
    /// See <https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_lookup_elem/>
    fn lookup_elem(&mut self, _key: &[u8]) -> Result<Option<&[u8]>> {
        Err(BpfError::NotSupported)
    }
    /// Update an element in the map.
    ///
    /// See <https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_update_elem/>
    fn update_elem(&mut self, _key: &[u8], _value: &[u8], _flags: u64) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Delete an element from the map.
    ///
    /// See <https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_delete_elem/>
    fn delete_elem(&mut self, _key: &[u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// For each element in map, call callback_fn function with map,
    /// callback_ctx and other map-specific parameters.
    ///
    /// See <https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_for_each_map_elem/>
    fn for_each_elem(&mut self, _cb: BpfCallBackFn, _ctx: *const u8, _flags: u64) -> Result<u32> {
        Err(BpfError::NotSupported)
    }
    /// Look up an element with the given key in the map referred to by the file descriptor fd,
    /// and if found, delete the element.
    fn lookup_and_delete_elem(&mut self, _key: &[u8], _value: &mut [u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }

    /// erform a lookup in percpu map for an entry associated to key on cpu.
    fn lookup_percpu_elem(&mut self, _key: &[u8], _cpu: u32) -> Result<Option<&[u8]>> {
        Err(BpfError::NotSupported)
    }
    /// Get the next key in the map. If key is None, get the first key.
    ///
    /// Called from syscall
    fn get_next_key(&self, _key: Option<&[u8]>, _next_key: &mut [u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }

    /// Push an element value in map.
    fn push_elem(&mut self, _value: &[u8], _flags: u64) -> Result<()> {
        Err(BpfError::NotSupported)
    }

    /// Pop an element value from map.
    fn pop_elem(&mut self, _value: &mut [u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }

    /// Peek an element value from map.
    fn peek_elem(&self, _value: &mut [u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }

    /// Freeze the map.
    ///
    /// It's useful for .rodata maps.
    fn freeze(&self) -> Result<()> {
        Err(BpfError::NotSupported)
    }

    /// Get the first value pointer.
    ///
    /// This is used for BPF_PSEUDO_MAP_VALUE.
    fn map_values_ptr_range(&self) -> Result<Range<usize>> {
        Err(BpfError::NotSupported)
    }
}

pub trait PerCpuVariantsOps: Sync + Send + Debug {
    fn create<T: Clone + Sync + Send + 'static>(value: T) -> Option<Box<dyn PerCpuVariants<T>>>;
    fn num_cpus() -> u32;
}

/// PerCpuVariants is a trait for per-cpu data structures.
#[allow(clippy::mut_from_ref)]
pub trait PerCpuVariants<T: Clone + Sync + Send>: Sync + Send + Debug {
    /// Get the per-cpu data for the current CPU.
    fn get(&self) -> &T;
    /// Get the per-cpu data for the current CPU.
    fn get_mut(&self) -> &mut T;
    /// Get the per-cpu data for the given CPU.
    ///
    /// # Safety
    /// This function is unsafe because it allows access to the per-cpu data for a CPU
    /// that may not be the current CPU. The caller must ensure that the CPU is valid
    /// and that the data is not accessed from a different CPU.
    unsafe fn force_get(&self, cpu: u32) -> &T;
    /// Get the per-cpu data for the given CPU.
    ///
    /// # Safety
    /// This function is unsafe because it allows access to the per-cpu data for a CPU
    /// that may not be the current CPU. The caller must ensure that the CPU is valid
    /// and that the data is not accessed from a different CPU.
    unsafe fn force_get_mut(&self, cpu: u32) -> &mut T;
}

bitflags::bitflags! {
    /// flags for BPF_MAP_UPDATE_ELEM command
    pub struct BpfMapUpdateElemFlags: u64 {
        /// create new element or update existing
        const BPF_ANY = 0;
        /// create new element if it didn't exist
        const BPF_NOEXIST = 1;
        /// update existing element
        const BPF_EXIST = 2;
        /// spin_lock-ed map_lookup/map_update
        const BPF_F_LOCK = 4;
    }
}
#[derive(Debug, Clone, Default)]
pub struct BpfMapMeta {
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub _map_flags: u32,
    pub _map_name: String,
}

impl TryFrom<&bpf_attr> for BpfMapMeta {
    type Error = BpfError;
    fn try_from(attr: &bpf_attr) -> Result<Self> {
        let u = unsafe { &attr.__bindgen_anon_1 };
        let map_name_slice = unsafe {
            core::slice::from_raw_parts(u.map_name.as_ptr() as *const u8, u.map_name.len())
        };
        let map_name = CStr::from_bytes_until_nul(map_name_slice)
            .map_err(|_| BpfError::InvalidArgument)?
            .to_str()
            .map_err(|_| BpfError::InvalidArgument)?
            .to_string();
        let map_type = BpfMapType::try_from(u.map_type).map_err(|_| BpfError::InvalidArgument)?;
        Ok(BpfMapMeta {
            map_type,
            key_size: u.key_size,
            value_size: u.value_size,
            max_entries: u.max_entries,
            _map_flags: u.map_flags,
            _map_name: map_name,
        })
    }
}

#[derive(Debug)]
pub struct UnifiedMap {
    inner_map: Box<dyn BpfMapCommonOps>,
    map_meta: BpfMapMeta,
}

impl UnifiedMap {
    fn new(map_meta: BpfMapMeta, map: Box<dyn BpfMapCommonOps>) -> Self {
        Self {
            inner_map: map,
            map_meta,
        }
    }
    /// Get a reference to the concrete map.
    pub fn map(&self) -> &dyn BpfMapCommonOps {
        self.inner_map.as_ref()
    }

    /// Get a mutable reference to the concrete map.
    pub fn map_mut(&mut self) -> &mut dyn BpfMapCommonOps {
        self.inner_map.as_mut()
    }

    /// Get the map metadata.
    pub fn map_meta(&self) -> &BpfMapMeta {
        &self.map_meta
    }
}

/// Create a map and return a file descriptor that refers to
/// the map.  The close-on-exec file descriptor flag
/// is automatically enabled for the new file descriptor.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_CREATE/>
pub fn bpf_map_create<T: PerCpuVariantsOps + 'static>(map_meta: BpfMapMeta) -> Result<UnifiedMap> {
    log::info!("The map attr is {:#?}", map_meta);
    let map: Box<dyn BpfMapCommonOps> = match map_meta.map_type {
        BpfMapType::BPF_MAP_TYPE_ARRAY => {
            let array_map = array::ArrayMap::new(&map_meta)?;
            Box::new(array_map)
        }
        BpfMapType::BPF_MAP_TYPE_PERCPU_ARRAY => {
            let per_cpu_array_map = array::PerCpuArrayMap::<T>::new(&map_meta)?;
            Box::new(per_cpu_array_map)
        }
        BpfMapType::BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
            let perf_event_array_map = array::PerfEventArrayMap::new(&map_meta, T::num_cpus())?;
            Box::new(perf_event_array_map)
        }

        BpfMapType::BPF_MAP_TYPE_CPUMAP
        | BpfMapType::BPF_MAP_TYPE_DEVMAP
        | BpfMapType::BPF_MAP_TYPE_DEVMAP_HASH => {
            log::error!("bpf map type {:?} not implemented", map_meta.map_type);
            Err(BpfError::NotSupported)?
        }
        BpfMapType::BPF_MAP_TYPE_HASH => {
            let hash_map = hash::BpfHashMap::new(&map_meta)?;
            Box::new(hash_map)
        }
        BpfMapType::BPF_MAP_TYPE_PERCPU_HASH => {
            let per_cpu_hash_map = hash::PerCpuHashMap::<T>::new(&map_meta)?;
            Box::new(per_cpu_hash_map)
        }
        BpfMapType::BPF_MAP_TYPE_QUEUE => {
            let queue_map = queue::QueueMap::new(&map_meta)?;
            Box::new(queue_map)
        }
        BpfMapType::BPF_MAP_TYPE_STACK => {
            let stack_map = queue::StackMap::new(&map_meta)?;
            Box::new(stack_map)
        }
        BpfMapType::BPF_MAP_TYPE_LRU_HASH => {
            let lru_hash_map = lru::LruMap::new(&map_meta)?;
            Box::new(lru_hash_map)
        }
        BpfMapType::BPF_MAP_TYPE_LRU_PERCPU_HASH => {
            let lru_per_cpu_hash_map = lru::PerCpuLruMap::<T>::new(&map_meta)?;
            Box::new(lru_per_cpu_hash_map)
        }
        _ => {
            unimplemented!("bpf map type {:?} not implemented", map_meta.map_type)
        }
    };
    let unified_map = UnifiedMap::new(map_meta, map);
    Ok(unified_map)
}

#[derive(Debug, Clone, Copy)]
pub struct BpfMapUpdateArg {
    pub map_fd: u32,
    pub key: u64,
    pub value: u64,
    pub flags: u64,
}

impl TryFrom<&bpf_attr> for BpfMapUpdateArg {
    type Error = BpfError;
    fn try_from(attr: &bpf_attr) -> Result<Self> {
        let u = unsafe { &attr.__bindgen_anon_2 };
        let map_fd = u.map_fd;
        let key = u.key;
        let value = unsafe { u.__bindgen_anon_1.value };
        let flags = u.flags;
        Ok(BpfMapUpdateArg {
            map_fd,
            key,
            value,
            flags,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BpfMapGetNextKeyArg {
    pub map_fd: u32,
    pub key: Option<u64>,
    pub next_key: u64,
}

impl TryFrom<&bpf_attr> for BpfMapGetNextKeyArg {
    type Error = BpfError;
    fn try_from(attr: &bpf_attr) -> Result<Self> {
        unsafe {
            let u = &attr.__bindgen_anon_2;
            Ok(BpfMapGetNextKeyArg {
                map_fd: u.map_fd,
                key: if u.key != 0 { Some(u.key) } else { None },
                next_key: u.__bindgen_anon_1.next_key,
            })
        }
    }
}

/// Create or update an element (key/value pair) in a specified map.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_UPDATE_ELEM/>
pub fn bpf_map_update_elem<F: KernelAuxiliaryOps>(arg: BpfMapUpdateArg) -> Result<()> {
    log::info!("<bpf_map_update_elem>: {:#x?}", arg);
    let res = F::get_unified_map_from_fd(arg.map_fd, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let value_size = meta.value_size as usize;
        let key = F::transmute_buf(arg.key as *const u8, key_size)?;
        let value = F::transmute_buf_mut(arg.value as *mut u8, value_size)?;
        unified_map.map_mut().update_elem(key, value, arg.flags)
    });
    log::info!("bpf_map_update_elem ok");
    res
}

pub fn bpf_map_freeze<F: KernelAuxiliaryOps>(map_fd:u32) -> Result<()> {
    log::info!("<bpf_map_freeze>: map_fd: {:}", map_fd);
    F::get_unified_map_from_fd(map_fd, |unified_map| unified_map.map().freeze())
}

///  Look up an element by key in a specified map and return its value.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_LOOKUP_ELEM/>
pub fn bpf_lookup_elem<F: KernelAuxiliaryOps>(arg: BpfMapUpdateArg) -> Result<()> {
    // info!("<bpf_lookup_elem>: {:#x?}", arg);
    F::get_unified_map_from_fd(arg.map_fd, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let value_size = meta.value_size as usize;
        let key = F::transmute_buf(arg.key as *const u8, key_size)?;
        let value = F::transmute_buf_mut(arg.value as *mut u8, value_size)?;
        let map = unified_map.map_mut();
        let r_value = map.lookup_elem(key)?;
        if let Some(r_value) = r_value {
            value.copy_from_slice(r_value[..value_size].as_ref());
            Ok(())
        } else {
            Err(BpfError::NotFound)
        }
    })
}
/// Look up an element by key in a specified map and return the key of the next element.
///
/// - If key is `None`, the operation returns zero and sets the next_key pointer to the key of the first element.
/// - If key is `Some(T)`, the operation returns zero and sets the next_key pointer to the key of the next element.
/// - If key is the last element, returns -1 and errno is set to ENOENT.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_GET_NEXT_KEY/>
pub fn bpf_map_get_next_key<F: KernelAuxiliaryOps>(arg: BpfMapGetNextKeyArg) -> Result<()> {
    // info!("<bpf_map_get_next_key>: {:#x?}", arg);
    F::get_unified_map_from_fd(arg.map_fd, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let map = unified_map.map_mut();
        let next_key = F::transmute_buf_mut(arg.next_key as *mut u8, key_size)?;
        if let Some(key_ptr) = arg.key {
            let key = F::transmute_buf(key_ptr as *const u8, key_size)?;
            map.get_next_key(Some(key), next_key)?;
        } else {
            map.get_next_key(None, next_key)?;
        };
        // info!("next_key: {:?}", next_key);
        Ok(())
    })
}

/// Look up and delete an element by key in a specified map.
///
/// # WARN
///
/// Not all map types (particularly array maps) support this operation,
/// instead a zero value can be written to the map value. Check the map types page to check for support.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_DELETE_ELEM/>
pub fn bpf_map_delete_elem<F: KernelAuxiliaryOps>(arg: BpfMapUpdateArg) -> Result<()> {
    // info!("<bpf_map_delete_elem>: {:#x?}", arg);
    F::get_unified_map_from_fd(arg.map_fd, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let key = F::transmute_buf(arg.key as *const u8, key_size)?;
        unified_map.map_mut().delete_elem(key)
    })
}

/// Iterate and fetch multiple elements in a map.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_LOOKUP_BATCH/>
pub fn bpf_map_lookup_batch<F: KernelAuxiliaryOps>(_arg: BpfMapUpdateArg) -> Result<usize> {
    todo!()
}

/// Look up an element with the given key in the map referred to by the file descriptor fd,
/// and if found, delete the element.
///
/// For BPF_MAP_TYPE_QUEUE and BPF_MAP_TYPE_STACK map types, the flags argument needs to be set to 0,
/// but for other map types, it may be specified as:
/// - BPF_F_LOCK : If this flag is set, the command will acquire the spin-lock of the map value we are looking up.
///
/// If the map contains no spin-lock in its value, -EINVAL will be returned by the command.
///
/// The BPF_MAP_TYPE_QUEUE and BPF_MAP_TYPE_STACK map types implement this command as a “pop” operation,
/// deleting the top element rather than one corresponding to key.
/// The key and key_len parameters should be zeroed when issuing this operation for these map types.
///
/// This command is only valid for the following map types:
/// - BPF_MAP_TYPE_QUEUE
/// - BPF_MAP_TYPE_STACK
/// - BPF_MAP_TYPE_HASH
/// - BPF_MAP_TYPE_PERCPU_HASH
/// - BPF_MAP_TYPE_LRU_HASH
/// - BPF_MAP_TYPE_LRU_PERCPU_HASH
///
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_MAP_LOOKUP_AND_DELETE_ELEM/>
pub fn bpf_map_lookup_and_delete_elem<F: KernelAuxiliaryOps>(arg: BpfMapUpdateArg) -> Result<()> {
    // info!("<bpf_map_lookup_and_delete_elem>: {:#x?}", arg);
    F::get_unified_map_from_fd(arg.map_fd, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let value_size = meta.value_size as usize;
        let key = F::transmute_buf(arg.key as *const u8, key_size)?;
        let value = F::transmute_buf_mut(arg.value as *mut u8, value_size)?;
        unified_map.map_mut().lookup_and_delete_elem(key, value)
    })
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec::Vec};
    use core::fmt::Debug;

    use super::{PerCpuVariants, PerCpuVariantsOps};

    #[derive(Debug)]
    pub struct DummyPerCpuCreator;

    #[derive(Debug)]
    pub struct DummyPerCpuCreatorFalse;

    pub struct DummyPerCpuVariants<T>(Vec<T>);

    impl<T> Debug for DummyPerCpuVariants<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("DummyPerCpuVariants").finish()
        }
    }

    impl<T: Clone + Sync + Send> PerCpuVariants<T> for DummyPerCpuVariants<T> {
        fn get(&self) -> &T {
            &self.0[0]
        }

        fn get_mut(&self) -> &mut T {
            unsafe { &mut *(self.0.as_ptr() as *mut T) }
        }

        unsafe fn force_get(&self, cpu: u32) -> &T {
            &self.0[cpu as usize]
        }

        unsafe fn force_get_mut(&self, cpu: u32) -> &mut T {
            let ptr = self.0.as_ptr();
            let ptr = unsafe { ptr.add(cpu as usize) } as *mut T;
            unsafe { &mut *ptr }
        }
    }

    impl PerCpuVariantsOps for DummyPerCpuCreator {
        fn create<T: Clone + Sync + Send + 'static>(
            value: T,
        ) -> Option<Box<dyn PerCpuVariants<T>>> {
            let mut vec = Vec::new();
            for _ in 0..Self::num_cpus() {
                vec.push(value.clone());
            }
            Some(Box::new(DummyPerCpuVariants(vec)))
        }

        fn num_cpus() -> u32 {
            1
        }
    }

    impl PerCpuVariantsOps for DummyPerCpuCreatorFalse {
        fn create<T: Clone + Sync + Send + 'static>(
            _value: T,
        ) -> Option<Box<dyn PerCpuVariants<T>>> {
            None
        }

        fn num_cpus() -> u32 {
            0
        }
    }
}
