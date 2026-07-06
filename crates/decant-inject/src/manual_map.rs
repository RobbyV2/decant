use std::ffi::c_void;

use crate::pe::{DLL_PROCESS_ATTACH, ImportSymbol, Pe, checked_add};
use crate::{InjectError, InjectionRequest, Injector, LoadInfo, Portability, sdk};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub struct ManualMapInjector;

impl Injector for ManualMapInjector {
    fn name(&self) -> &str {
        "manual-map"
    }

    fn portability(&self) -> Portability {
        Portability::LoaderInternals
    }

    fn inject(&self, req: &InjectionRequest) -> Result<LoadInfo, InjectError> {
        if req.carafe_image.is_empty() {
            return Err(InjectError::ManualMap(
                "carafe_image is empty; manual-map requires image bytes".into(),
            ));
        }
        let pe = Pe::parse(req.carafe_image)?;
        let mut image = pe.mapped_image(req.carafe_image)?;
        unsafe {
            let proc = req.target.0;
            let remote = match sdk::alloc_at(
                proc,
                pe.image_base as usize as *mut c_void,
                pe.size_of_image,
                sdk::PAGE_EXECUTE_READWRITE,
            ) {
                Ok(p) => p,
                Err(_) => sdk::alloc(proc, pe.size_of_image, sdk::PAGE_EXECUTE_READWRITE)?,
            };
            let remote_base = remote as usize;
            pe.apply_relocs(&mut image, remote_base as u64)?;
            pe.resolve_imports(&mut image, |module, symbol| {
                let module = sdk::remote_load_library(proc, module)?;
                match symbol {
                    ImportSymbol::Name(name) => {
                        sdk::remote_get_proc_address_name(proc, module, name)
                    }
                    ImportSymbol::Ordinal(ordinal) => {
                        sdk::remote_get_proc_address_ordinal(proc, module, ordinal)
                    }
                }
            })?;
            sdk::write(proc, remote, &image)?;
            pe.protect_sections(proc, remote_base)?;
            pe.call_tls(proc, &image, remote_base)?;
            pe.call_entry(proc, remote_base)?;
            Ok(LoadInfo {
                method: self.name().to_string(),
                remote_base: Some(remote_base),
                notes: vec!["mapped from carafe_image".into()],
            })
        }
    }
}

impl Pe {
    unsafe fn protect_sections(
        &self,
        process: *mut c_void,
        remote_base: usize,
    ) -> Result<(), InjectError> {
        unsafe {
            sdk::protect(
                process,
                remote_base as *mut c_void,
                self.size_of_headers,
                sdk::PAGE_READONLY,
            )?;
        }
        for section in &self.sections {
            let size = match section.virtual_size {
                0 => section.raw_size,
                v => v,
            } as usize;
            if size == 0 {
                continue;
            }
            let protect = section_protect(section.characteristics);
            let remote = checked_add(remote_base, section.virtual_address as usize)? as *mut c_void;
            unsafe { sdk::protect(process, remote, size, protect)? };
        }
        Ok(())
    }

    unsafe fn call_tls(
        &self,
        process: *mut c_void,
        image: &[u8],
        remote_base: usize,
    ) -> Result<(), InjectError> {
        if self.tls.rva == 0 || self.tls.size < 32 {
            return Ok(());
        }
        for callback in self.tls_callbacks(image, remote_base)? {
            unsafe {
                let _ = sdk::remote_call3(process, callback, remote_base, DLL_PROCESS_ATTACH, 0)?;
            }
        }
        Ok(())
    }

    unsafe fn call_entry(
        &self,
        process: *mut c_void,
        remote_base: usize,
    ) -> Result<(), InjectError> {
        match self.entry(remote_base)? {
            Some(entry) => {
                match unsafe {
                    sdk::remote_call3(process, entry, remote_base, DLL_PROCESS_ATTACH, 0)?
                } {
                    0 => Err(InjectError::ManualMap("DllMain returned FALSE".into())),
                    _ => Ok(()),
                }
            }
            None => Ok(()),
        }
    }
}

fn section_protect(characteristics: u32) -> u32 {
    let executable = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let readable = characteristics & IMAGE_SCN_MEM_READ != 0;
    let writable = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    match (executable, readable, writable) {
        (true, _, true) => sdk::PAGE_EXECUTE_READWRITE,
        (true, _, false) => sdk::PAGE_EXECUTE_READ,
        (false, _, true) => sdk::PAGE_READWRITE,
        (false, true, false) => sdk::PAGE_READONLY,
        (false, false, false) => sdk::PAGE_NOACCESS,
    }
}
