use std::collections::HashMap;
use std::ffi::c_void;

use crate::{InjectError, InjectionRequest, Injector, LoadInfo, Portability, sdk};

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const DLL_PROCESS_ATTACH: usize = 1;

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
            pe.resolve_imports(proc, &mut image)?;
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

#[derive(Clone, Copy)]
struct Dir {
    rva: u32,
    size: u32,
}

#[derive(Clone, Copy)]
struct Section {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
}

struct Pe {
    image_base: u64,
    entry_rva: u32,
    size_of_image: usize,
    size_of_headers: usize,
    import: Dir,
    reloc: Dir,
    tls: Dir,
    sections: Vec<Section>,
}

impl Pe {
    fn parse(bytes: &[u8]) -> Result<Self, InjectError> {
        match u16_at(bytes, 0)? {
            0x5A4D => {}
            _ => return mm("missing MZ header"),
        }
        let nt = u32_at(bytes, 0x3C)? as usize;
        match u32_at(bytes, nt)? {
            0x0000_4550 => {}
            _ => return mm("missing PE header"),
        }
        let file = nt + 4;
        match u16_at(bytes, file)? {
            0x8664 => {}
            _ => return mm("only x86_64 PE images are supported"),
        }
        let section_count = u16_at(bytes, file + 2)? as usize;
        let optional_size = u16_at(bytes, file + 16)? as usize;
        let opt = file + 20;
        match u16_at(bytes, opt)? {
            0x20B => {}
            _ => return mm("only PE32+ images are supported"),
        }
        let entry_rva = u32_at(bytes, opt + 16)?;
        let image_base = u64_at(bytes, opt + 24)?;
        let size_of_image = u32_at(bytes, opt + 56)? as usize;
        let size_of_headers = u32_at(bytes, opt + 60)? as usize;
        let dir_count = u32_at(bytes, opt + 108)? as usize;
        let dir = |idx| -> Result<Dir, InjectError> {
            match idx < dir_count {
                true => {
                    let off = opt + 112 + idx * 8;
                    Ok(Dir {
                        rva: u32_at(bytes, off)?,
                        size: u32_at(bytes, off + 4)?,
                    })
                }
                false => Ok(Dir { rva: 0, size: 0 }),
            }
        };
        let section_table = opt + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let off = section_table + i * 40;
            sections.push(Section {
                virtual_size: u32_at(bytes, off + 8)?,
                virtual_address: u32_at(bytes, off + 12)?,
                raw_size: u32_at(bytes, off + 16)?,
                raw_ptr: u32_at(bytes, off + 20)?,
                characteristics: u32_at(bytes, off + 36)?,
            });
        }
        Ok(Self {
            image_base,
            entry_rva,
            size_of_image,
            size_of_headers,
            import: dir(IMAGE_DIRECTORY_ENTRY_IMPORT)?,
            reloc: dir(IMAGE_DIRECTORY_ENTRY_BASERELOC)?,
            tls: dir(IMAGE_DIRECTORY_ENTRY_TLS)?,
            sections,
        })
    }

    fn mapped_image(&self, bytes: &[u8]) -> Result<Vec<u8>, InjectError> {
        let mut image = vec![0u8; self.size_of_image];
        let header_len = self.size_of_headers.min(bytes.len()).min(image.len());
        image[..header_len].copy_from_slice(&bytes[..header_len]);
        for section in &self.sections {
            let dst = section.virtual_address as usize;
            let src = section.raw_ptr as usize;
            let raw_size = section.raw_size as usize;
            if raw_size == 0 || section.raw_ptr == 0 {
                continue;
            }
            let copy_len = match section.virtual_size {
                0 => raw_size,
                v => raw_size.min(v as usize),
            };
            let src_end = checked_add(src, copy_len)?;
            let dst_end = checked_add(dst, copy_len)?;
            match (bytes.get(src..src_end), image.get_mut(dst..dst_end)) {
                (Some(src_slice), Some(dst_slice)) => dst_slice.copy_from_slice(src_slice),
                _ => return mm("section exceeds image bounds"),
            }
        }
        Ok(image)
    }

    fn apply_relocs(&self, image: &mut [u8], remote_base: u64) -> Result<(), InjectError> {
        if remote_base == self.image_base || self.reloc.rva == 0 || self.reloc.size == 0 {
            return Ok(());
        }
        let delta = remote_base.wrapping_sub(self.image_base);
        let mut pos = self.reloc.rva as usize;
        let end = checked_add(pos, self.reloc.size as usize)?;
        while pos + 8 <= end {
            let page_rva = u32_at(image, pos)? as usize;
            let block_size = u32_at(image, pos + 4)? as usize;
            if block_size < 8 {
                return mm("invalid relocation block");
            }
            let entries = (block_size - 8) / 2;
            pos += 8;
            for i in 0..entries {
                let entry = u16_at(image, pos + i * 2)?;
                let kind = entry >> 12;
                let off = (entry & 0x0FFF) as usize;
                match kind {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_DIR64 => {
                        let loc = checked_add(page_rva, off)?;
                        let patched = u64_at(image, loc)?.wrapping_add(delta);
                        put_u64(image, loc, patched)?;
                    }
                    _ => return mm("unsupported relocation type"),
                }
            }
            pos += entries * 2;
        }
        Ok(())
    }

    unsafe fn resolve_imports(
        &self,
        process: *mut c_void,
        image: &mut [u8],
    ) -> Result<(), InjectError> {
        if self.import.rva == 0 || self.import.size == 0 {
            return Ok(());
        }
        let mut modules: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut desc = self.import.rva as usize;
        loop {
            let original_first_thunk = u32_at(image, desc)?;
            let name_rva = u32_at(image, desc + 12)?;
            let first_thunk = u32_at(image, desc + 16)?;
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let module_name = cstr(image, name_rva as usize)?.to_vec();
            let module = match modules.get(&module_name) {
                Some(module) => *module,
                None => {
                    let module = unsafe { sdk::remote_load_library(process, &module_name)? };
                    modules.insert(module_name.clone(), module);
                    module
                }
            };
            let lookup_rva = match original_first_thunk {
                0 => first_thunk,
                rva => rva,
            } as usize;
            let mut lookup = lookup_rva;
            let mut iat = first_thunk as usize;
            loop {
                let thunk = u64_at(image, lookup)?;
                if thunk == 0 {
                    break;
                }
                let proc = match thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                    true => unsafe {
                        sdk::remote_get_proc_address_ordinal(
                            process,
                            module,
                            (thunk & 0xFFFF) as u16,
                        )?
                    },
                    false => {
                        let import_name = cstr(image, (thunk as usize) + 2)?.to_vec();
                        unsafe { sdk::remote_get_proc_address_name(process, module, &import_name)? }
                    }
                };
                put_u64(image, iat, proc as u64)?;
                lookup += 8;
                iat += 8;
            }
            desc += 20;
        }
        Ok(())
    }

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
        let callbacks_va = u64_at(image, self.tls.rva as usize + 24)?;
        if callbacks_va == 0 {
            return Ok(());
        }
        let mut off = remote_va_to_offset(callbacks_va, remote_base, image.len())?;
        for _ in 0..256 {
            let callback = u64_at(image, off)?;
            if callback == 0 {
                return Ok(());
            }
            unsafe {
                let _ = sdk::remote_call3(
                    process,
                    callback as usize,
                    remote_base,
                    DLL_PROCESS_ATTACH,
                    0,
                )?;
            }
            off += 8;
        }
        mm("too many TLS callbacks")
    }

    unsafe fn call_entry(
        &self,
        process: *mut c_void,
        remote_base: usize,
    ) -> Result<(), InjectError> {
        if self.entry_rva == 0 {
            return Ok(());
        }
        let entry = checked_add(remote_base, self.entry_rva as usize)?;
        match unsafe { sdk::remote_call3(process, entry, remote_base, DLL_PROCESS_ATTACH, 0)? } {
            0 => mm("DllMain returned FALSE"),
            _ => Ok(()),
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

fn checked_add(a: usize, b: usize) -> Result<usize, InjectError> {
    a.checked_add(b)
        .ok_or_else(|| InjectError::ManualMap("integer overflow".into()))
}

fn remote_va_to_offset(
    va: u64,
    remote_base: usize,
    image_len: usize,
) -> Result<usize, InjectError> {
    let off = va
        .checked_sub(remote_base as u64)
        .ok_or_else(|| InjectError::ManualMap("remote VA precedes image base".into()))?
        as usize;
    match off < image_len {
        true => Ok(off),
        false => mm("remote VA exceeds image bounds"),
    }
}

fn cstr(image: &[u8], offset: usize) -> Result<&[u8], InjectError> {
    let rest = image
        .get(offset..)
        .ok_or_else(|| InjectError::ManualMap("string offset exceeds image bounds".into()))?;
    match rest.iter().position(|b| *b == 0) {
        Some(len) => Ok(&rest[..len]),
        None => mm("unterminated string"),
    }
}

fn u16_at(bytes: &[u8], off: usize) -> Result<u16, InjectError> {
    let b = bytes
        .get(off..off + 2)
        .ok_or_else(|| InjectError::ManualMap("read exceeds image bounds".into()))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], off: usize) -> Result<u32, InjectError> {
    let b = bytes
        .get(off..off + 4)
        .ok_or_else(|| InjectError::ManualMap("read exceeds image bounds".into()))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(bytes: &[u8], off: usize) -> Result<u64, InjectError> {
    let b = bytes
        .get(off..off + 8)
        .ok_or_else(|| InjectError::ManualMap("read exceeds image bounds".into()))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn put_u64(bytes: &mut [u8], off: usize, value: u64) -> Result<(), InjectError> {
    let dst = bytes
        .get_mut(off..off + 8)
        .ok_or_else(|| InjectError::ManualMap("write exceeds image bounds".into()))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn mm<T>(message: &str) -> Result<T, InjectError> {
    Err(InjectError::ManualMap(message.into()))
}
