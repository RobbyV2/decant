use crate::InjectError;

pub(crate) const DLL_PROCESS_ATTACH: usize = 1;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const DLATTR_RVA: u32 = 1;
const IMAGE_LOAD_CONFIG_SECURITY_COOKIE_OFFSET64: usize = 0x58;
const DEFAULT_SECURITY_COOKIE_X64: u64 = 0x0000_2B99_2DDF_A232;
const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
const IMAGE_FILE_DLL: u32 = 0x2000;

#[derive(Clone, Copy)]
pub(crate) struct Dir {
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct Section {
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    #[allow(dead_code)]
    pub characteristics: u32,
}

#[derive(Clone, Copy)]
pub(crate) enum ImportSymbol<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
}

pub(crate) struct Pe {
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: usize,
    pub size_of_headers: usize,
    pub import: Dir,
    pub exception: Dir,
    pub reloc: Dir,
    pub tls: Dir,
    pub load_config: Dir,
    pub delay_import: Dir,
    pub export_dir: Dir,
    pub com_descriptor: Dir,
    pub sections: Vec<Section>,
    pub characteristics: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

impl Pe {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, InjectError> {
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
        let characteristics = u32_at(bytes, file + 18)?;
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
        let subsystem = u16_at(bytes, opt + 68)?;
        let dll_characteristics = u16_at(bytes, opt + 70)?;
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
            exception: dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION)?,
            reloc: dir(IMAGE_DIRECTORY_ENTRY_BASERELOC)?,
            tls: dir(IMAGE_DIRECTORY_ENTRY_TLS)?,
            load_config: dir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)?,
            delay_import: dir(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?,
            export_dir: dir(0)?,
            com_descriptor: dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?,
            sections,
            characteristics,
            subsystem,
            dll_characteristics,
        })
    }

    pub(crate) fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    pub(crate) fn is_exe(&self) -> bool {
        !self.is_dll() && self.subsystem != IMAGE_SUBSYSTEM_UNKNOWN
    }

    pub(crate) fn is_pure_il(&self) -> bool {
        self.com_descriptor.rva != 0 && self.com_descriptor.size != 0
    }

    pub(crate) fn manifest_id(&self, bytes: &[u8]) -> Result<Option<u32>, InjectError> {
        const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
        const RT_MANIFEST: u32 = 24;
        const RESOURCE_DIRECTORY_FLAG: u32 = 0x8000_0000;
        const MANIFEST_RESOURCE_ID: u32 = 1;
        let nt = u32_at(bytes, 0x3C)? as usize;
        let file = nt + 4;
        let opt = file + 20;
        let dir_count = u32_at(bytes, opt + 108)? as usize;
        if dir_count <= IMAGE_DIRECTORY_ENTRY_RESOURCE {
            return Ok(None);
        }
        let rsrc_off = opt + 112 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        let rsrc = Dir {
            rva: u32_at(bytes, rsrc_off)?,
            size: u32_at(bytes, rsrc_off + 4)?,
        };
        if rsrc.rva == 0 || rsrc.size == 0 {
            return Ok(None);
        }
        let Some(rsrc_file) = self.rva_to_file_offset(rsrc.rva) else {
            return Ok(None);
        };
        let rsrc_size = rsrc.size as usize;

        let Some(type_entry) = resource_directory_entries(bytes, rsrc_file, rsrc_size, 0)
            .and_then(|entries| entries.into_iter().find(|(id, _)| *id == RT_MANIFEST))
        else {
            return Ok(None);
        };
        if type_entry.1 & RESOURCE_DIRECTORY_FLAG == 0 {
            return Ok(None);
        }
        let type_dir = type_entry.1 & !RESOURCE_DIRECTORY_FLAG;

        let Some(name_entry) = resource_directory_entries(bytes, rsrc_file, rsrc_size, type_dir)
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|(id, _)| *id == MANIFEST_RESOURCE_ID)
            })
        else {
            return Ok(None);
        };
        if name_entry.1 & RESOURCE_DIRECTORY_FLAG == 0 {
            return Ok(None);
        }
        let language_dir = name_entry.1 & !RESOURCE_DIRECTORY_FLAG;

        let Some((_, data_entry)) =
            resource_directory_entries(bytes, rsrc_file, rsrc_size, language_dir).and_then(
                |entries| {
                    entries
                        .into_iter()
                        .find(|(_, offset)| offset & RESOURCE_DIRECTORY_FLAG == 0)
                },
            )
        else {
            return Ok(None);
        };
        let Some(data_entry_file) = rsrc_file.checked_add(data_entry as usize) else {
            return Ok(None);
        };
        let Some(data_entry_end) = data_entry_file.checked_add(16) else {
            return Ok(None);
        };
        let Some(resource_end) = rsrc_file.checked_add(rsrc_size) else {
            return Ok(None);
        };
        if data_entry_end > resource_end || data_entry_end > bytes.len() {
            return Ok(None);
        }
        let data_rva = u32_at(bytes, data_entry_file)?;
        let data_size = u32_at(bytes, data_entry_file + 4)? as usize;
        let Some(data_file) = self.rva_to_file_offset(data_rva) else {
            return Ok(None);
        };
        if data_size == 0
            || data_file
                .checked_add(data_size)
                .is_none_or(|end| end > bytes.len())
        {
            return Ok(None);
        }
        Ok(Some(MANIFEST_RESOURCE_ID))
    }

    fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers as u32 {
            return Some(rva as usize);
        }
        self.sections.iter().find_map(|section| {
            let span = section.virtual_size.max(section.raw_size);
            let delta = rva.checked_sub(section.virtual_address)?;
            if delta < span && delta < section.raw_size {
                Some(section.raw_ptr.checked_add(delta)? as usize)
            } else {
                None
            }
        })
    }

    pub(crate) fn mapped_image(&self, bytes: &[u8]) -> Result<Vec<u8>, InjectError> {
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

    pub(crate) fn apply_relocs(
        &self,
        image: &mut [u8],
        remote_base: u64,
    ) -> Result<(), InjectError> {
        if remote_base == self.image_base {
            return Ok(());
        }
        if !self.has_relocation_directory() {
            return mm(
                "image is not loaded at its preferred base and has no base relocation directory",
            );
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

    pub(crate) fn resolve_imports<E>(
        &self,
        image: &mut [u8],
        mut resolve: impl FnMut(&[u8], ImportSymbol<'_>) -> Result<usize, E>,
    ) -> Result<(), E>
    where
        E: From<InjectError>,
    {
        if self.import.rva == 0 || self.import.size == 0 {
            return Ok(());
        }
        let mut desc = self.import.rva as usize;
        loop {
            let original_first_thunk = u32_at(image, desc).map_err(E::from)?;
            let name_rva = u32_at(image, desc + 12).map_err(E::from)?;
            let first_thunk = u32_at(image, desc + 16).map_err(E::from)?;
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let module_name = cstr(image, name_rva as usize).map_err(E::from)?.to_vec();
            let lookup_rva = match original_first_thunk {
                0 => first_thunk,
                rva => rva,
            } as usize;
            let mut lookup = lookup_rva;
            let mut iat = first_thunk as usize;
            loop {
                let thunk = u64_at(image, lookup).map_err(E::from)?;
                if thunk == 0 {
                    break;
                }
                let proc = match thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                    true => resolve(&module_name, ImportSymbol::Ordinal((thunk & 0xFFFF) as u16))?,
                    false => {
                        let import_name = cstr(image, (thunk as usize) + 2).map_err(E::from)?;
                        resolve(&module_name, ImportSymbol::Name(import_name))?
                    }
                };
                put_u64(image, iat, proc as u64).map_err(E::from)?;
                lookup += 8;
                iat += 8;
            }
            desc += 20;
        }
        Ok(())
    }

    pub(crate) fn resolve_delay_imports<E>(
        &self,
        image: &mut [u8],
        mut resolve: impl FnMut(&[u8], ImportSymbol<'_>) -> Result<usize, E>,
    ) -> Result<(), E>
    where
        E: From<InjectError>,
    {
        if self.delay_import.rva == 0 || self.delay_import.size == 0 {
            return Ok(());
        }
        let mut desc = self.delay_import.rva as usize;
        loop {
            let attributes = u32_at(image, desc).map_err(E::from)?;
            let name_rva = u32_at(image, desc + 4).map_err(E::from)?;
            let iat_rva = u32_at(image, desc + 12).map_err(E::from)?;
            let int_rva = u32_at(image, desc + 16).map_err(E::from)?;
            if attributes == 0 && name_rva == 0 && iat_rva == 0 && int_rva == 0 {
                break;
            }
            if attributes & DLATTR_RVA == 0 {
                return Err(InjectError::ManualMap(
                    "delay import descriptor uses VA fields; only RVA delay imports are supported"
                        .into(),
                )
                .into());
            }
            let module_name = cstr(image, name_rva as usize).map_err(E::from)?.to_vec();
            let mut lookup = match int_rva {
                0 => iat_rva,
                rva => rva,
            } as usize;
            let mut iat = iat_rva as usize;
            loop {
                let thunk = u64_at(image, lookup).map_err(E::from)?;
                if thunk == 0 {
                    break;
                }
                let proc = match thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                    true => resolve(&module_name, ImportSymbol::Ordinal((thunk & 0xFFFF) as u16))?,
                    false => {
                        let import_name = cstr(image, (thunk as usize) + 2).map_err(E::from)?;
                        resolve(&module_name, ImportSymbol::Name(import_name))?
                    }
                };
                put_u64(image, iat, proc as u64).map_err(E::from)?;
                lookup += 8;
                iat += 8;
            }
            desc += 32;
        }
        Ok(())
    }

    pub(crate) fn has_exception_directory(&self) -> bool {
        self.exception.rva != 0 && self.exception.size != 0
    }

    pub(crate) fn has_load_config(&self) -> bool {
        self.load_config.rva != 0 && self.load_config.size != 0
    }

    pub(crate) fn seed_security_cookie(
        &self,
        image: &mut [u8],
        remote_base: u64,
        cookie: u64,
    ) -> Result<Option<u64>, InjectError> {
        if self.load_config.rva == 0
            || self.load_config.size < (IMAGE_LOAD_CONFIG_SECURITY_COOKIE_OFFSET64 + 8) as u32
        {
            return Ok(None);
        }
        let load_config = self.load_config.rva as usize;
        let cookie_va = u64_at(
            image,
            load_config + IMAGE_LOAD_CONFIG_SECURITY_COOKIE_OFFSET64,
        )?;
        if cookie_va == 0 {
            return Ok(None);
        }
        let cookie_offset = remote_va_to_offset(cookie_va, remote_base as usize, image.len())?;
        let current = u64_at(image, cookie_offset)?;
        if !security_cookie_needs_seed(current) {
            return Ok(None);
        }
        let cookie = normalize_security_cookie(cookie);
        put_u64(image, cookie_offset, cookie)?;
        Ok(Some(cookie))
    }

    pub(crate) fn has_relocation_directory(&self) -> bool {
        self.reloc.rva != 0 && self.reloc.size != 0
    }

    pub(crate) fn has_static_tls(&self, image: &[u8]) -> Result<bool, InjectError> {
        if self.tls.rva == 0 || self.tls.size < 32 {
            return Ok(false);
        }
        let tls = self.tls.rva as usize;
        let start_raw = u64_at(image, tls)?;
        let end_raw = u64_at(image, tls + 8)?;
        let index = u64_at(image, tls + 16)?;
        Ok(index != 0 || (start_raw != 0 && end_raw > start_raw))
    }

    pub(crate) fn tls_index_offset(
        &self,
        image: &[u8],
        remote_base: usize,
    ) -> Result<Option<usize>, InjectError> {
        if self.tls.rva == 0 || self.tls.size < 32 {
            return Ok(None);
        }
        let index_va = u64_at(image, self.tls.rva as usize + 16)?;
        if index_va == 0 {
            return Ok(None);
        }
        let offset = remote_va_to_offset(index_va, remote_base, image.len())?;
        Ok(Some(offset))
    }

    pub(crate) fn tls_template(
        &self,
        image: &[u8],
        remote_base: usize,
    ) -> Result<Option<Vec<u8>>, InjectError> {
        if self.tls.rva == 0 || self.tls.size < 32 {
            return Ok(None);
        }
        let tls = self.tls.rva as usize;
        let start_va = u64_at(image, tls)?;
        let end_va = u64_at(image, tls + 8)?;
        let zero_fill = u32_at(image, tls + 32)? as usize;
        if start_va == 0 || end_va == 0 || end_va < start_va {
            return Ok(Some(vec![0u8; zero_fill]));
        }
        let start_off = remote_va_to_offset(start_va, remote_base, image.len())?;
        let end_off = remote_va_to_offset(end_va, remote_base, image.len())?;
        let raw_len = end_off - start_off;
        let mut template = Vec::with_capacity(raw_len + zero_fill);
        template.extend_from_slice(&image[start_off..end_off]);
        template.resize(raw_len + zero_fill, 0);
        Ok(Some(template))
    }

    pub(crate) fn tls_callbacks(
        &self,
        image: &[u8],
        remote_base: usize,
    ) -> Result<Vec<usize>, InjectError> {
        if self.tls.rva == 0 || self.tls.size < 32 {
            return Ok(Vec::new());
        }
        let callbacks_va = u64_at(image, self.tls.rva as usize + 24)?;
        if callbacks_va == 0 {
            return Ok(Vec::new());
        }
        let mut off = remote_va_to_offset(callbacks_va, remote_base, image.len())?;
        let mut out = Vec::new();
        for _ in 0..256 {
            let callback = u64_at(image, off)?;
            if callback == 0 {
                return Ok(out);
            }
            out.push(callback as usize);
            off += 8;
        }
        mm("too many TLS callbacks")
    }

    pub(crate) fn entry(&self, remote_base: usize) -> Result<Option<usize>, InjectError> {
        match self.entry_rva {
            0 => Ok(None),
            rva => checked_add(remote_base, rva as usize).map(Some),
        }
    }

    pub(crate) fn cfg_call_targets(&self, image: &[u8]) -> Result<Vec<u32>, InjectError> {
        let mut targets = Vec::new();
        if self.entry_rva != 0 {
            targets.push(self.entry_rva);
        }
        if self.export_dir.rva == 0 || self.export_dir.size < 26 {
            return Ok(targets);
        }
        let exp = self.export_dir.rva as usize;
        let num_funcs = u32_at(image, exp + 20)? as usize;
        let func_rva = u32_at(image, exp + 28)? as usize;
        if func_rva == 0 || num_funcs == 0 {
            return Ok(targets);
        }
        for i in 0..num_funcs {
            let off = func_rva + i * 4;
            if off + 4 > image.len() {
                break;
            }
            let rva = u32_at(image, off)?;
            if rva != 0 {
                targets.push(rva);
            }
        }
        targets.sort_unstable();
        targets.dedup();
        Ok(targets)
    }
}

fn resource_directory_entries(
    bytes: &[u8],
    resource_file_base: usize,
    resource_size: usize,
    directory_offset: u32,
) -> Option<Vec<(u32, u32)>> {
    let resource_end = resource_file_base.checked_add(resource_size)?;
    let directory = resource_file_base.checked_add(directory_offset as usize)?;
    let directory_entries = directory.checked_add(16)?;
    if directory_entries > resource_end || directory_entries > bytes.len() {
        return None;
    }
    let named_count = u16_at(bytes, directory + 12).ok()? as usize;
    let id_count = u16_at(bytes, directory + 14).ok()? as usize;
    let total = named_count.checked_add(id_count)?;
    let entries_end = directory_entries.checked_add(total.checked_mul(8)?)?;
    if entries_end > resource_end || entries_end > bytes.len() {
        return None;
    }

    let mut entries = Vec::with_capacity(total);
    for i in 0..total {
        let entry = directory_entries + i * 8;
        let name_or_id = u32_at(bytes, entry).ok()?;
        let offset = u32_at(bytes, entry + 4).ok()?;
        if name_or_id & 0x8000_0000 == 0 {
            entries.push((name_or_id, offset));
        }
    }
    Some(entries)
}

pub(crate) fn checked_add(a: usize, b: usize) -> Result<usize, InjectError> {
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

fn security_cookie_needs_seed(value: u64) -> bool {
    matches!(value, 0 | DEFAULT_SECURITY_COOKIE_X64)
}

fn normalize_security_cookie(value: u64) -> u64 {
    let mut value = value & 0x0000_FFFF_FFFF_FFFF;
    if security_cookie_needs_seed(value) {
        value ^= 0x0000_A5A5_5A5A_9669;
    }
    value
}

pub(crate) fn cstr(image: &[u8], offset: usize) -> Result<&[u8], InjectError> {
    let rest = image
        .get(offset..)
        .ok_or_else(|| InjectError::ManualMap("string offset exceeds image bounds".into()))?;
    match rest.iter().position(|b| *b == 0) {
        Some(len) => Ok(&rest[..len]),
        None => mm("unterminated string"),
    }
}

pub(crate) fn u16_at(bytes: &[u8], off: usize) -> Result<u16, InjectError> {
    let b = bytes
        .get(off..off + 2)
        .ok_or_else(|| InjectError::ManualMap("read exceeds image bounds".into()))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn u32_at(bytes: &[u8], off: usize) -> Result<u32, InjectError> {
    let b = bytes
        .get(off..off + 4)
        .ok_or_else(|| InjectError::ManualMap("read exceeds image bounds".into()))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn u64_at(bytes: &[u8], off: usize) -> Result<u64, InjectError> {
    let b = bytes
        .get(off..off + 8)
        .ok_or_else(|| InjectError::ManualMap("read exceeds image bounds".into()))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

pub(crate) fn put_u64(bytes: &mut [u8], off: usize, value: u64) -> Result<(), InjectError> {
    let dst = bytes
        .get_mut(off..off + 8)
        .ok_or_else(|| InjectError::ManualMap("write exceeds image bounds".into()))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn mm<T>(message: &str) -> Result<T, InjectError> {
    Err(InjectError::ManualMap(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Pe {
        Pe {
            image_base: 0x1800_0000,
            entry_rva: 0,
            size_of_image: 0,
            size_of_headers: 0,
            import: Dir { rva: 0, size: 0 },
            exception: Dir { rva: 0, size: 0 },
            reloc: Dir { rva: 0, size: 0 },
            tls: Dir { rva: 0, size: 0 },
            load_config: Dir { rva: 0, size: 0 },
            delay_import: Dir { rva: 0, size: 0 },
            export_dir: Dir { rva: 0, size: 0 },
            com_descriptor: Dir { rva: 0, size: 0 },
            sections: Vec::new(),
            characteristics: 0,
            subsystem: 0,
            dll_characteristics: 0,
        }
    }

    #[test]
    fn fixed_image_can_only_load_at_preferred_base() {
        let pe = minimal_pe();
        let mut image = Vec::new();
        pe.apply_relocs(&mut image, pe.image_base).unwrap();
        let err = pe.apply_relocs(&mut image, pe.image_base + 0x1000);
        assert!(
            matches!(err, Err(InjectError::ManualMap(message)) if message.contains("no base relocation"))
        );
    }

    #[test]
    fn seed_security_cookie_updates_default_cookie() {
        let mut pe = minimal_pe();
        pe.image_base = 0x1800_0000;
        pe.size_of_image = 0x200;
        pe.load_config = Dir {
            rva: 0x40,
            size: 0x60,
        };
        let mut image = vec![0u8; pe.size_of_image];
        put_u64(
            &mut image,
            pe.load_config.rva as usize + IMAGE_LOAD_CONFIG_SECURITY_COOKIE_OFFSET64,
            pe.image_base + 0x100,
        )
        .unwrap();
        put_u64(&mut image, 0x100, DEFAULT_SECURITY_COOKIE_X64).unwrap();

        let seeded = pe
            .seed_security_cookie(&mut image, pe.image_base, 0x1234_5678)
            .unwrap();

        assert_eq!(seeded, Some(0x1234_5678));
        assert_eq!(u64_at(&image, 0x100).unwrap(), 0x1234_5678);
    }

    #[test]
    fn seed_security_cookie_preserves_nondefault_cookie() {
        let mut pe = minimal_pe();
        pe.image_base = 0x1800_0000;
        pe.size_of_image = 0x200;
        pe.load_config = Dir {
            rva: 0x40,
            size: 0x60,
        };
        let mut image = vec![0u8; pe.size_of_image];
        put_u64(
            &mut image,
            pe.load_config.rva as usize + IMAGE_LOAD_CONFIG_SECURITY_COOKIE_OFFSET64,
            pe.image_base + 0x100,
        )
        .unwrap();
        put_u64(&mut image, 0x100, 0xDEAD_BEEF).unwrap();

        let seeded = pe
            .seed_security_cookie(&mut image, pe.image_base, 0x1234_5678)
            .unwrap();

        assert_eq!(seeded, None);
        assert_eq!(u64_at(&image, 0x100).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn tls_index_offset_uses_remote_image_base() {
        let mut pe = minimal_pe();
        pe.size_of_image = 0x200;
        pe.tls = Dir {
            rva: 0x40,
            size: 0x28,
        };
        let remote_base = 0x7000_0000usize;
        let mut image = vec![0u8; pe.size_of_image];
        put_u64(
            &mut image,
            pe.tls.rva as usize + 16,
            remote_base as u64 + 0x120,
        )
        .unwrap();

        assert_eq!(
            pe.tls_index_offset(&image, remote_base).unwrap(),
            Some(0x120)
        );
    }

    #[test]
    fn manifest_lookup_decodes_resource_directories_from_file_offsets() {
        let mut pe = minimal_pe();
        pe.size_of_headers = 0x200;
        pe.sections.push(Section {
            virtual_size: 0x100,
            virtual_address: 0x3000,
            raw_size: 0x100,
            raw_ptr: 0x200,
            characteristics: 0,
        });

        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        let optional_header = 0x98usize;
        bytes[optional_header..optional_header + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        bytes[optional_header + 108..optional_header + 112].copy_from_slice(&16u32.to_le_bytes());
        let resource_directory = optional_header + 112 + 2 * 8;
        bytes[resource_directory..resource_directory + 4].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[resource_directory + 4..resource_directory + 8]
            .copy_from_slice(&0x100u32.to_le_bytes());

        let resource = 0x200usize;
        bytes[resource + 14..resource + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[resource + 16..resource + 20].copy_from_slice(&24u32.to_le_bytes());
        bytes[resource + 20..resource + 24].copy_from_slice(&0x8000_0020u32.to_le_bytes());

        bytes[resource + 0x20 + 14..resource + 0x20 + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[resource + 0x30..resource + 0x34].copy_from_slice(&1u32.to_le_bytes());
        bytes[resource + 0x34..resource + 0x38].copy_from_slice(&0x8000_0040u32.to_le_bytes());

        bytes[resource + 0x40 + 14..resource + 0x40 + 16].copy_from_slice(&1u16.to_le_bytes());
        bytes[resource + 0x50..resource + 0x54].copy_from_slice(&0x409u32.to_le_bytes());
        bytes[resource + 0x54..resource + 0x58].copy_from_slice(&0x60u32.to_le_bytes());

        bytes[resource + 0x60..resource + 0x64].copy_from_slice(&0x3080u32.to_le_bytes());
        bytes[resource + 0x64..resource + 0x68].copy_from_slice(&1u32.to_le_bytes());
        bytes[resource + 0x80] = b'<';

        assert_eq!(pe.manifest_id(&bytes).unwrap(), Some(1));
    }
}
