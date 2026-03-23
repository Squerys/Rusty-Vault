#[cfg(target_os = "windows")]
pub unsafe fn resolve_rva(
    nt_headers: *const winapi::um::winnt::IMAGE_NT_HEADERS64,
    section_header_ptr: *const winapi::um::winnt::IMAGE_SECTION_HEADER,
    rva: u32
) -> usize {
    use winapi::um::winnt::IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;

    for i in 0..num_sections {
        let section = &*section_header_ptr.offset(i as isize);
        if rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData {
            return (rva - section.VirtualAddress + section.PointerToRawData) as usize;
        }
    }
    rva as usize
}
