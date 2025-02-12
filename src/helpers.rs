use std::ffi::CStr;
use windows::core::{PCSTR, PCWSTR, PWSTR};

pub trait WindowsStringHelpers {
    /// Transform a string/str to a PWSTR
    /// Note: Holding a reference to the Vec<u16> is a trick to keep the pointer used for the PWSTR in the same scope until it's freed
    fn to_pwstr(self) -> (PWSTR, Vec<u16>);
}

impl WindowsStringHelpers for &str {
    fn to_pwstr(self) -> (PWSTR, Vec<u16>) {
        let mut encoded = self.encode_utf16().chain([0u16]).collect::<Vec<u16>>();

        (PWSTR(encoded.as_mut_ptr()), encoded)
    }
}
impl WindowsStringHelpers for &String {
    fn to_pwstr(self) -> (PWSTR, Vec<u16>) {
        let mut encoded = self.encode_utf16().chain([0u16]).collect::<Vec<u16>>();

        (PWSTR(encoded.as_mut_ptr()), encoded)
    }
}

pub fn convert_pcwstr_to_string(pcwstr: PCWSTR) -> Option<String> {
    if pcwstr.is_null() {
        return None;
    }

    unsafe {
        // Find the length of the wide string (null-terminated)
        let mut len = 0;
        while *pcwstr.0.add(len) != 0 {
            len += 1;
        }

        // Create a slice of u16 from the PCWSTR
        let slice = std::slice::from_raw_parts(pcwstr.0, len);

        // Convert the UTF-16 slice to a Rust String
        String::from_utf16(slice).ok()
    }
}

pub fn convert_pcstr_to_string(pcstr: PCSTR) -> Option<String> {
    if pcstr.is_null() {
        return None; // Handle null pointers
    }
    unsafe {
        // Convert the PCSTR to a raw pointer and then to a CStr
        CStr::from_ptr(pcstr.0 as *const i8)
            .to_str() // Convert to &str
            .map(|s| s.to_string()) // Convert &str to String
            .ok() // Handle invalid UTF-8
    }
}
