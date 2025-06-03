use super::constants::EMPTY_STRING;
use std::ffi::{CStr, OsString};
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::SUCCESS;
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Networking::ActiveDirectory::{
    DsGetDcNameA, DOMAIN_CONTROLLER_INFOA, DS_PDC_REQUIRED,
};

pub fn get_pdce_hostname() -> String {
    // Declare the buffer that will receive the PDCe information
    let mut pdce_information: *mut DOMAIN_CONTROLLER_INFOA = null_mut();
    unsafe {
        let result = DsGetDcNameA(
            PCSTR::default(),
            PCSTR::default(),
            null_mut(),
            PCSTR::default(),
            DS_PDC_REQUIRED,
            &mut pdce_information,
        );
        if result == SUCCESS {
            let domain_info = *pdce_information;
            let pdce_name = CStr::from_ptr(domain_info.DomainControllerName.0 as *const i8)
                .to_string_lossy()
                .into_owned();
            NetApiBufferFree(pdce_information as *mut _);
            return pdce_name[2..].to_string(); // Strip the first 2 \\;
        }
    }

    EMPTY_STRING.to_string()
}

pub trait WindowsStringHelpers {
    /// Transform a string/str to a PWSTR
    /// Note: Holding a reference to the Vec<u16> is a trick to keep the pointer used for the PWSTR in the same scope until it's freed
    fn to_pwstr(self) -> (PWSTR, Vec<u16>);
    /// Transform a string/str to a PCWSTR
    /// Note: Holding a reference to the Vec<u16> is a trick to keep the pointer used for the PWSTR in the same scope until it's freed
    fn to_pcwstr(self) -> (PCWSTR, Vec<u16>);
}

impl WindowsStringHelpers for &str {
    fn to_pwstr(self) -> (PWSTR, Vec<u16>) {
        let mut encoded = self.encode_utf16().chain([0u16]).collect::<Vec<u16>>();

        (PWSTR(encoded.as_mut_ptr()), encoded)
    }

    fn to_pcwstr(self) -> (PCWSTR, Vec<u16>) {
        let mut encoded = self
            .encode_utf16()
            .chain([0u16])
            .collect::<Vec<u16>>();

        (PCWSTR(encoded.as_mut_ptr()), encoded)
    }
}

impl WindowsStringHelpers for &String {
    fn to_pwstr(self) -> (PWSTR, Vec<u16>) {
        let mut encoded = self.encode_utf16().chain([0u16]).collect::<Vec<u16>>();

        (PWSTR(encoded.as_mut_ptr()), encoded)
    }

    fn to_pcwstr(self) -> (PCWSTR, Vec<u16>) {
        let mut encoded = self
            .encode_utf16()
            .chain([0u16])
            .collect::<Vec<u16>>();

        (PCWSTR(encoded.as_mut_ptr()), encoded)
    }
}

pub fn convert_pwstr_to_string(pwstr: PWSTR) -> String {
    if pwstr.0.is_null() {
        return String::new();
    }

    unsafe {
        // Find the length of the null-terminated string
        let len = (0..).take_while(|&i| *pwstr.0.offset(i) != 0).count();
        // Convert the wide string to a Rust OsString, then to String
        OsString::from_wide(std::slice::from_raw_parts(pwstr.0, len))
            .to_string_lossy()
            .into_owned()
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

pub fn sanitize_for_powershell<S>(input: S) -> String
where S: AsRef<str>
{
    return input
        .as_ref()
        .replace("'", "''") // Escape single quotes by doubling them
}

#[cfg(test)]
mod tests {
    mod sanitize_powershell {
        use crate::helpers::sanitize_for_powershell;

        #[test]
        fn it_should_remove_malicious_content() {
            // Arrange
            let input = "ACME\\testUser'; Remove-Item -Recurse C:\\Antivirus";
            // Act
            let sanitized = sanitize_for_powershell(&input);

            // Arrange
            assert_eq!(sanitized, "ACME\\testUser''; Remove-Item -Recurse C:\\Antivirus");
        }
    }
}