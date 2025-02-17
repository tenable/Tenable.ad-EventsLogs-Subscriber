use super::super::constants::*;
use super::super::helpers::{convert_pcstr_to_string, convert_pcwstr_to_string};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use core::ffi::c_void;
use log::debug;
use std::ffi::CStr;
use std::ptr::null_mut;
use windows::core::{GUID, PCSTR, PWSTR};
use windows::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, PSID, SYSTEMTIME,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::System::EventLog::*;

struct EventData {
    pub props: Vec<u16>,
    pub count: u32,
}

struct SystemEventData {
    pub event_id: String,
    pub provider_name: String,
    pub created_date_time: String,
    pub process_id: String,
    pub thread_id: String,
}

pub unsafe fn render_event_using_values(h_event: isize) -> String {
    let system_props = match render_event_props(h_event, EvtRenderContextSystem) {
        Some(s) => s,
        None => return EMPTY_STRING.to_string(),
    };

    let user_props = match render_event_props(h_event, EvtRenderContextUser) {
        Some(s) => s,
        None => return EMPTY_STRING.to_string(),
    };

    let system_data: SystemEventData = match format_system_data_from_values(&system_props) {
        Some(value) => value,
        None => return EMPTY_STRING.to_string(),
    };

    let user_data = match format_user_data_from_values(&user_props) {
        Some(value) => value,
        None => return EMPTY_STRING.to_string(),
    };

    format!(
        "({})#{}##{}##{}#######{}#{}###########\n",
        user_data,
        system_data.event_id,
        system_data.provider_name,
        system_data.created_date_time,
        system_data.process_id,
        system_data.thread_id
    )
}

unsafe fn render_event_props(h_event: isize, flag: EVT_RENDER_CONTEXT_FLAGS) -> Option<EventData> {
    let mut buffersize = 0;
    let mut bufferused: u32 = 0;
    let mut properties_count: u32 = 0;
    let valuePaths: &[::windows::core::PWSTR] = &[];
    let renderFlags = EvtRenderEventValues.0 as u32;

    let hContext = EvtCreateRenderContext(valuePaths, flag.0 as u32);

    let _buffer_search = EvtRender(
        hContext,
        h_event,
        renderFlags,
        buffersize,
        null_mut(),
        &mut bufferused as *mut u32,
        null_mut(),
    )
    .as_bool();

    let status = GetLastError();
    if status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    buffersize = bufferused;
    let mut rendered_values: Vec<u16> = vec![0; buffersize as usize];

    EvtRender(
        hContext,
        h_event,
        renderFlags,
        buffersize,
        rendered_values.as_mut_ptr() as *mut c_void,
        &mut bufferused,
        &mut properties_count,
    )
    .as_bool();

    let event_data: EventData = EventData {
        props: rendered_values,
        count: properties_count,
    };

    EvtClose(hContext);

    Some(event_data)
}

unsafe fn format_system_data_from_values(system_data: &EventData) -> Option<SystemEventData> {
    let mut event_id: String = EMPTY_STRING.to_string();
    let mut provider_name: String = EMPTY_STRING.to_string();
    let mut created_date_time: String = EMPTY_STRING.to_string();
    let mut process_id: String = EMPTY_STRING.to_string();
    let mut thread_id: String = EMPTY_STRING.to_string();

    let system_variant_array = system_data.props.as_ptr() as *const EVT_VARIANT;

    for property_id in 0..system_data.count {
        let system_variant = *system_variant_array.add(property_id as usize);
        let system_property = EVT_SYSTEM_PROPERTY_ID(property_id as i32);

        match system_property {
            EvtSystemEventID => {
                event_id = system_variant.Anonymous.UInt16Val.to_string();
            }
            EvtSystemProviderName => {
                provider_name = match as_string_option(&system_variant) {
                    Some(value) => value,
                    None => return None,
                }
            }
            EvtSystemTimeCreated => {
                let filetime_value = system_variant.Anonymous.FileTimeVal;
                let utc_date_time = convert_fileTime_to_utc_datetime(filetime_value);
                created_date_time = utc_date_time.format(DATE_TIME_FORMAT).to_string()
            }
            EvtSystemProcessID => {
                process_id = match system_variant.Anonymous.UInt32Val {
                    0 => EMPTY_STRING.to_string(),
                    v => v.to_string(),
                }
            }
            EvtSystemThreadID => {
                thread_id = match system_variant.Anonymous.UInt32Val {
                    0 => EMPTY_STRING.to_string(),
                    v => v.to_string(),
                }
            }
            _ => {}
        }
    }

    let system_event_data = SystemEventData {
        event_id: event_id,
        provider_name: provider_name,
        created_date_time: created_date_time,
        process_id: process_id,
        thread_id: thread_id,
    };

    Some(system_event_data)
}

unsafe fn format_user_data_from_values(user_data: &EventData) -> Option<String> {
    let user_variant_array = user_data.props.as_ptr() as *const EVT_VARIANT;
    let mut user_properties: Vec<String> = Vec::with_capacity(user_data.count as usize);

    for property_id in 0..user_data.count {
        let user_variant = *user_variant_array.add(property_id as usize);
        let vType = user_variant.Type as i32;
        let variant_type = EVT_VARIANT_TYPE(vType);
        match variant_type {
            EvtVarTypeNull => (),
            EvtVarTypeString => match as_string_option(&user_variant) {
                Some(value) => {
                    let normalized_value = value.replace("\r\n", "\n");
                    user_properties.push(normalized_value);
                }
                None => (),
            },
            EvtVarTypeAnsiString => {
                let ansi_val: PCSTR = user_variant.Anonymous.AnsiStringVal;
                let st = convert_pcstr_to_string(ansi_val);
                match st {
                    Some(value) => {
                        let normalized_value = value.replace("\r\n", "\n");
                        user_properties.push(normalized_value)
                    }
                    None => (),
                }
            }
            EvtVarTypeSByte => {
                let s_byte = user_variant.Anonymous.SByteVal;
                let s_byte_st = s_byte.to_string();
                user_properties.push(s_byte_st);
            }
            EvtVarTypeByte => {
                let byte_val = user_variant.Anonymous.ByteVal;
                let byte_val_st = byte_val.to_string();
                user_properties.push(byte_val_st);
            }
            EvtVarTypeInt16 => {
                let i16_value = user_variant.Anonymous.Int16Val;
                let i16_st = i16_value.to_string();
                user_properties.push(i16_st);
            }
            EvtVarTypeInt32 => {
                let i32_value = user_variant.Anonymous.Int32Val;
                let i32_st = i32_value.to_string();
                user_properties.push(i32_st);
            }
            EvtVarTypeInt64 => {
                let i64_value = user_variant.Anonymous.Int64Val;
                let i64_st = i64_value.to_string();
                user_properties.push(i64_st);
            }
            EvtVarTypeSid => {
                let psid = user_variant.Anonymous.SidVal;
                let s_psid = convert_sid_to_string(psid);
                match s_psid {
                    Some(value) => user_properties.push(value),
                    None => (),
                }
            }
            EvtVarTypeUInt16 => {
                let value = user_variant.Anonymous.UInt16Val.to_string();
                user_properties.push(value);
            }
            EvtVarTypeUInt32 => {
                let value = user_variant.Anonymous.UInt32Val.to_string();
                user_properties.push(value);
            }
            EvtVarTypeUInt64 => {
                let value = user_variant.Anonymous.UInt64Val.to_string();
                user_properties.push(value);
            }
            EvtVarTypeSingle => {
                let single_value = user_variant.Anonymous.SingleVal.to_string();
                user_properties.push(single_value);
            }
            EvtVarTypeBoolean => {
                let boolean_value = match user_variant.Anonymous.BooleanVal {
                    windows::Win32::Foundation::BOOL(0) => "false".to_string(),
                    _ => "true".to_string(),
                };
                user_properties.push(boolean_value);
            }
            EvtVarTypeBinary => {
                let bValue = user_variant.Anonymous.BinaryVal;
                match convert_mut_ptr_to_string(bValue) {
                    Some(value) => user_properties.push(value),
                    None => (),
                }
            }
            EvtVarTypeGuid => {
                let guidValue = user_variant.Anonymous.GuidVal;
                match convert_guid_to_string(guidValue) {
                    Some(value) => user_properties.push(value),
                    None => (),
                }
            }
            EvtVarTypeSizeT => {
                let value = user_variant.Anonymous.SizeTVal.to_string();
                user_properties.push(value);
            }
            EvtVarTypeDouble => {
                let double_value = user_variant.Anonymous.DoubleVal.to_string();
                user_properties.push(double_value);
            }
            EvtVarTypeHexInt32 => {
                let u_value: u32 = user_variant.Anonymous.UInt32Val;
                let value = format!("0x{:x}", u_value);
                user_properties.push(value);
            }
            EvtVarTypeHexInt64 => {
                let u_value = user_variant.Anonymous.UInt64Val;
                let value = format!("0x{:x}", u_value);
                user_properties.push(value);
            }
            EvtVarTypeSysTime => {
                let sys_time_value = user_variant.Anonymous.SysTimeVal;
                match convert_systemtime_to_utc_string(sys_time_value) {
                    Some(value) => user_properties.push(value),
                    None => (),
                }
            }
            EvtVarTypeFileTime => {
                let file_time_value = user_variant.Anonymous.FileTimeVal;
                let file_time_utc_value = convert_fileTime_to_utc_datetime(file_time_value);
                let file_time_st_value: String = file_time_utc_value
                    .format("%Y-%m-%dT%H:%M:%S%.fZ")
                    .to_string();
                user_properties.push(file_time_st_value);
            }
            EvtVarTypeEvtHandle => (),
            EvtVarTypeEvtXml => {
                let xml_val = user_variant.Anonymous.XmlVal;
                match convert_pcwstr_to_string(xml_val) {
                    Some(value) => user_properties.push(value),
                    None => (),
                }
            }
            _ => debug!("Find un-matching type '{vType}'",),
        }
    }

    if user_properties.is_empty() {
        return None;
    }

    let formatted_user_data = user_properties.iter().fold(String::new(), |mut acc, word| {
        if acc.is_empty() {
            acc.push_str(format!("{}{}{}", QUOTE, word, QUOTE).as_str());
            return acc;
        }
        acc.push_str(format!("{}{}{}{}", DATA_DELIMITER, QUOTE, word, QUOTE).as_str());
        acc
    });
    Some(formatted_user_data)
}

fn convert_systemtime_to_utc_string(systemtime_ptr: *mut SYSTEMTIME) -> Option<String> {
    if systemtime_ptr.is_null() {
        return None; // Return None if the pointer is null
    }

    unsafe {
        // Dereference the pointer to access the SYSTEMTIME struct
        let systemtime = &*systemtime_ptr;

        // Create a NaiveDateTime using the SYSTEMTIME fields
        let naive = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd(
                systemtime.wYear as i32,
                systemtime.wMonth as u32,
                systemtime.wDay as u32,
            ),
            chrono::NaiveTime::from_hms(
                systemtime.wHour as u32,
                systemtime.wMinute as u32,
                systemtime.wSecond as u32,
            ),
        );

        // Convert to UTC DateTime
        let utc = Utc.from_utc_datetime(&naive);

        // Format the DateTime as a string (e.g., "2025-01-13T12:34:56Z")
        Some(utc.to_rfc3339())
    }
}

fn convert_fileTime_to_utc_datetime(filetime_value: u64) -> DateTime<Utc> {
    // FILETIME is based on 100-nanosecond intervals since January 1, 1601.
    let seconds_since_epoch = (filetime_value / 10_000_000) as i64 - FILETIME_TO_UNIX_EPOCH_SECS;
    let nanoseconds = ((filetime_value % 10_000_000) * 100) as u32;

    Utc.timestamp(seconds_since_epoch, nanoseconds)
}
fn convert_guid_to_string(guid_ptr: *mut GUID) -> Option<String> {
    if guid_ptr.is_null() {
        return None; // Return None if the pointer is null
    }

    unsafe {
        // Dereference the pointer to access the GUID
        let guid = &*guid_ptr;

        // Format the GUID as a string in the standard {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} format
        Some(format!(
            "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
            guid.data1,
            guid.data2,
            guid.data3,
            (guid.data4[0] as u16) << 8 | guid.data4[1] as u16,
            u64::from(guid.data4[2]) << 40
                | u64::from(guid.data4[3]) << 32
                | u64::from(guid.data4[4]) << 24
                | u64::from(guid.data4[5]) << 16
                | u64::from(guid.data4[6]) << 8
                | u64::from(guid.data4[7])
        ))
    }
}

fn convert_mut_ptr_to_string(ptr: *mut u8) -> Option<String> {
    if ptr.is_null() {
        return None; // Return None if the pointer is null
    }

    unsafe {
        // Treat the *mut u8 pointer as a null-terminated C string
        let c_str = CStr::from_ptr(ptr as *const i8); // Convert *mut u8 to *const i8
        match c_str.to_str() {
            Ok(str) => Some(str.to_string()), // Convert to String
            Err(_) => None,                   // Return None if invalid UTF-8
        }
    }
}

unsafe fn convert_sid_to_string(psid: PSID) -> Option<String> {
    let mut string_sid_ptr: PWSTR = PWSTR(null_mut());

    if ConvertSidToStringSidW(psid, &mut string_sid_ptr).as_bool() {
        if string_sid_ptr.is_null() {
            return None;
        }

        let mut end = string_sid_ptr.0;

        while *end != 0 {
            end = end.add(1);
        }

        let result = String::from_utf16_lossy(std::slice::from_raw_parts(
            string_sid_ptr.0,
            end.offset_from(string_sid_ptr.0) as _,
        ));

        windows::Win32::System::Memory::LocalFree(string_sid_ptr.0 as _);

        Some(result)
    } else {
        // Failed to convert
        None
    }
}

unsafe fn as_string_option(v: &EVT_VARIANT) -> Option<String> {
    let string_val = v.Anonymous.StringVal;

    if string_val.is_null() {
        return None;
    }

    let count = v.Count as usize;
    let wide_str: &[u16] = std::slice::from_raw_parts(string_val.0, count);
    Some(String::from_utf16_lossy(wide_str))
}

mod convert_systemtime_to_utc_string {
    use super::*;

    #[test]
    fn it_should_convert_SYSTEMTIME_to_a_UTC_string() {
        let mut systemtime = SYSTEMTIME {
            wYear: 2025,
            wMonth: 1,
            wDay: 13,
            wHour: 12,
            wMinute: 34,
            wSecond: 56,
            wMilliseconds: 0,
            ..Default::default()
        };
        let systemtime_ptr: *mut SYSTEMTIME = &mut systemtime;

        let systemtime = convert_systemtime_to_utc_string(systemtime_ptr);

        assert_eq!(systemtime, Some("2025-01-13T12:34:56+00:00".to_string()));
    }
}

mod convert_guid_to_string {
    use super::*;

    #[test]
    fn it_should_convert_guid_to_string() {
        let guid = GUID::from_u128(0xD3B6B6F798AA4A5FB84A4106185D0D9D);
        let guid_ptr: *mut GUID = &guid as *const GUID as *mut GUID;

        let guid_st = convert_guid_to_string(guid_ptr);

        assert_eq!(
            guid_st,
            Some("{D3B6B6F7-98AA-4A5F-B84A-4106185D0D9D}".to_string())
        );
    }
}

mod convert_sid_to_string {
    use super::*;
    use std::ptr;
    use windows::Win32::Security::{AllocateAndInitializeSid, FreeSid, SID_IDENTIFIER_AUTHORITY};

    unsafe fn create_psid() -> Option<PSID> {
        // SID_IDENTIFIER_AUTHORITY for the NT Authority (predefined)
        let authority = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5],
        };

        // Initialize a SID for the "Administrators" group (RID = 544)
        let psid: *mut windows::Win32::Foundation::PSID = &mut PSID(ptr::null_mut());

        // Allocate and initialize the SID
        let success = AllocateAndInitializeSid(
            &authority, 2,   // Number of sub-authorities
            21,  // SECURITY_BUILTIN_DOMAIN_RID (well-known RID for Built-in group)
            544, // SECURITY_GROUP_RID_ADMINISTRATORS (well-known RID for Administrators group)
            0, 0, 0, 0, 0, 0, psid,
        );

        if success.as_bool() {
            Some(*psid) // Return the created PSID
        } else {
            None // Return None if the creation fails
        }
    }

    #[test]
    fn it_should_convert_sid_to_string() {
        unsafe {
            let psid: PSID = create_psid().unwrap();

            let sid = convert_sid_to_string(psid);

            assert_eq!(sid, Some("S-1-5-21-544".to_string()));

            FreeSid(psid);
        }
    }
}

mod convert_fileTime_to_utc_datetime {
    use super::*;

    #[test]
    fn it_should_convert_system_fileTime_to_created_date_time() {
        // UTC String: 2025-01-13T12:00:00Z
        let time: u64 = 133812438622695655;

        let utc_date_time = convert_fileTime_to_utc_datetime(time);
        let created_date_time = utc_date_time.format(DATE_TIME_FORMAT).to_string();

        assert_eq!(created_date_time, "20250113121102.269565-000".to_string());
    }

    #[test]
    fn it_should_convert_user_fileTime_to_utc_datetime() {
        let file_time_value: u64 = 19422069751480403;
        let file_time_utc_value = convert_fileTime_to_utc_datetime(file_time_value);
        let file_time_st_value: String = file_time_utc_value
            .format("%Y-%m-%dT%H:%M:%S%.fZ")
            .to_string();

        assert_eq!(
            file_time_st_value,
            "1662-07-19T05:56:15.148040300Z".to_string()
        );
    }
}
