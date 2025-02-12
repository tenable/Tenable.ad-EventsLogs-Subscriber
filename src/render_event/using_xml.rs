use super::super::constants::*;
use chrono::{DateTime, Utc};
use core::ffi::c_void;
use minidom::Element;
use roxmltree::{Document, Node};
use std::ptr::null_mut;
use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows::Win32::System::EventLog::*;

pub fn render_event_using_xml(h_event: isize, flag: u32) -> String {
    let mut buffersize = 0;
    let mut bufferused: u32 = 0;
    let mut properties_count: u32 = 0;

    unsafe {
        let _buffer_search = EvtRender(
            0,
            h_event,
            flag,
            buffersize,
            null_mut(),
            &mut bufferused as *mut u32,
            null_mut(),
        )
        .as_bool();

        let status = GetLastError();
        if status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER {
            return EMPTY_STRING.to_string();
        }

        buffersize = bufferused;
        let mut rendered_values: Vec<u16> = vec![0; buffersize as usize];

        let render_result = EvtRender(
            0,
            h_event,
            flag,
            buffersize,
            rendered_values.as_mut_ptr() as *mut c_void,
            &mut bufferused,
            &mut properties_count,
        )
        .as_bool();

        if !render_result {
            return EMPTY_STRING.to_string();
        }

        build_event_log_record_using_minidom(rendered_values)
    }
}

////////////////// minidom //////////////////

fn build_event_log_record_using_minidom(rendered_values: Vec<u16>) -> String {
    let read_xml = String::from_utf16_lossy(&rendered_values[..])
        .trim_matches(char::from(0))
        .to_string();

    let root: Element = match read_xml.parse() {
        Ok(c) => c,
        Err(_e) => return EMPTY_STRING.to_string(),
    };

    let mut root_children = root.children();

    // System
    let event_system_option = root_children.next();
    let event_system = match event_system_option {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let mut system_properties = event_system.children();
    let provider_name_option = match system_properties.next() {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let provider_name = match provider_name_option.attr(NAME) {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };

    let event_id = match system_properties.next() {
        Some(n) => n.text(),
        None => return EMPTY_STRING.to_string(),
    };

    let mut prop_count = 0;
    let created_date_time_raw_option = loop {
        prop_count += 1;
        if prop_count == 7 {
            return EMPTY_STRING.to_string();
        }

        break match system_properties.next() {
            Some(n) if n.name() == TIME_CREATED => n,
            _ => continue,
        };
    };

    let created_date_time_raw = match created_date_time_raw_option.attr(SYSTEM_TIME) {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let created_date_time_option = match created_date_time_raw.parse::<DateTime<Utc>>() {
        Ok(c) => c,
        Err(_e) => return EMPTY_STRING.to_string(),
    };
    let created_date_time = created_date_time_option.format(DATE_TIME_FORMAT);

    prop_count = 0;
    let mut process_id = "";
    let mut thread_id = "";
    let empty = EMPTY_STRING.to_string();
    while prop_count < 4 {
        let execution = match system_properties.next() {
            Some(n) if n.name() == EXECUTION => n,
            _ => {
                prop_count += 1;
                continue;
            }
        };

        process_id = match execution.attr(PROCESS_ID) {
            Some(n) => n,
            None => &empty,
        };

        thread_id = match execution.attr(THREAD_ID) {
            Some(n) => n,
            None => &empty,
        };

        break;
    }

    // Data
    let event_data = match root_children.next() {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let event_data_properties = event_data.children();
    let mut event_data_strings = String::new();
    let mut last_property_has_no_data = false;
    let mut data_properties_count = 0;
    for data_prop in event_data_properties {
        let prop_text = data_prop.text();
        last_property_has_no_data = prop_text == EMPTY_STRING;

        event_data_strings = format!(
            "{}{}",
            event_data_strings,
            format!("{}{}{}{}", QUOTE, data_prop.text(), QUOTE, DATA_DELIMITER)
        );

        data_properties_count = data_properties_count + 1;
    }

    // Handle eventual event data sub node
    if (data_properties_count == 1) && last_property_has_no_data {
        event_data_strings.clear();

        let event_sub_data = match event_data.children().next() {
            Some(n) => n,
            None => return EMPTY_STRING.to_string(),
        };

        event_data_strings = build_sub_event_data_using_minidom(event_sub_data);
    }

    let event_data_strings = remove_last_chars(&event_data_strings, 2);

    format!(
        "({})#{}##{}##{}#######{}#{}###########\n",
        event_data_strings, event_id, provider_name, created_date_time, process_id, thread_id
    )
}

fn build_sub_event_data_using_minidom(event_sub_data: &Element) -> String {
    let mut event_data_strings = String::new();
    let event_sub_data_properties = event_sub_data.children();

    for data_prop in event_sub_data_properties {
        event_data_strings = format!(
            "{}{}",
            event_data_strings,
            format!("{}{}{}{}", QUOTE, data_prop.text(), QUOTE, DATA_DELIMITER)
        );
    }

    event_data_strings
}

////////////////// roxmltree //////////////////

fn build_event_log_record_using_roxmltree(rendered_values: Vec<u16>) -> String {
    // let start = Instant::now();
    let read_xml = String::from_utf16_lossy(&rendered_values[..])
        .trim_matches(char::from(0))
        .to_string();

    let root: Document = match roxmltree::Document::parse(&read_xml) {
        Ok(c) => c,
        Err(_e) => return EMPTY_STRING.to_string(),
    };

    let mut root_children = root.root_element().children().filter(Node::is_element);

    // System
    let event_system_option = root_children.next();
    let event_system = match event_system_option {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let mut system_properties = event_system.children().filter(Node::is_element);
    let provider_name_option = match system_properties.next() {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let provider_name = match provider_name_option.attribute(NAME) {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };

    let event_id_option = match system_properties.next() {
        Some(n) => n.text(),
        None => None,
    };

    let event_id = match event_id_option {
        Some(text) => text,
        None => return EMPTY_STRING.to_string(),
    };

    let mut prop_count = 0;
    let created_date_time_raw_option = loop {
        prop_count += 1;
        if prop_count == 7 {
            return EMPTY_STRING.to_string();
        }

        break match system_properties.next() {
            Some(n) if n.tag_name().name() == TIME_CREATED => n,
            _ => continue,
        };
    };

    let created_date_time_raw = match created_date_time_raw_option.attribute(SYSTEM_TIME) {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let created_date_time_option = match created_date_time_raw.parse::<DateTime<Utc>>() {
        Ok(c) => c,
        Err(_e) => return EMPTY_STRING.to_string(),
    };
    let created_date_time = created_date_time_option.format(DATE_TIME_FORMAT);

    prop_count = 0;
    let mut process_id = "";
    let mut thread_id = "";
    let empty = EMPTY_STRING.to_string();
    while prop_count < 4 {
        let execution = match system_properties.next() {
            Some(n) if n.tag_name().name() == EXECUTION => n,
            _ => {
                prop_count += 1;
                continue;
            }
        };

        process_id = match execution.attribute(PROCESS_ID) {
            Some(n) => n,
            None => &empty,
        };

        thread_id = match execution.attribute(THREAD_ID) {
            Some(n) => n,
            None => &empty,
        };

        break;
    }

    // Data
    let event_data = match root_children.next() {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let event_data_properties = event_data.children().filter(Node::is_element);
    let mut event_data_strings = String::new();
    let mut last_property_has_no_data = false;
    let mut data_properties_count = 0;
    for data_prop in event_data_properties {
        let prop_text = data_prop.text().unwrap_or(EMPTY_STRING);
        last_property_has_no_data = prop_text == EMPTY_STRING;

        event_data_strings = format!(
            "{}{}",
            event_data_strings,
            format!("{}{}{}{}", QUOTE, prop_text, QUOTE, DATA_DELIMITER)
        );

        data_properties_count = data_properties_count + 1;
    }

    // Handle eventual event data sub node
    if (data_properties_count == 1) && last_property_has_no_data {
        event_data_strings.clear();

        let event_sub_data = match event_data.children().filter(Node::is_element).next() {
            Some(n) => n,
            None => return EMPTY_STRING.to_string(),
        };

        event_data_strings = build_sub_event_data_using_roxmltree(&event_sub_data);
    }

    let event_data_strings = remove_last_chars(&event_data_strings, 2);

    format!(
        "({})#{}##{}##{}#######{}#{}###########\n",
        event_data_strings, event_id, provider_name, created_date_time, process_id, thread_id
    )
}

fn build_sub_event_data_using_roxmltree(event_sub_data: &Node) -> String {
    let mut event_data_strings = String::new();
    let event_sub_data_properties = event_sub_data.children().filter(Node::is_element);

    for data_prop in event_sub_data_properties {
        let data = data_prop.text().unwrap_or(EMPTY_STRING);
        event_data_strings = format!(
            "{}{}",
            event_data_strings,
            format!("{}{}{}{}", QUOTE, data, QUOTE, DATA_DELIMITER)
        );
    }

    event_data_strings
}

fn remove_last_chars(s: &String, n: usize) -> &str {
    if n == 0 {
        return s;
    }

    let len = s.len();
    if n > len {
        return EMPTY_STRING;
    }

    let (result, _) = s.split_at(len - n);
    result
}

mod remove_last_chars {
    use super::*;

    #[test]
    fn it_should_not_remove_0_chars() {
        // Arrange
        let s = String::from("Hello, world!");
        let n = 0;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "Hello, world!");
    }

    #[test]
    fn it_should_remove_the_last_char() {
        // Arrange
        let s = String::from("Hello, world!");
        let n = 1;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "Hello, world");
    }

    #[test]
    fn it_should_remove_the_last_2_chars() {
        // Arrange
        let s = String::from("Hello, world!");
        let n = 2;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "Hello, worl");
    }

    #[test]
    fn it_should_remove_all_chars() {
        // Arrange
        let s = String::from("Hello, world!");
        let n = s.len();

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "");
    }

    #[test]
    fn it_should_remove_all_chars_on_overflow() {
        // Arrange
        let s = String::from("Hello, world!");
        let n = s.len() + 1;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "");
    }

    #[test]
    fn it_should_remove_all_chars_when_the_string_has_the_same_size() {
        // Arrange
        let s = String::from("HW");
        let n = s.len() + 1;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "");
    }

    #[test]
    fn it_should_remove_all_chars_when_the_string_is_too_small() {
        // Arrange
        let s = String::from("H");
        let n = s.len() + 1;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "");
    }

    #[test]
    fn it_should_remove_all_chars_when_the_string_is_empty() {
        // Arrange
        let s = String::from("");
        let n = s.len() + 1;

        // Act
        let s = remove_last_chars(&s, n);

        // Assert
        assert_eq!(s, "");
    }
}

mod build_event_log_record {
    use super::*;
    use windows::core::HSTRING;

    #[test]
    fn it_should_convert_an_xml_event_to_an_event_log() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                        Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" />\
              <EventID>4688</EventID>\
              <Version>2</Version>\
              <Level>0</Level>\
              <Task>13312</Task>\
              <Opcode>0</Opcode>\
              <Keywords>0x8020000000000000</Keywords>\
              <TimeCreated SystemTime=\"2022-08-01T14:03:19.253078100Z\" />\
              <EventRecordID>3784135</EventRecordID>\
              <Correlation />\
              <Execution ProcessID=\"4\" ThreadID=\"3120\" />\
              <Channel>Security</Channel>\
              <Computer>DC-ROOT.ROOT.DOMAIN</Computer>\
              <Security />\
             </System>\
             <EventData>\
              <Data Name=\"SubjectUserSid\">S-1-5-18</Data>\
              <Data Name=\"SubjectUserName\">DC-ROOT$</Data>\
              <Data Name=\"SubjectDomainName\">ROOT</Data>\
              <Data Name=\"SubjectLogonId\">0x3e7</Data>\
              <Data Name=\"NewProcessId\">0x1638</Data>\
              <Data Name=\"NewProcessName\"> \
               C:\\Windows\\System32\\backgroundTaskHost.exe\
              </Data>\
              <Data Name=\"TokenElevationType\">%%1936</Data>\
              <Data Name=\"ProcessId\">0x3a0</Data>\
              <Data Name=\"CommandLine\"> \
               \"C:\\Windows\\system32\\backgroundTaskHost.exe\" \
               -ServerName:CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca</Data>\
              <Data Name=\"TargetUserSid\">S-1-0-0</Data>\
              <Data Name=\"TargetUserName\">administrator</Data>\
              <Data Name=\"TargetDomainName\">ROOT</Data>\
              <Data Name=\"TargetLogonId\">0x77260</Data>\
              <Data Name=\"ParentProcessName\">C:\\Windows\\System32\\svchost.exe</Data>\
              <Data Name=\"MandatoryLabel\">S-1-16-4096</Data>\
             </EventData>\
            </Event>",
        );
        let expected_result = "(\"S-1-5-18\"\u{1f}\u{1e}\
            \"DC-ROOT$\"\u{1f}\u{1e}\
            \"ROOT\"\u{1f}\u{1e}\
            \"0x3e7\"\u{1f}\u{1e}\
            \"0x1638\"\u{1f}\u{1e}\
            \" C:\\Windows\\System32\\backgroundTaskHost.exe\"\u{1f}\u{1e}\
            \"%%1936\"\u{1f}\u{1e}\
            \"0x3a0\"\u{1f}\u{1e}\
            \" \"C:\\Windows\\system32\\backgroundTaskHost.exe\" \
            -ServerName:CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca\"\u{1f}\u{1e}\
            \"S-1-0-0\"\u{1f}\u{1e}\
            \"administrator\"\u{1f}\u{1e}\
            \"ROOT\"\u{1f}\u{1e}\
            \"0x77260\"\u{1f}\u{1e}\
            \"C:\\Windows\\System32\\svchost.exe\"\u{1f}\u{1e}\
            \"S-1-16-4096\")\
            #4688##Microsoft-Windows-Security-Auditing#\
            #20220801140319.253078-000#######4#3120###########\n";

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, expected_result);
        assert_eq!(roxmltree_result, expected_result);
    }

    #[test]
    fn it_should_convert_an_xml_event_with_a_different_system_node_to_en_event_log() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                <System>\
                    <Provider Name=\"VSSAudit\" />\
                    <EventID Qualifiers=\"0\">8222</EventID>\
                    <Level>0</Level>\
                    <Task>3</Task>\
                    <Keywords>0x80a0000000000000</Keywords>\
                    <TimeCreated SystemTime=\"2022-08-04T13:28:22.517359200Z\" />\
                    <EventRecordID>3986554</EventRecordID>\
                    <Channel>Security</Channel>\
                    <Computer>DC-ROOT.ROOT.DOMAIN</Computer>\
                    <Security UserID=\"S-1-5-18\" />\
                </System>\
                <EventData>\
                    <Data>S-1-5-21-3770311822-3616871986-1308186358-11269</Data>\
                    <Data>ROOT\\AttackerAdmin</Data>\
                    <Data>0x0000000000001630</Data>\
                    <Data>C:\\Windows\\System32\\esentutl.exe</Data>\
                    <Data>{f9f78cf6-f380-4c9e-93d0-fe3a03bc03b7}</Data>\
                    <Data>{abc28faa-32a4-4b26-a0da-b18c9471f751}</Data>\
                    <Data>{b5946137-7b9f-4925-af80-51abd60b20d5}</Data>\
                    <Data>DC-ROOT.ROOT.DOMAIN</Data>\
                    <Data>\\\\?\\Volume{ca4a3263-dfab-48ee-a67f-d64e5ef1ee5c}\\</Data>\
                    <Data>\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy14</Data>\
                </EventData>\
            </Event>",
        );
        let expected_result = "(\"S-1-5-21-3770311822-3616871986-1308186358-11269\"\u{1f}\u{1e}\
        \"ROOT\\AttackerAdmin\"\u{1f}\u{1e}\
        \"0x0000000000001630\"\u{1f}\u{1e}\
        \"C:\\Windows\\System32\\esentutl.exe\"\u{1f}\u{1e}\
        \"{f9f78cf6-f380-4c9e-93d0-fe3a03bc03b7}\"\u{1f}\u{1e}\
        \"{abc28faa-32a4-4b26-a0da-b18c9471f751}\"\u{1f}\u{1e}\
        \"{b5946137-7b9f-4925-af80-51abd60b20d5}\"\u{1f}\u{1e}\
        \"DC-ROOT.ROOT.DOMAIN\"\u{1f}\u{1e}\
        \"\\\\?\\Volume{ca4a3263-dfab-48ee-a67f-d64e5ef1ee5c}\\\"\u{1f}\u{1e}\
        \"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy14\")\
        #8222##VSSAudit##20220804132822.517359-000###################\n";

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, expected_result);
        assert_eq!(roxmltree_result, expected_result);
    }

    #[test]
    fn it_should_convert_an_efs_xml_event_to_an_event_log() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
              <System>\
                <Provider Name=\"Microsoft-Windows-EFS\" \
                          Guid=\"{3663a992-84be-40ea-bba9-90c7ed544222}\" />\
                <EventID>1</EventID>\
                <Version>0</Version>\
                <Level>2</Level>\
                <Task>0</Task>\
                <Opcode>0</Opcode>\
                <Keywords>0x8000000000000000</Keywords>\
                <TimeCreated SystemTime=\"2022-08-03T16:03:02.067389300Z\" />\
                <EventRecordID>19867</EventRecordID>\
                <Correlation />\
                <Execution ProcessID=\"716\" ThreadID=\"4816\" />\
                <Channel>Microsoft-Windows-EFS/Debug</Channel>\
                <Computer>DC-ROOT.ROOT.DOMAIN</Computer>\
                <Security UserID=\"S-1-5-18\" />\
              </System>\
              <UserData>\
                <EfsLogString1Data xmlns=\"http://schemas.microsoft.com/schemas/event/\
                                           Microsoft.Windows/1.0.0.0\">\
                  <FileNumber>6</FileNumber>\
                  <LineNumber>4769</LineNumber>\
                  <Param>53</Param>\
                </EfsLogString1Data>\
              </UserData>\
            </Event>",
        );

        let expected_result = "(\"6\"\u{1f}\u{1e}\"4769\"\u{1f}\u{1e}\"53\")\
            #1##Microsoft-Windows-EFS##20220803160302.067389-000#######716#4816###########\n";

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, expected_result);
        assert_eq!(roxmltree_result, expected_result);
    }

    #[test]
    fn it_should_convert_an_xml_event_to_an_event_log_with_no_data_when_no_data() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                        Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
              <EventID>4688</EventID> \
              <Version>2</Version> \
              <Level>0</Level> \
              <Task>13312</Task> \
              <Opcode>0</Opcode> \
              <Keywords>0x8020000000000000</Keywords> \
              <TimeCreated SystemTime=\"2022-08-01T14:03:19.253078100Z\" /> \
              <EventRecordID>3784135</EventRecordID> \
              <Correlation /> \
              <Execution ProcessID=\"4\" ThreadID=\"3120\" /> \
              <Channel>Security</Channel> \
              <Computer>DC-ROOT.ROOT.DOMAIN</Computer> \
              <Security /> \
             </System>\
             <EventData>\
             </EventData> \
            </Event>",
        );
        let expected_result = "()#4688##Microsoft-Windows-Security-Auditing#\
            #20220801140319.253078-000#######4#3120###########\n";

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, expected_result);
        assert_eq!(roxmltree_result, expected_result);
    }

    #[test]
    fn it_should_return_an_empty_string_when_root_has_no_children() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
            </Event>",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empty_string_when_system_has_no_children() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
             </System>\
             <EventData>\
             </EventData> \
            </Event>",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empty_string_when_provider_has_no_name() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
             </System>\
             <EventData>\
             </EventData> \
            </Event>",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empty_string_when_there_is_no_event_id() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                        Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
             </System>\
             <EventData>\
             </EventData> \
            </Event>",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empry_string_when_there_is_no_time_created() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                        Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
              <EventID>4688</EventID> \
              <Version>2</Version> \
              <Level>0</Level> \
              <Task>13312</Task> \
              <Opcode>0</Opcode> \
              <Keywords>0x8020000000000000</Keywords> \
             </System>\
             <EventData>\
             </EventData> \
            </Event>",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empty_string_when_there_is_no_event_data() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                        Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
              <EventID>4688</EventID> \
              <Version>2</Version> \
              <Level>0</Level> \
              <Task>13312</Task> \
              <Opcode>0</Opcode> \
              <Keywords>0x8020000000000000</Keywords> \
              <TimeCreated SystemTime=\"2022-08-01T14:03:19.253078100Z\" /> \
              <EventRecordID>3784135</EventRecordID> \
              <Correlation /> \
              <Execution ProcessID=\"4\" ThreadID=\"3120\" /> \
              <Channel>Security</Channel> \
              <Computer>DC-ROOT.ROOT.DOMAIN</Computer> \
              <Security /> \
             </System>\
            </Event>",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empty_string_when_given_an_invalid_xml() {
        // Arrange
        let event = HSTRING::from(
            "\
            <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System>\
              <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                        Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
            ...",
        );

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }

    #[test]
    fn it_should_return_an_empty_string_when_given_an_empty_string() {
        // Arrange
        let event = HSTRING::from("");

        // Act
        let minidom_result = build_event_log_record_using_minidom(event.as_wide().to_vec());
        let roxmltree_result = build_event_log_record_using_roxmltree(event.as_wide().to_vec());

        // Assert
        assert_eq!(minidom_result, "");
        assert_eq!(roxmltree_result, "");
    }
}
