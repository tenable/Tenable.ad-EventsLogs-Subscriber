use crate::constants::EMPTY_STRING;
use crate::setup::run_command;
use log::info;
use std::ffi::OsStr;

/// Wrapper around the gpupdate command
/// This is required as some GPO have specific CSE (Client-Side Extension) that can trigger an interactive input asking for a reboot of the system
/// When this happens, we will simply answer "N" as those warnings can be dismissed because the Tenable GPO is not concerned by this reboot
/// This is made to ensure that the program is not left waiting indefinitely on the command
pub fn force_gpo_update() -> anyhow::Result<String> {
    run_command("echo \"N\" | gpupdate /target:computer /force")?;
    return Ok(EMPTY_STRING.to_string());
}

pub fn get_powershell_output<S>(command: S) -> anyhow::Result<String>
where
    S: AsRef<OsStr>,
    S: std::fmt::Display,
{
    info!("Run powershell command:\r\n{command}");

    let output = std::process::Command::new("PowerShell")
        .arg(command)
        .output()?;

    if !output.status.success() {
        let error = String::from_utf8(output.stderr)?;
        return Err(anyhow::anyhow!(error));
    }

    let stdout = String::from_utf8(output.stdout)?;

    info!("Output of the command:\r\n{stdout}");

    Ok(stdout)
}

pub fn get_powershell_output_lossy<S>(command: S) -> anyhow::Result<String>
where
    S: AsRef<OsStr>,
    S: std::fmt::Display,
{
    info!("Run powershell command:\r\n{command}");

    let output = std::process::Command::new("PowerShell")
        .arg(command)
        .output()?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(error.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    info!("Output of the command:\r\n{stdout}");

    Ok(stdout)
}

/// PowerShell's output is a little bit difficult to handle in regard to encoding.
/// It's a bit of CP437, but when this code page doesn't work, it's falling back to
/// something else (yet undetermined).
/// The `get_powershell_unicode_output()` method handles such situations by passing
/// the PowerShell's command output to a file for which encoding is clearly defined
/// (UTF8 directly here) thus allowing safe reading.
///
/// ⚠️ this method uses a file to get the command's output, it's not recommended
/// to use it in code's hot paths.
pub fn get_powershell_unicode_output<S>(command: S) -> anyhow::Result<String>
where
    S: AsRef<OsStr>,
    S: std::fmt::Display,
{
    info!("Run powershell command through tmpfile:\r\n{command}");

    let file_path = tempfile::NamedTempFile::new()?.into_temp_path();
    let file_path = file_path.to_str().unwrap_or("default.tmp");

    let command =
        format!("$x = $({command}); [System.IO.File]::WriteAllLines(\"{file_path}\", $x)");
    info!("\r\nReal command:\r\n{command}");

    let output = std::process::Command::new("PowerShell")
        .arg("-c")
        .arg(command)
        .output()?;

    if !output.status.success() {
        let error = String::from_utf8(output.stderr)?;
        return Err(anyhow::anyhow!(error));
    }

    let stdout = std::fs::read_to_string(file_path)?;
    let _ = std::fs::remove_file(file_path);

    info!("\r\nOutput of the command:\r\n{stdout}");

    Ok(stdout)
}

#[cfg(test)]
mod tests {
    mod powershell {
        use super::super::*;

        #[test]
        fn ensure_ps_unicode_is_handling_non_ascii() {
            let test_str = "This is à tèst with non-ASCI£ charact€rs 🐼";
            let test_command = format!("Write-Output '{test_str}'");

            let output = get_powershell_unicode_output(test_command).unwrap();
            let output = output.trim();

            assert_eq!(test_str, output);
        }

        #[test]
        fn ensure_ps_unicode_is_handling_ascii_as_get_ps_output() {
            let test_str = "This is an ASCII test only (keep $$$ secured)";
            let test_command = format!("Write-Output '{test_str}'");

            let output1 = get_powershell_unicode_output(&test_command).unwrap();
            let output2 = get_powershell_output(&test_command).unwrap();

            assert_eq!(output1, output2);
        }

        #[test]
        fn ps_unicode_should_return_error_when_ps_command_is() {
            let result1 = get_powershell_unicode_output(
                "foobarbazquxquux - this shouldn't be a valid PS command",
            );
            let result2 = get_powershell_unicode_output("Write-Error 'Well...'");

            assert!(result1.is_err());
            assert!(result2.is_err());
        }
    }
}
