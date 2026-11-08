//! Secure key-file creation and platform permission tests.

use super::temp_path;
use crate::{VaultKey, create_key_file};
use std::fs;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;

fn test_directory() -> PathBuf {
    let path = temp_path().with_extension("key-test");
    if let Err(error) = fs::create_dir_all(&path) {
        panic!("cannot create key-file test directory: {error}");
    }
    path
}

#[test]
fn generated_key_file_is_valid_private_and_never_overwrites() {
    let root = test_directory();
    let key_path = root.join("vault.key");
    if let Err(error) = create_key_file(&key_path) {
        panic!("cannot create key file: {error}");
    }
    match VaultKey::from_file(&key_path) {
        Ok(_) => {}
        Err(error) => panic!("generated key file failed validation: {error}"),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match fs::metadata(&key_path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777,
            Err(error) => panic!("cannot inspect generated key file: {error}"),
        };
        assert_eq!(mode, 0o600, "generated key file must be owner-only");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)) {
            panic!("cannot loosen existing key fixture: {error}");
        }
    }

    let original = match fs::read(&key_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read generated key file: {error}"),
    };
    assert!(create_key_file(&key_path).is_err());
    let unchanged = match fs::read(&key_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot re-read generated key file: {error}"),
    };
    assert_eq!(
        unchanged, original,
        "existing key file must not be overwritten"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match fs::metadata(&key_path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777,
            Err(error) => panic!("cannot inspect existing key file: {error}"),
        };
        assert_eq!(mode, 0o644, "existing permissions must not be changed");
    }
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn generated_key_file_overrides_inherited_broad_permissions() {
    let root = test_directory();
    let output_dir = root.join("inherited");
    let probe_path = output_dir.join("probe.txt");
    if let Err(error) = fs::create_dir(&output_dir) {
        panic!("cannot create inherited-ACL test directory: {error}");
    }

    let setup_parent = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
             $sddl = \"D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;WD)\"; \
             $sec = New-Object System.Security.AccessControl.DirectorySecurity; \
             $sec.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access); \
             [System.IO.Directory]::SetAccessControl('{}', $sec); \
             $dirAcl = [System.IO.Directory]::GetAccessControl('{}'); \
             $dirSddl = $dirAcl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if ($dirSddl -notmatch 'WD|S-1-1-0') {{ throw 'Everyone parent ACE missing' }} \
             [System.IO.File]::WriteAllText('{}', 'probe'); \
             $probeAcl = [System.IO.File]::GetAccessControl('{}'); \
             $probeSddl = $probeAcl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if ($probeSddl -notmatch 'WD|S-1-1-0') {{ throw 'Everyone ACE was not inherited' }} \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        output_dir.display(),
        output_dir.display(),
        probe_path.display(),
        probe_path.display()
    );
    run_powershell(&setup_parent, "setting inherited broad permissions");
    if let Err(error) = fs::remove_file(&probe_path) {
        panic!("cannot remove ACL test probe: {error}");
    }

    let initial_path = output_dir.join("initial.tmp");
    if let Err(error) = crate::key_file::create_temporary_file_for_test(&initial_path) {
        panic!("temporary key file was not private at creation: {error}");
    }
    let verify_initial_acl = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
             $acl = [System.IO.File]::GetAccessControl('{}'); \
             $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if (!$acl.AreAccessRulesProtected) {{ throw 'initial DACL is not protected' }} \
             if ($sddl -notmatch [regex]::Escape($sid)) {{ throw 'effective user SID is absent from initial DACL' }} \
             if ($sddl -match 'WD|S-1-1-0') {{ throw 'Everyone ACE was inherited at creation' }} \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        initial_path.display()
    );
    run_powershell(
        &verify_initial_acl,
        "checking temporary-file DACL at creation",
    );
    if let Err(error) = fs::remove_file(&initial_path) {
        panic!("cannot remove immediate-DACL test file: {error}");
    }

    let key_path = output_dir.join("vault.key");
    if let Err(error) = create_key_file(&key_path) {
        panic!("cannot create key under a broad inherited DACL: {error}");
    }
    match VaultKey::from_file(&key_path) {
        Ok(_) => {}
        Err(error) => panic!("generated key failed permission validation: {error}"),
    }

    let verify_acl = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
             $acl = [System.IO.File]::GetAccessControl('{}'); \
             $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if (!$acl.AreAccessRulesProtected) {{ throw 'key DACL is not protected' }} \
             if ($sddl -notmatch [regex]::Escape($sid)) {{ throw 'effective user SID is absent from key DACL' }} \
             if ($sddl -match 'WD|S-1-1-0') {{ throw 'Everyone ACE remained on key file' }} \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        key_path.display()
    );
    run_powershell(&verify_acl, "checking generated key DACL");
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn effective_token_sid_matches_windows_identity() {
    let sid = crate::key_file::current_user_sid()
        .unwrap_or_else(|| panic!("cannot read effective Windows token SID"));
    assert!(
        sid == powershell_current_user_sid(),
        "effective token SID must match WindowsIdentity.GetCurrent().User.Value"
    );
}

#[cfg(windows)]
fn powershell_current_user_sid() -> String {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => panic!(
            "PowerShell could not read the current Windows SID: {}",
            output.status
        ),
        Err(error) => panic!("cannot execute PowerShell to read the current Windows SID: {error}"),
    }
}

#[cfg(windows)]
#[test]
fn windows_key_file_acl_validation_rejects_unsafe_acl_changes() {
    let root = test_directory();
    let key_path = root.join("vault.key");
    if let Err(error) = fs::write(&key_path, format!("{}\n", "ab".repeat(32))) {
        panic!("cannot write ACL test key file: {error}");
    }
    match VaultKey::from_file(&key_path) {
        Ok(_) => {}
        Err(error) => assert!(error.to_string().contains("permissions")),
    }

    let broad_dacl = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
             $sddl = \"D:P(A;;FA;;;$sid)(A;;FR;;;WD)\"; \
             $sec = New-Object System.Security.AccessControl.FileSecurity; \
             $sec.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access); \
             [System.IO.File]::SetAccessControl('{}', $sec); \
             $acl = [System.IO.File]::GetAccessControl('{}'); \
             $actual = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if ($actual -notmatch 'WD|S-1-1-0') {{ throw 'Everyone ACE missing after ACL write' }} \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        key_path.display(),
        key_path.display()
    );
    run_powershell(&broad_dacl, "setting broad key-file permissions");
    assert!(
        create_key_file(&key_path).is_err(),
        "key creation must not replace an existing file"
    );
    let broad_dacl_remains = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $acl = [System.IO.File]::GetAccessControl('{}'); \
             $actual = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if ($actual -notmatch 'WD|S-1-1-0') {{ throw 'existing Everyone ACE was changed' }} \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        key_path.display()
    );
    run_powershell(&broad_dacl_remains, "checking existing ACL preservation");
    assert_permission_rejected(&key_path, "broad Everyone allow");

    let callback_dacl = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
             $sddl = \"D:P(A;;FA;;;$sid)(XA;;FR;;;WD;(Member_of {{SID(S-1-1-0)}}))\"; \
             $sec = New-Object System.Security.AccessControl.FileSecurity; \
             $sec.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access); \
             [System.IO.File]::SetAccessControl('{}', $sec); \
             $acl = [System.IO.File]::GetAccessControl('{}'); \
             $actual = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access); \
             if ($actual -notmatch 'XA') {{ throw 'callback ACE missing after ACL write' }} \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        key_path.display(),
        key_path.display()
    );
    run_powershell(&callback_dacl, "setting callback key-file permissions");
    assert_permission_rejected(&key_path, "callback allow");

    let null_dacl = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
             $sec = New-Object System.Security.AccessControl.FileSecurity; \
             $sec.SetSecurityDescriptorBinaryForm([byte[]]@(1,0,4,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), \
             [System.Security.AccessControl.AccessControlSections]::Access); \
             [System.IO.File]::SetAccessControl('{}', $sec) \
         }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}",
        key_path.display()
    );
    run_powershell(&null_dacl, "setting NULL-DACL key-file permissions");
    assert_permission_rejected(&key_path, "NULL DACL");
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
fn assert_permission_rejected(path: &Path, label: &str) {
    match VaultKey::from_file(path) {
        Ok(_) => panic!("{label} key file must be rejected"),
        Err(error) => assert!(
            error.to_string().contains("permissions"),
            "expected permissions error for {label}, got: {error}"
        ),
    }
}

#[cfg(windows)]
fn run_powershell(script: &str, description: &str) {
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .status();
    match status {
        Ok(status) => assert!(
            status.success(),
            "PowerShell failed while {description}: {status}"
        ),
        Err(error) => panic!("cannot execute PowerShell while {description}: {error}"),
    }
}
