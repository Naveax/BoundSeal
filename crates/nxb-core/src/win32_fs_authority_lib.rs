#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod windows {
    use std::{
        ffi::{c_void, OsStr},
        fs::File,
        io,
        mem::{size_of, size_of_val},
        os::windows::{ffi::OsStrExt, io::{AsRawHandle, RawHandle}},
        path::{Component, Path},
        ptr,
    };

    const FILE_RENAME_INFO_CLASS: i32 = 3;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    /// ABI-compatible `FILE_RENAME_INFO` for `FileRenameInfo`.
    ///
    /// The first DWORD occupies the union containing `BOOLEAN ReplaceIfExists`
    /// and `DWORD Flags`. The backing buffer is zero-initialized, therefore
    /// `ReplaceIfExists` is FALSE for this no-replace operation.
    #[repr(C)]
    struct FileRenameInfo {
        replace_or_flags: u32,
        root_directory: RawHandle,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileInformationByHandle"]
        fn get_file_information_by_handle(
            file: RawHandle,
            information: *mut ByHandleFileInformation,
        ) -> i32;

        #[link_name = "SetFileInformationByHandle"]
        fn set_file_information_by_handle(
            file: RawHandle,
            information_class: i32,
            information: *mut c_void,
            buffer_size: u32,
        ) -> i32;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileIdentity {
        pub volume_serial_number: u32,
        pub file_index: u64,
    }

    pub fn file_identity(file: &File) -> io::Result<FileIdentity> {
        let mut information = ByHandleFileInformation::default();

        // SAFETY: `file` owns a live Windows handle for the complete call and
        // `information` is a valid writable ABI-compatible output structure.
        let succeeded = unsafe {
            get_file_information_by_handle(file.as_raw_handle(), &raw mut information)
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(FileIdentity {
            volume_serial_number: information.volume_serial_number,
            file_index: (u64::from(information.file_index_high) << 32)
                | u64::from(information.file_index_low),
        })
    }

    pub fn rename_handle_relative_no_replace(
        file: &File,
        parent: &File,
        new_name: &OsStr,
    ) -> io::Result<()> {
        validate_literal_child_name(new_name)?;
        let wide = new_name.encode_wide().collect::<Vec<_>>();
        if wide.is_empty() || wide.iter().any(|value| *value == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Win32 rename destination name is empty or contains NUL",
            ));
        }

        let name_bytes = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Win32 rename destination name is too large",
                )
            })?;
        let extra_bytes = wide
            .len()
            .saturating_sub(1)
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Win32 rename information size overflow",
                )
            })?;
        let buffer_bytes = size_of::<FileRenameInfo>()
            .checked_add(extra_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Win32 rename information size overflow",
                )
            })?;
        let word_bytes = size_of::<usize>();
        let words = buffer_bytes
            .checked_add(word_bytes - 1)
            .map(|value| value / word_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Win32 rename information allocation overflow",
                )
            })?;
        let mut storage = vec![0_usize; words];
        if size_of_val(storage.as_slice()) < buffer_bytes {
            return Err(io::Error::other(
                "Win32 rename information allocation is shorter than requested",
            ));
        }

        let information = storage.as_mut_ptr().cast::<FileRenameInfo>();
        let buffer_size = u32::try_from(buffer_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Win32 rename information exceeds DWORD length",
            )
        })?;

        // SAFETY: `storage` is zero-initialized and aligned to `usize`, which
        // satisfies the FILE_RENAME_INFO ABI on supported Windows targets. It
        // is sized for the fixed header plus the complete UTF-16 name. `file`
        // and `parent` remain alive across the call. A zero first DWORD means
        // ReplaceIfExists = FALSE. `new_name` is one literal child component,
        // so RootDirectory is the retained parent authority for resolution.
        let succeeded = unsafe {
            (*information).root_directory = parent.as_raw_handle();
            (*information).file_name_length = name_bytes;
            ptr::copy_nonoverlapping(
                wide.as_ptr(),
                (*information).file_name.as_mut_ptr(),
                wide.len(),
            );
            set_file_information_by_handle(
                file.as_raw_handle(),
                FILE_RENAME_INFO_CLASS,
                information.cast::<c_void>(),
                buffer_size,
            )
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn validate_literal_child_name(name: &OsStr) -> io::Result<()> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Win32 rename destination must be one literal child name",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            os::windows::fs::OpenOptionsExt,
            path::PathBuf,
            time::{SystemTime, UNIX_EPOCH},
        };

        const DELETE: u32 = 0x0001_0000;
        const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        fn root(name: &str) -> PathBuf {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock predates Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "nxb-win32-authority-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            path
        }

        fn parent_handle(path: &Path) -> File {
            fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .unwrap()
        }

        fn retained_file(path: &Path) -> File {
            fs::OpenOptions::new()
                .access_mode(GENERIC_READ | DELETE)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .unwrap()
        }

        fn verification_file(path: &Path) -> File {
            fs::OpenOptions::new()
                .access_mode(GENERIC_READ)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .unwrap()
        }

        #[test]
        fn handle_relative_rename_preserves_exact_identity() {
            let root = root("identity");
            let source = root.join("workspace.json");
            fs::write(&source, b"old\n").unwrap();
            let parent = parent_handle(&root);
            let retained = retained_file(&source);
            let before = file_identity(&retained).unwrap();

            rename_handle_relative_no_replace(&retained, &parent, OsStr::new("retired.json"))
                .unwrap();

            assert!(!source.exists());
            let retired = verification_file(&root.join("retired.json"));
            assert_eq!(file_identity(&retired).unwrap(), before);
            assert_eq!(fs::read(root.join("retired.json")).unwrap(), b"old\n");
            drop(retired);
            drop(retained);
            drop(parent);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn no_replace_rename_preserves_existing_destination() {
            let root = root("no-replace");
            let source = root.join("workspace.json");
            let destination = root.join("retired.json");
            fs::write(&source, b"old\n").unwrap();
            fs::write(&destination, b"foreign\n").unwrap();
            let parent = parent_handle(&root);
            let retained = retained_file(&source);

            assert!(rename_handle_relative_no_replace(
                &retained,
                &parent,
                OsStr::new("retired.json")
            )
            .is_err());
            assert_eq!(fs::read(&source).unwrap(), b"old\n");
            assert_eq!(fs::read(&destination).unwrap(), b"foreign\n");

            drop(retained);
            drop(parent);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn source_handle_denies_rename_until_retained_authority_is_released() {
            let root = root("share-deny");
            let source = root.join("workspace.json");
            let moved = root.join("workspace-moved.json");
            fs::write(&source, b"old\n").unwrap();
            let retained = retained_file(&source);

            assert!(fs::rename(&source, &moved).is_err());
            assert_eq!(fs::read(&source).unwrap(), b"old\n");
            drop(retained);

            fs::rename(&source, &moved).unwrap();
            assert_eq!(fs::read(&moved).unwrap(), b"old\n");
            fs::remove_dir_all(root).unwrap();
        }
    }
}

#[cfg(windows)]
pub use windows::{file_identity, rename_handle_relative_no_replace, FileIdentity};
