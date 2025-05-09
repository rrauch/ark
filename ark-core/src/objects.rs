#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObjectType {
    FileSystem(FileSystem),
    Email(Email),
    ObjectStorage(ObjectStorage),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FileSystem {
    Posix,
    Windows,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Email {
    IMAP,
    GMAIL,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObjectStorage {
    S3,
}

pub mod protos {
    use crate::objects::protos::Gmail as ProtoGmail;
    use crate::objects::protos::Imap as ProtoImap;
    use crate::objects::protos::Posix as ProtoPosix;
    use crate::objects::protos::S3 as ProtoS3;
    use crate::objects::protos::Windows as ProtoWindows;
    use crate::objects::protos::email::EmailType;
    use crate::objects::protos::filesystem::FilesystemType;
    use crate::objects::protos::object_storage::StorageType;
    use crate::objects::protos::object_type::Type;
    use anyhow::anyhow;

    include!(concat!(env!("OUT_DIR"), "/protos/objects.rs"));

    impl From<super::ObjectType> for ObjectType {
        fn from(value: super::ObjectType) -> Self {
            Self {
                r#type: Some(value.into()),
            }
        }
    }

    impl TryFrom<ObjectType> for super::ObjectType {
        type Error = anyhow::Error;

        fn try_from(value: ObjectType) -> Result<Self, Self::Error> {
            value
                .r#type
                .ok_or(anyhow!("invalid object_type"))
                .and_then(|s| match s {
                    Type::Filesystem(fs) => {
                        let fs = fs.try_into()?;
                        Ok(super::ObjectType::FileSystem(fs))
                    }
                    Type::Email(email) => {
                        let email = email.try_into()?;
                        Ok(super::ObjectType::Email(email))
                    }
                    Type::ObjectStorage(os) => {
                        let os = os.try_into()?;
                        Ok(super::ObjectType::ObjectStorage(os))
                    }
                })
        }
    }

    impl From<super::ObjectType> for Type {
        fn from(value: super::ObjectType) -> Self {
            match value {
                super::ObjectType::FileSystem(fs) => Type::Filesystem(fs.into()),
                super::ObjectType::Email(email) => Type::Email(email.into()),
                super::ObjectType::ObjectStorage(os) => Type::ObjectStorage(os.into()),
            }
        }
    }

    impl From<super::ObjectStorage> for ObjectStorage {
        fn from(value: super::ObjectStorage) -> Self {
            Self {
                storage_type: match value {
                    super::ObjectStorage::S3 => Some(StorageType::S3(ProtoS3::default())),
                },
            }
        }
    }

    impl TryFrom<ObjectStorage> for super::ObjectStorage {
        type Error = anyhow::Error;

        fn try_from(value: ObjectStorage) -> Result<Self, Self::Error> {
            value
                .storage_type
                .map(|s| match s {
                    StorageType::S3(_) => super::ObjectStorage::S3,
                })
                .ok_or(anyhow!("invalid object_storage"))
        }
    }

    impl From<super::Email> for Email {
        fn from(value: super::Email) -> Self {
            Self {
                email_type: match value {
                    super::Email::IMAP => Some(EmailType::Imap(ProtoImap::default())),
                    super::Email::GMAIL => Some(EmailType::Gmail(ProtoGmail::default())),
                },
            }
        }
    }

    impl TryFrom<Email> for super::Email {
        type Error = anyhow::Error;

        fn try_from(value: Email) -> Result<Self, Self::Error> {
            value
                .email_type
                .map(|s| match s {
                    EmailType::Imap(_) => super::Email::IMAP,
                    EmailType::Gmail(_) => super::Email::GMAIL,
                })
                .ok_or(anyhow!("invalid email_type"))
        }
    }

    impl From<super::FileSystem> for Filesystem {
        fn from(value: super::FileSystem) -> Self {
            Self {
                filesystem_type: match value {
                    super::FileSystem::Posix => Some(FilesystemType::Posix(ProtoPosix::default())),
                    super::FileSystem::Windows => {
                        Some(FilesystemType::Windows(ProtoWindows::default()))
                    }
                },
            }
        }
    }

    impl TryFrom<Filesystem> for super::FileSystem {
        type Error = anyhow::Error;

        fn try_from(value: Filesystem) -> Result<Self, Self::Error> {
            value
                .filesystem_type
                .map(|s| match s {
                    FilesystemType::Posix(_) => super::FileSystem::Posix,
                    FilesystemType::Windows(_) => super::FileSystem::Windows,
                })
                .ok_or(anyhow!("invalid filesystem_type"))
        }
    }
}
