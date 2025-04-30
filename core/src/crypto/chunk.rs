use crate::crypto::EncryptedData;
use anyhow::{anyhow, bail};
use autonomi::pointer::PointerTarget;
use autonomi::{Chunk, ChunkAddress};
use bytes::Bytes;
use std::fmt::Display;
use std::marker::PhantomData;

impl<T> From<TypedChunk<T>> for PointerTarget {
    fn from(value: TypedChunk<T>) -> Self {
        PointerTarget::ChunkAddress(value.address.inner)
    }
}

impl<T> TryFrom<PointerTarget> for TypedChunkAddress<T> {
    type Error = anyhow::Error;

    fn try_from(value: PointerTarget) -> Result<Self, Self::Error> {
        let address = match value {
            PointerTarget::ChunkAddress(address) => address,
            _ => bail!("pointer target not a chunk address"),
        };

        Ok(Self::new(address))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedChunkAddress<T> {
    inner: ChunkAddress,
    _type: PhantomData<T>,
}

impl<T> TypedChunkAddress<T> {
    pub(crate) fn new(inner: ChunkAddress) -> Self {
        Self {
            inner,
            _type: Default::default(),
        }
    }

    pub(crate) fn as_ref(&self) -> &ChunkAddress {
        &self.inner
    }
}

pub struct TypedChunk<T> {
    inner: Chunk,
    address: TypedChunkAddress<T>,
}

impl<T> TypedChunk<T> {
    pub(crate) fn from_chunk(inner: Chunk) -> Self {
        let address = inner.address.clone();
        Self {
            inner,
            address: TypedChunkAddress::new(address),
        }
    }

    pub fn address(&self) -> &TypedChunkAddress<T> {
        &self.address
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub(crate) fn as_ref(&self) -> &Chunk {
        &self.inner
    }
}

impl<T: Into<Bytes>> TypedChunk<T> {
    pub fn from_value(value: T) -> Self {
        Self::from_chunk(Chunk::new(value.into()))
    }
}

impl<T: TryFrom<Bytes>> TypedChunk<T> {
    pub fn try_into_inner(self) -> anyhow::Result<T>
    where
        <T as TryFrom<Bytes>>::Error: Display,
    {
        T::try_from(self.inner.value).map_err(|e| anyhow!("converting from chunk failed: {}", e))
    }
}

pub type EncryptedChunk<T, V> = TypedChunk<EncryptedData<T, V>>;
