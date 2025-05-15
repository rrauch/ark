use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use autonomi::pointer::PointerTarget;
use autonomi::{Pointer, PointerAddress};
use blsttc::SecretKey;
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedPointerAddress<T, V> {
    inner: PointerAddress,
    owner: TypedPublicKey<T>,
    _value_type: PhantomData<V>,
}

impl<T, V: Into<PointerTarget>> TypedPointerAddress<T, V> {
    pub(crate) fn new(inner: PointerAddress) -> Self {
        let owner = TypedPublicKey::from(inner.owner().clone());
        Self {
            inner,
            owner,
            _value_type: Default::default(),
        }
    }
}

impl<T, V> TypedPointerAddress<T, V> {
    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }

    pub(crate) fn as_ref(&self) -> &PointerAddress {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedPointer<T, V> {
    owner: TypedSecretKey<T>,
    address: TypedPointerAddress<T, V>,
}

impl<T, V: Into<PointerTarget>> TypedOwnedPointer<T, V> {
    pub(crate) fn new(owner: TypedSecretKey<T>) -> Self {
        let address =
            TypedPointerAddress::new(PointerAddress::new(owner.public_key().as_ref().clone()));
        Self { owner, address }
    }
}

impl<T, V> TypedOwnedPointer<T, V> {
    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedPointerAddress<T, V> {
        &self.address
    }
}

pub(crate) trait PointerExt {
    fn is_final(&self) -> bool;
    fn new_final(owner: &SecretKey, target: PointerTarget) -> Self;
}

impl PointerExt for Pointer {
    fn is_final(&self) -> bool {
        self.counter() == u32::MAX
    }

    fn new_final(owner: &SecretKey, target: PointerTarget) -> Self {
        Self::new(owner, u32::MAX, target)
    }
}
