use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use autonomi::register::RegisterAddress;
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedRegister<T, V> {
    owner: TypedSecretKey<T>,
    address: TypedRegisterAddress<T, V>,
}

impl<T: Clone, V> TypedOwnedRegister<T, V> {
    pub(crate) fn new(owner: TypedSecretKey<T>) -> Self {
        let address =
            TypedRegisterAddress::new(RegisterAddress::new(owner.public_key().clone().into()));
        Self { owner, address }
    }
}

impl<T, V> TypedOwnedRegister<T, V> {
    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedRegisterAddress<T, V> {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedRegisterAddress<T, V> {
    inner: RegisterAddress,
    owner: TypedPublicKey<T>,
    _value_type: PhantomData<V>,
}

impl<T, V> TypedRegisterAddress<T, V> {
    pub(crate) fn new(inner: RegisterAddress) -> Self {
        let owner = TypedPublicKey::from(inner.owner());
        Self {
            inner,
            owner,
            _value_type: Default::default(),
        }
    }

    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }

    pub(crate) fn as_ref(&self) -> &RegisterAddress {
        &self.inner
    }
}
