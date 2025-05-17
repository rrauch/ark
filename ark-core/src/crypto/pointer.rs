use crate::crypto::Finalizeable;
use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use crate::{AutonomiClient, Core, Receipt};
use anyhow::{anyhow, bail};
use autonomi::pointer::PointerTarget;
use autonomi::{Pointer, PointerAddress};
use std::fmt::Display;
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

impl<T> TryFrom<PointerTarget> for TypedPublicKey<T> {
    type Error = anyhow::Error;

    fn try_from(value: PointerTarget) -> std::result::Result<Self, Self::Error> {
        match value {
            PointerTarget::PointerAddress(addr) => Ok(Self::from(addr.owner().clone())),
            _ => Err(anyhow!("not an address pointer")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedPointer<T, V> {
    owner: TypedSecretKey<T>,
    inner: TypedPointer<T, V>,
}

impl<T, V: Into<PointerTarget>> TypedOwnedPointer<T, V> {
    pub(crate) fn new(target: V, owner: TypedSecretKey<T>) -> Self {
        let address =
            TypedPointerAddress::new(PointerAddress::new(owner.public_key().as_ref().clone()));
        let inner = TypedPointer {
            counter: 0,
            target,
            address,
        };
        Self { owner, inner }
    }

    pub fn update(&mut self, new_target: V) -> anyhow::Result<u32> {
        if !self.is_mutable() {
            bail!("pointer is immutable")
        }
        self.inner.target = new_target;
        self.inner.counter += 1;
        Ok(self.inner.counter)
    }

    fn into_pointer(self) -> Pointer {
        let sk = self.owner.as_ref().clone();
        Pointer::new(&sk, self.inner.counter, self.inner.target.into())
    }
}

impl<T, V: Finalizeable + Into<PointerTarget>> TypedOwnedPointer<T, V> {
    fn make_immutable(mut self) -> anyhow::Result<Pointer> {
        if !self.is_mutable() {
            bail!("pointer already immutable");
        }

        self.inner.counter = u32::MAX;

        Ok(self.into_pointer())
    }
}

impl<T, V> TypedOwnedPointer<T, V> {
    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedPointerAddress<T, V> {
        self.inner.address()
    }

    pub fn target(&self) -> &V {
        &self.inner.target
    }

    pub fn into_target(self) -> V {
        self.inner.target
    }

    pub fn is_mutable(&self) -> bool {
        self.inner.is_mutable()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedPointer<T, V> {
    counter: u32,
    target: V,
    address: TypedPointerAddress<T, V>,
}

impl<T, V: TryFrom<PointerTarget> + Into<PointerTarget>> TypedPointer<T, V>
where
    <V as TryFrom<PointerTarget>>::Error: Send + Sync + Display,
{
    fn try_from_pointer(pointer: Pointer) -> anyhow::Result<Self> {
        let target = pointer
            .target()
            .clone()
            .try_into()
            .map_err(|e| anyhow!("{}", e))?;
        Ok(Self {
            counter: pointer.counter(),
            address: TypedPointerAddress::new(pointer.address()),
            target,
        })
    }
}

impl<T, V> TypedPointer<T, V> {
    pub fn address(&self) -> &TypedPointerAddress<T, V> {
        &self.address
    }

    pub fn target(&self) -> &V {
        &self.target
    }

    pub fn into_target(self) -> V {
        self.target
    }

    pub fn is_mutable(&self) -> bool {
        self.counter < u32::MAX
    }
}

impl<T: Clone, V> TypedPointer<T, V> {
    pub(crate) fn try_into_owned(
        self,
        owner: &TypedSecretKey<T>,
    ) -> anyhow::Result<TypedOwnedPointer<T, V>> {
        if owner.public_key().as_ref() != self.address.as_ref().owner() {
            bail!("invalid owner");
        }
        Ok(TypedOwnedPointer {
            owner: owner.clone(),
            inner: self,
        })
    }
}

pub(crate) trait PointerExt {
    fn is_mutable(&self) -> bool;
}

impl PointerExt for Pointer {
    fn is_mutable(&self) -> bool {
        self.counter() < u32::MAX
    }
}

impl Core {
    pub(crate) async fn create_pointer<T, V: Into<PointerTarget>>(
        &self,
        pointer: TypedOwnedPointer<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<TypedPointerAddress<T, V>> {
        self._create_pointer(pointer.into_pointer(), receipt).await
    }

    pub(crate) async fn create_immutable_pointer<T, V: Into<PointerTarget> + Finalizeable>(
        &self,
        pointer: TypedOwnedPointer<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<TypedPointerAddress<T, V>> {
        self._create_pointer(pointer.make_immutable()?, receipt)
            .await
    }

    async fn _create_pointer<T, V: Into<PointerTarget>>(
        &self,
        pointer: Pointer,
        receipt: &mut Receipt,
    ) -> anyhow::Result<TypedPointerAddress<T, V>> {
        let address = PointerAddress::new(*pointer.owner());
        if let Some(_) = self._pointer_get(&address).await? {
            bail!("pointer already exists");
        }

        let res = self
            .client
            .pointer_put(pointer, self.payment())
            .await
            .map_err(|e| anyhow::Error::from(e));

        self.pointer_cache.invalidate(&address).await;

        let (attos, addr) = res?;

        receipt.add(attos);
        if &address != &addr {
            self.pointer_cache.invalidate(&addr).await;
            bail!("incorrect pointer address returned");
        };

        Ok(TypedPointerAddress::new(address))
    }

    async fn update_pointer<T, V: Into<PointerTarget>>(
        &self,
        pointer: TypedOwnedPointer<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<u32> {
        let existing = self
            ._pointer_get(pointer.address().as_ref())
            .await?
            .ok_or(anyhow!("pointer does not exist"))?;
        if !existing.is_mutable() {
            bail!("pointer is immutable");
        }

        let pointer = pointer.into_pointer();

        if existing.counter() > pointer.counter() {
            bail!("existing pointer has higher version number");
        }

        if existing.target() == pointer.target() && existing.counter() == pointer.counter() {
            // nothing has changed
            // no need to send to the network
            return Ok(existing.counter());
        }

        let address = pointer.address();
        let counter = pointer.counter();

        let res = self.client.pointer_put(pointer, self.payment()).await;
        self.pointer_cache.invalidate(&address).await;
        let (attos, _) = res.map_err(|e| anyhow!("{}", e))?;
        receipt.add(attos);

        Ok(counter)
    }

    async fn read_pointer<T, V: TryFrom<PointerTarget> + Into<PointerTarget>>(
        &self,
        address: &TypedPointerAddress<T, V>,
    ) -> anyhow::Result<Option<TypedPointer<T, V>>>
    where
        <V as TryFrom<PointerTarget>>::Error: Send + Sync + Display,
    {
        Ok(self
            ._pointer_get(address.as_ref())
            .await?
            .map(|p| TypedPointer::try_from_pointer(p))
            .transpose()?)
    }

    async fn _pointer_get(&self, address: &PointerAddress) -> anyhow::Result<Option<Pointer>> {
        self.pointer_cache
            .try_get_with_by_ref(address, Self::_pointer_get_live(&self.client, address))
            .await
            .map_err(|e| anyhow!("{}", e))
    }

    async fn _pointer_get_live(
        client: &AutonomiClient,
        address: &PointerAddress,
    ) -> anyhow::Result<Option<Pointer>> {
        if !client.pointer_check_existance(address).await? {
            return Ok(None);
        }
        Ok(Some(client.pointer_get(address).await?))
    }

    pub(crate) async fn read_pointer_directly<T, V: TryFrom<PointerTarget> + Into<PointerTarget>>(
        client: &AutonomiClient,
        address: &TypedPointerAddress<T, V>,
    ) -> anyhow::Result<Option<TypedPointer<T, V>>>
    where
        <V as TryFrom<PointerTarget>>::Error: Send + Sync + Display,
    {
        Ok(Self::_pointer_get_live(client, address.as_ref())
            .await?
            .map(|p| TypedPointer::try_from_pointer(p))
            .transpose()?)
    }
}
