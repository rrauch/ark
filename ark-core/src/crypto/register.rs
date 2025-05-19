use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use crate::{Core, Receipt};
use ant_networking::{GetRecordError, NetworkError};
use anyhow::{anyhow, bail};
use autonomi::pointer::PointerError;
use autonomi::register::{RegisterAddress, RegisterError, RegisterValue};
use blsttc::SecretKey;
use std::fmt::Display;
use std::marker::PhantomData;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedRegister<T, V> {
    value: V,
    address: TypedRegisterAddress<T, V>,
}

impl<T, V: TryFrom<RegisterValue>> TypedRegister<T, V>
where
    <V as TryFrom<RegisterValue>>::Error: Send + Sync + Display,
{
    fn try_from_existing(address: RegisterAddress, value: RegisterValue) -> anyhow::Result<Self> {
        let value = value.try_into().map_err(|e| anyhow!("{}", e))?;
        Ok(Self {
            address: TypedRegisterAddress::new(address),
            value,
        })
    }
}

impl<T, V> TypedRegister<T, V> {
    pub fn address(&self) -> &TypedRegisterAddress<T, V> {
        &self.address
    }

    pub fn value(&self) -> &V {
        &self.value
    }

    pub fn into_value(self) -> V {
        self.value
    }
}

impl<T: Clone, V> TypedRegister<T, V> {
    pub(crate) fn try_into_owned(
        self,
        owner: &TypedSecretKey<T>,
    ) -> anyhow::Result<TypedOwnedRegister<T, V>> {
        if owner.public_key().as_ref() != self.address.owner.as_ref() {
            bail!("invalid owner");
        }
        Ok(TypedOwnedRegister {
            owner: owner.clone(),
            inner: self,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedRegister<T, V> {
    owner: TypedSecretKey<T>,
    inner: TypedRegister<T, V>,
}

impl<T, V> TypedOwnedRegister<T, V> {
    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedRegisterAddress<T, V> {
        &self.inner.address()
    }

    pub fn value(&self) -> &V {
        &self.inner.value
    }
}

impl<T, V: Into<RegisterValue>> TypedOwnedRegister<T, V> {
    pub(crate) fn new(value: V, owner: TypedSecretKey<T>) -> Self {
        let address =
            TypedRegisterAddress::new(RegisterAddress::new(owner.public_key().as_ref().clone()));
        let inner = TypedRegister { value, address };
        Self { owner, inner }
    }

    pub fn update(&mut self, value: V) -> anyhow::Result<()> {
        self.inner.value = value;
        Ok(())
    }

    fn into_register(self) -> (SecretKey, RegisterValue) {
        let value = self.inner.value.into();
        (self.owner.inner, value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricValue<V>(V);

impl<V> HistoricValue<V> {
    pub fn as_ref(&self) -> &V {
        &self.0
    }

    pub fn into_inner(self) -> V {
        self.0
    }
}

impl Core {
    pub(crate) async fn create_register<T, V: Into<RegisterValue>>(
        &self,
        register: TypedOwnedRegister<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<TypedRegisterAddress<T, V>> {
        if self
            ._register_get(register.address().as_ref())
            .await?
            .is_some()
        {
            bail!("register already exists")
        }

        let (sk, value) = register.into_register();
        let (attos, address) = self
            .client
            .register_create(&sk, value, self.payment())
            .await?;

        self.register_cache.invalidate(&address).await;
        self.register_history_cache.invalidate(&address).await;
        receipt.add(attos);

        Ok(TypedRegisterAddress::new(address))
    }

    pub(crate) async fn update_register<T, V: Into<RegisterValue>>(
        &self,
        register: TypedOwnedRegister<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        if self
            ._register_get(register.address().as_ref())
            .await?
            .is_none()
        {
            bail!("register does not exists")
        }

        let address = register.address().as_ref().clone();

        let (sk, value) = register.into_register();
        let res = self
            .client
            .register_update(&sk, value, self.payment())
            .await;

        self.register_cache.invalidate(&address).await;
        self.register_history_cache.invalidate(&address).await;
        receipt.add(res?);

        Ok(())
    }

    pub(crate) async fn get_register<T, V: TryFrom<RegisterValue>>(
        &self,
        address: &TypedRegisterAddress<T, V>,
    ) -> anyhow::Result<Option<TypedRegister<T, V>>>
    where
        <V as TryFrom<RegisterValue>>::Error: Send + Sync + Display,
    {
        Ok(self
            ._register_get(address.as_ref())
            .await?
            .map(|v| TypedRegister::try_from_existing(address.as_ref().clone(), v))
            .transpose()?)
    }

    pub(crate) async fn read_register<T, V: TryFrom<RegisterValue>>(
        &self,
        address: &TypedRegisterAddress<T, V>,
    ) -> anyhow::Result<V>
    where
        <V as TryFrom<RegisterValue>>::Error: Send + Sync + Display,
    {
        Ok(self
            .get_register(address)
            .await?
            .map(|r| r.into_value())
            .ok_or(anyhow!("register not found"))?)
    }

    async fn _register_get(
        &self,
        address: &RegisterAddress,
    ) -> anyhow::Result<Option<RegisterValue>> {
        self.register_cache
            .try_get_with_by_ref(address, async move {
                match self.client.register_get(address).await {
                    Ok(reg) => Ok(Some(reg)),
                    Err(RegisterError::PointerError(PointerError::Network(
                        NetworkError::GetRecordError(GetRecordError::RecordNotFound),
                    ))) => {
                        // if there is a better way to check for a register's existence, please update!
                        Ok(None)
                    }
                    Err(err) => Err(err),
                }
            })
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn register_history<T, V: TryFrom<RegisterValue>>(
        &self,
        address: &TypedRegisterAddress<T, V>,
    ) -> anyhow::Result<Vec<HistoricValue<V>>>
    where
        <V as TryFrom<RegisterValue>>::Error: Send + Sync + Display,
    {
        Ok(self
            ._register_history(address.as_ref())
            .await?
            .into_iter()
            .map(|v| {
                V::try_from(v)
                    .map_err(|e| anyhow!("{}", e))
                    .and_then(|v| Ok(HistoricValue(v)))
            })
            .collect::<anyhow::Result<Vec<_>>>()?)
    }

    async fn _register_history(
        &self,
        address: &RegisterAddress,
    ) -> anyhow::Result<Vec<RegisterValue>> {
        self.register_history_cache
            .try_get_with_by_ref(address, self.client.register_history(address).collect())
            .await
            .map_err(|e| e.into())
    }
}
