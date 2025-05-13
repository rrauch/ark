use crate::crypto::{Bech32Public, Bech32Secret, TypedPublicKey, TypedSecretKey};

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BridgeKind;
pub type BridgeAddress = TypedPublicKey<BridgeKind>;
pub type BridgeKey = TypedSecretKey<BridgeKind>;

impl Bech32Public for BridgeKind {
    const HRP: &'static str = "arkbridgepub";
}

impl Bech32Secret for BridgeKind {
    const HRP: &'static str = "arkbridgesec";
}