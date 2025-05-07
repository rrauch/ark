use anyhow::{anyhow, bail};
use autonomi::{
    Client as AutonomiClient, ClientConfig as AutonomiClientConfig, Multiaddr,
    Network as EvmNetwork,
};
use bon::Builder;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;

const SCHEME: &str = "autonomi";
const PREFIX: &str = "config";
const RPC_URL_PARAM: &str = "rpc_url";
const PAYMENT_TOKEN_PARAM: &str = "payment_token_addr";
const DATA_PAYMENTS_PARAM: &str = "data_payments_addr";
const BOOTSTRAP_PEER_PARAM: &str = "peer";
const BOOTSTRAP_URL_PARAM: &str = "bootstrap_url";
const BOOTSTRAP_IGNORE_CACHE: &str = "ignore_cache";
const BOOTSTRAP_CACHE_PARAM: &str = "bootstrap_cache_dir";
const NETWORK_ID_PARAM: &str = "network_id";

const NETWORK_MAINNET: &str = "mainnet";
const NETWORK_ALPHANET: &str = "alphanet";
const NETWORK_TESTNET: &str = "testnet";
const NETWORK_LOCAL: &str = "local";

#[derive(Builder, Clone, Debug)]
pub struct ClientConfig {
    network: Network,
    network_id: Option<u8>,
    bootstrap_peers: Option<BootstrapPeers>,
    bootstrap_cache: Option<PathBuf>,
    ignore_cache: Option<bool>,
}

impl ClientConfig {
    pub async fn try_new_client(&self) -> anyhow::Result<AutonomiClient> {
        Ok(AutonomiClient::init_with_config(self.to_autononomi_config().await?).await?)
    }

    async fn to_autononomi_config(&self) -> anyhow::Result<AutonomiClientConfig> {
        let mut config = AutonomiClientConfig::default();

        match &self.network {
            Network::MainNet => {
                config.evm_network = EvmNetwork::ArbitrumOne;
                config.network_id = Some(1);
                self.set_ignore_cache(&mut config);
                self.set_bootstrap_cache(&mut config);
            }
            Network::AlphaNet => {
                config.evm_network = EvmNetwork::ArbitrumSepoliaTest;
                config.network_id = Some(2);
                self.set_ignore_cache(&mut config);
                self.set_bootstrap_cache(&mut config);
            }
            Network::TestNet => {
                config.evm_network = EvmNetwork::ArbitrumSepoliaTest;
                self.set_network_id(&mut config);
                Self::disable_mainnet_contacts(&mut config);
                self.set_ignore_cache(&mut config);
                self.set_bootstrap_cache(&mut config);
            }
            Network::Local(local_config) => {
                config.evm_network = EvmNetwork::new_custom(
                    local_config.rpc_url.as_str(),
                    local_config.payment_token_addr.as_str(),
                    local_config.data_payments_addr.as_str(),
                );
                self.set_network_id(&mut config);
                Self::disable_mainnet_contacts(&mut config);
                config.init_peers_config.local = true;
                config.init_peers_config.ignore_cache = true;
            }
        };

        if let Some(bootstrap_peers) = &self.bootstrap_peers {
            match bootstrap_peers {
                BootstrapPeers::Urls(urls) => {
                    config.init_peers_config.network_contacts_url =
                        urls.into_iter().map(|u| u.as_str().to_string()).collect();
                }
                BootstrapPeers::MultiAddresses(addresses) => {
                    config.init_peers_config.addrs = addresses.clone();
                }
            }
        }

        if config.init_peers_config.local
            && !config.init_peers_config.network_contacts_url.is_empty()
        {
            // The Autonomi Client does NOT download peers from a given bootstrap cache when using a local network.
            // This makes using a local network for development harder because peer ids change after each restart.
            // This basically re-implements the bootstrap cache download function, so bootstrap cache urls can be used.
            let contacts_fetcher = ant_bootstrap::ContactsFetcher::with_endpoints(
                config
                    .init_peers_config
                    .network_contacts_url
                    .drain(0..)
                    .map(|s| Url::parse(s.as_str()).map_err(|e| e.into()))
                    .collect::<anyhow::Result<Vec<Url>>>()?,
            )?;
            config.init_peers_config.addrs = contacts_fetcher.fetch_addrs().await?;
        }

        Ok(config)
    }

    fn set_bootstrap_cache(&self, config: &mut AutonomiClientConfig) {
        if let Some(bootstrap_cache) = &self.bootstrap_cache {
            config.init_peers_config.bootstrap_cache_dir = Some(bootstrap_cache.clone());
        }
    }

    fn set_ignore_cache(&self, config: &mut AutonomiClientConfig) {
        if let Some(ignore_cache) = self.ignore_cache {
            config.init_peers_config.ignore_cache = ignore_cache;
        }
    }

    fn set_network_id(&self, config: &mut AutonomiClientConfig) {
        if let Some(network_id) = self.network_id {
            config.network_id = Some(network_id);
        }
    }

    fn disable_mainnet_contacts(config: &mut AutonomiClientConfig) {
        config.init_peers_config.disable_mainnet_contacts = true;
    }

    pub fn to_url(&self) -> Url {
        let net = match &self.network {
            Network::MainNet => NETWORK_MAINNET,
            Network::AlphaNet => NETWORK_ALPHANET,
            Network::TestNet => NETWORK_TESTNET,
            Network::Local(_) => NETWORK_LOCAL,
        };
        let mut url = Url::parse(format!("{}:{}:{}", SCHEME, PREFIX, net).as_str())
            .expect("url parsing should never fail");
        match &self.network {
            Network::Local(local_config) => {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair(RPC_URL_PARAM, local_config.rpc_url.as_str());
                pairs.append_pair(
                    PAYMENT_TOKEN_PARAM,
                    local_config.payment_token_addr.as_str(),
                );
                pairs.append_pair(
                    DATA_PAYMENTS_PARAM,
                    local_config.data_payments_addr.as_str(),
                );
            }
            _ => {}
        }

        match &self.bootstrap_peers {
            Some(BootstrapPeers::Urls(urls)) => {
                let mut pairs = url.query_pairs_mut();
                urls.into_iter().for_each(|url| {
                    pairs.append_pair(BOOTSTRAP_URL_PARAM, url.as_str());
                });
            }
            Some(BootstrapPeers::MultiAddresses(peers)) => {
                let mut pairs = url.query_pairs_mut();
                peers.into_iter().for_each(|peer| {
                    pairs.append_pair(BOOTSTRAP_PEER_PARAM, peer.to_string().as_str());
                });
            }
            None => {}
        }

        if let Some(network_id) = self.network_id {
            url.query_pairs_mut()
                .append_pair(NETWORK_ID_PARAM, format!("{}", network_id).as_str());
        }

        if let Some(true) = self.ignore_cache {
            url.query_pairs_mut()
                .append_key_only(BOOTSTRAP_IGNORE_CACHE);
        }

        if let Some(bootstrap_cache) = &self.bootstrap_cache {
            url.query_pairs_mut().append_pair(
                BOOTSTRAP_CACHE_PARAM,
                bootstrap_cache.to_str().unwrap_or_default(),
            );
        }

        url
    }

    pub fn friendly(&self) -> String {
        match &self.network {
            Network::MainNet => "MainNet".to_string(),
            Network::AlphaNet => "AlphaNet".to_string(),
            Network::TestNet => "TestNet".to_string(),
            Network::Local(cfg) => {
                format!(
                    "Local ({}{})",
                    cfg.rpc_url.host_str().unwrap_or("unknown"),
                    cfg.rpc_url
                        .port()
                        .map(|p| format!(":{}", p))
                        .unwrap_or("".to_string())
                )
            }
        }
    }
}

impl FromStr for ClientConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(Url::parse(s)?)
    }
}

impl TryFrom<Url> for ClientConfig {
    type Error = anyhow::Error;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        if url.scheme() != SCHEME {
            bail!("url scheme [{}] != [{}]", url.scheme(), SCHEME);
        }

        let network = url
            .path()
            .strip_prefix(format!("{}:", PREFIX).as_str())
            .ok_or(anyhow!("path does not start with '{}:'", PREFIX))?
            .trim()
            .to_ascii_lowercase();

        let mut rpc_url = None;
        let mut payment_token_addr = None;
        let mut data_payments_addr = None;
        let mut network_id = None;
        let mut ignore_cache = None;
        let mut bootstrap_cache = None;
        let mut bootstrap_peers = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                RPC_URL_PARAM => {
                    rpc_url = Some(Url::try_from(value.as_ref())?);
                }
                PAYMENT_TOKEN_PARAM => {
                    payment_token_addr = Some(value.to_string());
                }
                DATA_PAYMENTS_PARAM => {
                    data_payments_addr = Some(value.to_string());
                }
                NETWORK_ID_PARAM => {
                    network_id = Some(u8::from_str(value.as_ref())?);
                }
                BOOTSTRAP_IGNORE_CACHE => {
                    ignore_cache = Some(true);
                }
                BOOTSTRAP_CACHE_PARAM => {
                    bootstrap_cache = Some(PathBuf::from_str(value.as_ref())?);
                }
                BOOTSTRAP_URL_PARAM => {
                    let url = Url::parse(value.as_ref())?;
                    if bootstrap_peers.is_none() {
                        bootstrap_peers = Some(BootstrapPeers::Urls(vec![]));
                    }
                    if let Some(BootstrapPeers::Urls(urls)) = &mut bootstrap_peers {
                        urls.push(url);
                    } else {
                        bail!("cannot mix bootstrap peers and urls");
                    }
                }
                BOOTSTRAP_PEER_PARAM => {
                    let addr = Multiaddr::from_str(value.as_ref())?;
                    if bootstrap_peers.is_none() {
                        bootstrap_peers = Some(BootstrapPeers::MultiAddresses(vec![]));
                    }
                    if let Some(BootstrapPeers::MultiAddresses(addrs)) = &mut bootstrap_peers {
                        addrs.push(addr);
                    } else {
                        bail!("cannot mix bootstrap peers and urls");
                    }
                }
                _ => {}
            }
        }

        let network = match network.as_str() {
            NETWORK_MAINNET => Network::MainNet,
            NETWORK_ALPHANET => Network::AlphaNet,
            NETWORK_TESTNET => Network::TestNet,
            NETWORK_LOCAL => Network::Local(
                LocalNetworkConfig::builder()
                    .rpc_url(rpc_url.ok_or(anyhow!("{} is missing", RPC_URL_PARAM))?)
                    .payment_token_addr(
                        payment_token_addr.ok_or(anyhow!("{} is missing", PAYMENT_TOKEN_PARAM))?,
                    )
                    .data_payments_addr(
                        data_payments_addr.ok_or(anyhow!("{} is missing", DATA_PAYMENTS_PARAM))?,
                    )
                    .build(),
            ),
            _ => {
                bail!("invalid network: [{}]", url.path())
            }
        };

        Ok(ClientConfig::builder()
            .network(network)
            .maybe_network_id(network_id)
            .maybe_ignore_cache(ignore_cache)
            .maybe_bootstrap_cache(bootstrap_cache)
            .maybe_bootstrap_peers(bootstrap_peers)
            .build())
    }
}

impl Display for ClientConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.to_url(), f)
    }
}

#[derive(Clone, Debug)]
pub enum Network {
    MainNet,
    AlphaNet,
    TestNet,
    Local(LocalNetworkConfig),
}

#[derive(Builder, Clone, Debug)]
pub struct LocalNetworkConfig {
    #[builder(into)]
    rpc_url: Url,
    #[builder(into)]
    payment_token_addr: String,
    #[builder(into)]
    data_payments_addr: String,
}

#[derive(Clone, Debug)]
pub enum BootstrapPeers {
    Urls(Vec<Url>),
    MultiAddresses(Vec<Multiaddr>),
}
