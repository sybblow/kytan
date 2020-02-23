use std::{collections::HashMap, fmt, net::IpAddr, path::Path, sync::Arc};

use log::{debug, trace};
use parking_lot::Mutex;
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{CFType, TCFType, ToVoid},
        dictionary::{CFDictionary, CFMutableDictionary},
        propertylist::CFPropertyList,
        string::CFString,
    },
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder},
    sys::schema_definitions::kSCPropNetDNSServerAddresses,
};

pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can happen when setting/monitoring DNS on macOS.
#[derive(err_derive::Error, Debug)]
pub enum Error {
    /// Error while setting DNS servers
    #[error(display = "Error while setting DNS servers")]
    SettingDnsFailed,

    /// Failed to initialize dynamic store
    #[error(display = "Failed to initialize dynamic store")]
    DynamicStoreInitError,
}

const STATE_PATH_PATTERN: &str = "State:/Network/Service/.*/DNS";
const SETUP_PATH_PATTERN: &str = "Setup:/Network/Service/.*/DNS";

type ServicePath = String;
type DnsServer = String;

struct State {
    /// The settings this monitor is currently enforcing as active settings.
    dns_settings: DnsSettings,
    /// The backup of all DNS settings. These are being applied back on reset.
    backup: HashMap<ServicePath, Option<DnsSettings>>,
}

/// Holds the configuration for one service.
#[derive(Debug, Eq, PartialEq)]
struct DnsSettings(CFDictionary);

unsafe impl Send for DnsSettings {}

impl DnsSettings {
    pub fn from_server_addresses(server_addresses: &[DnsServer]) -> Self {
        let mut mut_dict = CFMutableDictionary::new();
        if !server_addresses.is_empty() {
            let cf_string_servers: Vec<CFString> =
                server_addresses.iter().map(|s| CFString::new(s)).collect();
            let server_addresses_value = CFArray::from_CFTypes(&cf_string_servers).into_untyped();
            let server_addresses_key =
                unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
            mut_dict.add(
                &server_addresses_key.to_void(),
                &server_addresses_value.to_void(),
            );
        }
        let dict = unsafe { CFDictionary::wrap_under_get_rule(mut_dict.as_concrete_TypeRef()) };
        DnsSettings(dict)
    }

    /// Get DNS settings for a given service path. Returns `None` If the path does not exist.
    pub fn load<S: Into<CFString>>(store: &SCDynamicStore, path: S) -> Option<Self> {
        let dict = store
            .get(path)
            .and_then(CFPropertyList::downcast_into::<CFDictionary>)?;
        Some(DnsSettings(dict))
    }

    /// Set the dynamic store entry at `path` to a dictionary these DNS settings.
    pub fn save<S: Into<CFString> + fmt::Display>(
        &self,
        store: &SCDynamicStore,
        path: S,
    ) -> Result<()> {
        trace!(
            "Setting DNS to [{}] for {}",
            self.server_addresses().join(", "),
            path.to_string()
        );
        if store.set(path, self.0.clone()) {
            Ok(())
        } else {
            Err(Error::SettingDnsFailed)
        }
    }

    pub fn server_addresses(&self) -> Vec<String> {
        self.0
            .find(unsafe { kSCPropNetDNSServerAddresses }.to_void())
            .map(|array_ptr| unsafe { CFType::wrap_under_get_rule(*array_ptr) })
            .and_then(|array| array.downcast::<CFArray>())
            .and_then(Self::parse_cf_array_to_strings)
            .unwrap_or(Vec::new())
    }

    /// Parses a CFArray into a Rust vector of Rust strings, if the array contains CFString
    /// instances only, otherwise `None` is returned.
    fn parse_cf_array_to_strings(array: CFArray) -> Option<Vec<String>> {
        let mut strings = Vec::new();
        for item_ptr in array.iter() {
            let item = unsafe { CFType::wrap_under_get_rule(*item_ptr) };
            if let Some(string) = item.downcast::<CFString>() {
                strings.push(string.to_string());
            } else {
                log::error!("DNS server entry is not a string: {:?}", item);
                return None;
            };
        }
        Some(strings)
    }
}

pub struct DnsMonitor {
    store: SCDynamicStore,

    /// The current DNS injection state. If this is `None` it means we are not injecting any DNS.
    /// When it's `Some(state)` we are actively making sure `state.dns_settings` is configured
    /// on all network interfaces.
    state: Arc<Mutex<Option<State>>>,
}

impl super::DnsMonitorT for DnsMonitor {
    type Error = Error;

    /// Creates and returns a new `DnsMonitor`. This spawns a background thread that will monitor
    /// DNS settings for all network interfaces. If any changes occur it will instantly reset
    /// the DNS settings for that interface back to the last server list set to this instance
    /// with `set_dns`.
    fn new(_cache_dir: impl AsRef<Path>) -> Result<Self> {
        let state = Arc::new(Mutex::new(None));
        Ok(DnsMonitor {
            store: SCDynamicStoreBuilder::new("kytan-dns").build(),
            state,
        })
    }

    fn set(&mut self, _interface: &str, servers: &[IpAddr]) -> Result<()> {
        log::info!(
            "Setting DNS servers to {}",
            servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
        let servers: Vec<DnsServer> = servers.iter().map(|ip| ip.to_string()).collect();
        let settings = DnsSettings::from_server_addresses(&servers);
        let mut state_lock = self.state.lock();
        *state_lock = Some(match state_lock.take() {
            None => {
                let backup = read_all_dns(&self.store);
                trace!("Backup of DNS settings: {:#?}", backup);
                for service_path in backup.keys() {
                    settings.save(&self.store, service_path.as_str())?;
                }
                State {
                    dns_settings: settings,
                    backup,
                }
            }
            Some(state) => {
                if servers != state.dns_settings.server_addresses() {
                    for service_path in state.backup.keys() {
                        settings.save(&self.store, service_path.as_str())?;
                    }
                    State {
                        dns_settings: settings,
                        backup: state.backup,
                    }
                } else {
                    debug!("No change, new DNS same as the one already set");
                    state
                }
            }
        });
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        log::info!("Resetting DNS");
        let mut state_lock = self.state.lock();
        if let Some(state) = state_lock.take() {
            trace!("Restoring DNS settings to: {:#?}", state.backup);
            for (service_path, settings) in state.backup {
                if let Some(settings) = settings {
                    settings.save(&self.store, service_path.as_str())?;
                } else {
                    debug!("Removing DNS for {}", service_path);
                    if !self.store.remove(CFString::new(&service_path)) {
                        return Err(Error::SettingDnsFailed);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Read all existing DNS settings and return them.
fn read_all_dns(store: &SCDynamicStore) -> HashMap<ServicePath, Option<DnsSettings>> {
    let mut backup = HashMap::new();
    // Backup all "state" DNS, and all corresponding "setup" DNS even if they don't exist
    if let Some(paths) = store.get_keys(STATE_PATH_PATTERN) {
        for state_path in paths.iter() {
            let state_path_str = state_path.to_string();
            let setup_path_str = state_to_setup_path(&state_path_str).unwrap();
            backup.insert(state_path_str, DnsSettings::load(store, state_path.clone()));
            backup.insert(
                setup_path_str.clone(),
                DnsSettings::load(store, setup_path_str.as_ref()),
            );
        }
    }
    // Backup all "setup" DNS not already covered
    if let Some(paths) = store.get_keys(SETUP_PATH_PATTERN) {
        for setup_path in paths.iter() {
            let setup_path_str = setup_path.to_string();
            if !backup.contains_key(&setup_path_str) {
                backup.insert(setup_path_str, DnsSettings::load(store, setup_path.clone()));
            }
        }
    }
    backup
}

fn state_to_setup_path(state_path: &str) -> Option<String> {
    if state_path.starts_with("State:/") {
        Some(state_path.replacen("State:/", "Setup:/", 1))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_current_dns() {
        let store = super::SCDynamicStoreBuilder::new("my-test-dyn-store").build();
        let current = super::read_all_dns(&store);
        println!("Current DNS settings: {:#?}", current);
    }
}
