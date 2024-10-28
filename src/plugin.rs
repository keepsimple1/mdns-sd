use std::collections::HashMap;
use crate::ServiceInfo;
use flume::Sender;

/// Commands to be implemented by plugins
#[derive(Debug)]
pub enum PluginCommand {
    /// Command to fetch services that are currently provided by the plugin
    ListServices(Sender<HashMap<String, ServiceInfo>>),

    Exit(Sender<()>),
}
