use crate::ServiceInfo;
use flume::Sender;
use std::collections::HashMap;

/// Commands to be implemented by plugins
#[derive(Debug)]
pub enum PluginCommand {
    /// Command to fetch services that are currently provided by the plugin
    ListServices(Sender<HashMap<String, ServiceInfo>>),

    Exit(Sender<()>),
}
