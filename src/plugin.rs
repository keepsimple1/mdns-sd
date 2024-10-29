use crate::ServiceInfo;
use flume::Sender;
use std::collections::HashMap;
use std::sync::Arc;

/// Commands to be implemented by plugins
#[derive(Debug)]
pub enum PluginCommand {
    Registered,

    /// Command to fetch services that are currently provided by the plugin
    ListServices(Sender<HashMap<String, Arc<ServiceInfo>>>),

    Exit(Sender<()>),
}
