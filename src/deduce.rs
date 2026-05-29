use std::collections::{HashMap, HashSet};

use crate::proxy::*;

// ── ProxyInfo Trait ──────────────────────────────────────────────────────

/// Unified access to proxy metadata for dedup and name-resolution logic.
pub trait ProxyInfo {
    fn get_dedup_key(&self) -> DedupKey;
    fn get_name(&self) -> String;
    fn set_name(&mut self, name: String);
}

impl ProxyInfo for ProxyNode {
    fn get_dedup_key(&self) -> DedupKey {
        self.dedup_key()
    }
    fn get_name(&self) -> String {
        self.name().to_string()
    }
    fn set_name(&mut self, name: String) {
        self.set_name(name)
    }
}

impl ProxyInfo for EnrichedProxy {
    fn get_dedup_key(&self) -> DedupKey {
        self.node.dedup_key()
    }
    fn get_name(&self) -> String {
        self.node.name().to_string()
    }
    fn set_name(&mut self, name: String) {
        self.node.set_name(name)
    }
}

// ── Generic Implementations ──────────────────────────────────────────────

/// Deduplicate a list of proxy-like items, keeping the first occurrence of
/// each unique [`DedupKey`].
pub fn dedup_items<T: ProxyInfo + Clone>(nodes: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::new();
    nodes
        .into_iter()
        .filter(|node| seen.insert(node.get_dedup_key()))
        .collect()
}

/// Resolve duplicate names by appending " (N)" to each extra copy.
pub fn resolve_name_conflicts_inner<T: ProxyInfo>(nodes: &mut [T]) {
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for node in nodes.iter() {
        *name_counts.entry(node.get_name()).or_insert(0) += 1;
    }

    let mut seen_names: HashMap<String, usize> = HashMap::new();
    for node in nodes.iter_mut() {
        let name = node.get_name();
        if name_counts.get(&name).copied().unwrap_or(0) > 1 {
            let count = seen_names.entry(name.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                node.set_name(format!("{} ({})", name, *count - 1));
            }
        }
    }
}

// ── Backward-compatible Wrappers ─────────────────────────────────────────

pub fn dedup_proxies(nodes: Vec<ProxyNode>) -> Vec<ProxyNode> {
    dedup_items(nodes)
}

pub fn dedup_enriched(nodes: Vec<EnrichedProxy>) -> Vec<EnrichedProxy> {
    dedup_items(nodes)
}

pub fn resolve_name_conflicts(nodes: &mut [ProxyNode]) {
    resolve_name_conflicts_inner(nodes)
}

pub fn resolve_enriched_name_conflicts(nodes: &mut [EnrichedProxy]) {
    resolve_name_conflicts_inner(nodes)
}
