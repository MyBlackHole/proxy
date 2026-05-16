use std::collections::{HashMap, HashSet};

use crate::proxy::*;

pub fn dedup_proxies(nodes: Vec<ProxyNode>) -> Vec<ProxyNode> {
    let mut seen = HashSet::new();
    nodes.into_iter()
        .filter(|node| seen.insert(node.dedup_key()))
        .collect()
}

pub fn resolve_name_conflicts(nodes: &mut [ProxyNode]) {
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for node in nodes.iter() {
        *name_counts.entry(node.name().to_string()).or_insert(0) += 1;
    }

    let mut seen_names: HashMap<String, usize> = HashMap::new();
    for node in nodes.iter_mut() {
        let name = node.name().to_string();
        if name_counts.get(&name).copied().unwrap_or(0) > 1 {
            let count = seen_names.entry(name.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                node.set_name(format!("{} ({})", name, *count - 1));
            }
        }
    }
}

// ── EnrichedProxy Dedup ───────────────────────────────────────────────────

use crate::proxy::EnrichedProxy;

pub fn dedup_enriched(nodes: Vec<EnrichedProxy>) -> Vec<EnrichedProxy> {
    let mut seen = HashSet::new();
    nodes.into_iter()
        .filter(|ep| seen.insert(ep.node.dedup_key()))
        .collect()
}

pub fn resolve_enriched_name_conflicts(nodes: &mut [EnrichedProxy]) {
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for ep in nodes.iter() {
        *name_counts.entry(ep.node.name().to_string()).or_insert(0) += 1;
    }

    let mut seen_names: HashMap<String, usize> = HashMap::new();
    for ep in nodes.iter_mut() {
        let name = ep.node.name().to_string();
        if name_counts.get(&name).copied().unwrap_or(0) > 1 {
            let count = seen_names.entry(name.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                ep.node.set_name(format!("{} ({})", name, *count - 1));
            }
        }
    }
}
