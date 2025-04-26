use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

#[derive(Debug, PartialEq, Eq, Clone, Copy)] // Make it easy to use
pub enum Comparison {
    Equivalent, // Treat as unchanged for diff purposes
    Modified,   // Treat as changed
}

#[derive(Debug, Default, PartialEq, Eq)] // Default is handy for empty diffs
pub struct MapDiff<K: Eq + Hash> {
    pub added: HashSet<K>,
    pub removed: HashSet<K>,
    pub modified: HashSet<K>,
    pub unchanged: HashSet<K>, // Renamed from unchanged_keys for clarity
}

/// Compares two HashMaps and categorizes keys into added, removed, modified, or unchanged sets.
///
/// K: Key type - must support Eq, Hash, and Clone (for the result sets).
/// V1: Value type in the old map.
/// V2: Value type in the new map.
/// F: Comparator function type: Fn(&V1, &V2) -> Comparison
pub fn diff_maps<K, V1, V2, F>(
    old_map: &HashMap<K, V1>,
    new_map: &HashMap<K, V2>,
    compare_values: F,
) -> MapDiff<K>
where
    K: Eq + Hash + Clone, // Keys still need cloning for the HashSets
    // No constraints needed on V1 or V2 anymore!
    F: Fn(&V1, &V2) -> Comparison,
{
    let old_keys: HashSet<_> = old_map.keys().cloned().collect();
    let new_keys: HashSet<_> = new_map.keys().cloned().collect();

    // Directly compute the sets using set operations for clarity
    let added: HashSet<K> = new_keys.difference(&old_keys).cloned().collect();
    let removed: HashSet<K> = old_keys.difference(&new_keys).cloned().collect();

    let mut modified = HashSet::new();
    let mut unchanged = HashSet::new();

    // Check common keys using the comparator
    for key in old_keys.intersection(&new_keys) {
        // Key exists in both maps, unwraps are safe.
        let old_val = old_map.get(key).unwrap();
        let new_val = new_map.get(key).unwrap();

        match compare_values(old_val, new_val) {
            Comparison::Modified => {
                modified.insert(key.clone());
            }
            Comparison::Equivalent => {
                unchanged.insert(key.clone());
            }
        }
    }

    MapDiff {
        added,
        removed,
        modified,
        unchanged,
    }
}
