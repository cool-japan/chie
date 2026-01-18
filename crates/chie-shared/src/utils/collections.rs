//! Collection utility functions for working with vectors, hashmaps, and other data structures.

use std::collections::HashMap;

/// Deduplicate a vector while preserving order.
///
/// # Examples
///
/// ```
/// use chie_shared::deduplicate_preserve_order;
///
/// let items = vec![1, 2, 3, 2, 4, 1, 5];
/// let deduped = deduplicate_preserve_order(items);
/// assert_eq!(deduped, vec![1, 2, 3, 4, 5]);
///
/// // Order is preserved - first occurrence is kept
/// let words = vec!["hello", "world", "hello", "rust"];
/// let deduped_words = deduplicate_preserve_order(words);
/// assert_eq!(deduped_words, vec!["hello", "world", "rust"]);
/// ```
#[allow(dead_code)]
pub fn deduplicate_preserve_order<T: Clone + Eq + std::hash::Hash>(items: Vec<T>) -> Vec<T> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

/// Partition a vector into two vectors based on a predicate.
/// Returns (matching, non_matching).
///
/// # Examples
///
/// ```
/// use chie_shared::partition;
///
/// // Separate even and odd numbers
/// let numbers = vec![1, 2, 3, 4, 5, 6];
/// let (evens, odds) = partition(numbers, |n| n % 2 == 0);
/// assert_eq!(evens, vec![2, 4, 6]);
/// assert_eq!(odds, vec![1, 3, 5]);
///
/// // Filter strings by length
/// let words = vec!["hi", "hello", "bye", "goodbye"];
/// let (long, short) = partition(words, |w| w.len() > 3);
/// assert_eq!(long, vec!["hello", "goodbye"]);
/// assert_eq!(short, vec!["hi", "bye"]);
/// ```
#[allow(dead_code)]
pub fn partition<T, F>(items: Vec<T>, predicate: F) -> (Vec<T>, Vec<T>)
where
    F: Fn(&T) -> bool,
{
    let mut matching = Vec::new();
    let mut non_matching = Vec::new();

    for item in items {
        if predicate(&item) {
            matching.push(item);
        } else {
            non_matching.push(item);
        }
    }

    (matching, non_matching)
}

/// Group items by a key extraction function.
/// Returns a HashMap where keys are the result of the key function and values are vectors of items.
///
/// # Examples
///
/// ```
/// use chie_shared::group_by;
///
/// // Group numbers by their remainder when divided by 3
/// let numbers = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let groups = group_by(numbers, |n| n % 3);
/// assert_eq!(groups[&0], vec![3, 6, 9]);
/// assert_eq!(groups[&1], vec![1, 4, 7]);
/// assert_eq!(groups[&2], vec![2, 5, 8]);
///
/// // Group strings by their first character
/// let words = vec!["apple", "apricot", "banana", "berry", "cherry"];
/// let by_first = group_by(words, |w| w.chars().next().unwrap());
/// assert_eq!(by_first[&'a'].len(), 2);
/// assert_eq!(by_first[&'b'].len(), 2);
/// assert_eq!(by_first[&'c'].len(), 1);
/// ```
#[allow(dead_code)]
pub fn group_by<T, K, F>(items: Vec<T>, key_fn: F) -> HashMap<K, Vec<T>>
where
    K: Eq + std::hash::Hash,
    F: Fn(&T) -> K,
{
    let mut groups: HashMap<K, Vec<T>> = HashMap::new();

    for item in items {
        let key = key_fn(&item);
        groups.entry(key).or_default().push(item);
    }

    groups
}

/// Find duplicate items in a vector.
/// Returns a vector of items that appear more than once.
///
/// # Examples
///
/// ```
/// use chie_shared::find_duplicates;
///
/// let numbers = vec![1, 2, 3, 2, 4, 3, 5];
/// let mut dupes = find_duplicates(&numbers);
/// dupes.sort(); // Order is not guaranteed
/// assert_eq!(dupes, vec![2, 3]);
///
/// // Works with strings too
/// let words = vec!["cat", "dog", "cat", "bird", "dog"];
/// let mut dup_words = find_duplicates(&words);
/// dup_words.sort();
/// assert_eq!(dup_words, vec!["cat", "dog"]);
///
/// // No duplicates returns empty vector
/// let unique = vec![1, 2, 3, 4];
/// assert_eq!(find_duplicates(&unique), Vec::<i32>::new());
/// ```
#[allow(dead_code)]
pub fn find_duplicates<T: Clone + Eq + std::hash::Hash>(items: &[T]) -> Vec<T> {
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = std::collections::HashSet::new();

    for item in items {
        if !seen.insert(item) {
            duplicates.insert(item.clone());
        }
    }

    duplicates.into_iter().collect()
}

/// Merge two sorted vectors into a single sorted vector.
#[allow(dead_code)]
pub fn merge_sorted<T: Ord + Clone>(left: &[T], right: &[T]) -> Vec<T> {
    let mut result = Vec::with_capacity(left.len() + right.len());
    let mut i = 0;
    let mut j = 0;

    while i < left.len() && j < right.len() {
        if left[i] <= right[j] {
            result.push(left[i].clone());
            i += 1;
        } else {
            result.push(right[j].clone());
            j += 1;
        }
    }

    result.extend_from_slice(&left[i..]);
    result.extend_from_slice(&right[j..]);

    result
}

/// Take the first N items from a vector.
#[allow(dead_code)]
pub fn take<T: Clone>(items: &[T], n: usize) -> Vec<T> {
    items.iter().take(n).cloned().collect()
}

/// Skip the first N items and return the rest.
#[allow(dead_code)]
pub fn skip<T: Clone>(items: &[T], n: usize) -> Vec<T> {
    items.iter().skip(n).cloned().collect()
}

/// Batch items into groups where the size of each batch is determined by a size function.
/// Ensures no batch exceeds max_size.
///
/// # Examples
///
/// ```
/// use chie_shared::batch_by_size;
///
/// // Batch strings by character count, max 10 chars per batch
/// let words = vec!["hi", "hello", "world", "rust", "code"];
/// let batches = batch_by_size(words, |s| s.len(), 10);
/// // First batch: "hi" (2) + "hello" (5) = 7 chars
/// // Second batch: "world" (5) + "rust" (4) = 9 chars
/// // Third batch: "code" (4) chars
/// assert_eq!(batches.len(), 3);
/// assert_eq!(batches[0], vec!["hi", "hello"]);
/// assert_eq!(batches[1], vec!["world", "rust"]);
/// assert_eq!(batches[2], vec!["code"]);
///
/// // Batch numbers by value, max sum of 100
/// let numbers = vec![30, 40, 50, 20, 60];
/// let num_batches = batch_by_size(numbers, |n| *n, 100);
/// assert_eq!(num_batches.len(), 3);
/// assert_eq!(num_batches[0], vec![30, 40]); // 70 total
/// assert_eq!(num_batches[1], vec![50, 20]); // 70 total
/// assert_eq!(num_batches[2], vec![60]); // 60 total
/// ```
#[allow(dead_code)]
pub fn batch_by_size<T>(
    items: Vec<T>,
    size_fn: impl Fn(&T) -> usize,
    max_size: usize,
) -> Vec<Vec<T>> {
    let mut batches = Vec::new();
    let mut current_batch = Vec::new();
    let mut current_size = 0;

    for item in items {
        let item_size = size_fn(&item);

        if current_size + item_size > max_size && !current_batch.is_empty() {
            batches.push(std::mem::take(&mut current_batch));
            current_size = 0;
        }

        current_batch.push(item);
        current_size += item_size;
    }

    if !current_batch.is_empty() {
        batches.push(current_batch);
    }

    batches
}

/// Zip two vectors together, stopping at the length of the shorter vector.
#[allow(dead_code)]
pub fn zip_with<A, B, C, F>(a: Vec<A>, b: Vec<B>, f: F) -> Vec<C>
where
    F: Fn(A, B) -> C,
{
    a.into_iter().zip(b).map(|(x, y)| f(x, y)).collect()
}

/// Flatten a vector of vectors into a single vector.
#[allow(dead_code)]
pub fn flatten<T>(items: Vec<Vec<T>>) -> Vec<T> {
    items.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_preserve_order() {
        let items = vec![1, 2, 3, 2, 4, 1, 5];
        let deduped = deduplicate_preserve_order(items);
        assert_eq!(deduped, vec![1, 2, 3, 4, 5]);

        let strings = vec!["a".to_string(), "b".to_string(), "a".to_string()];
        let deduped = deduplicate_preserve_order(strings);
        assert_eq!(deduped, vec!["a".to_string(), "b".to_string()]);

        let empty: Vec<i32> = vec![];
        let deduped = deduplicate_preserve_order(empty);
        assert_eq!(deduped, Vec::<i32>::new());
    }

    #[test]
    fn test_partition() {
        let items = vec![1, 2, 3, 4, 5, 6];
        let (evens, odds) = partition(items, |x| x % 2 == 0);
        assert_eq!(evens, vec![2, 4, 6]);
        assert_eq!(odds, vec![1, 3, 5]);
    }

    #[test]
    fn test_group_by() {
        let items = vec![1, 2, 3, 4, 5, 6];
        let groups = group_by(items, |x| x % 3);

        assert_eq!(groups.get(&0), Some(&vec![3, 6]));
        assert_eq!(groups.get(&1), Some(&vec![1, 4]));
        assert_eq!(groups.get(&2), Some(&vec![2, 5]));
    }

    #[test]
    fn test_find_duplicates() {
        let items = vec![1, 2, 3, 2, 4, 1, 5, 1];
        let mut dups = find_duplicates(&items);
        dups.sort();
        assert_eq!(dups, vec![1, 2]);

        let no_dups = vec![1, 2, 3, 4, 5];
        assert_eq!(find_duplicates(&no_dups), Vec::<i32>::new());
    }

    #[test]
    fn test_merge_sorted() {
        let left = vec![1, 3, 5, 7];
        let right = vec![2, 4, 6, 8];
        let merged = merge_sorted(&left, &right);
        assert_eq!(merged, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let left = vec![1, 2, 3];
        let right: Vec<i32> = vec![];
        let merged = merge_sorted(&left, &right);
        assert_eq!(merged, vec![1, 2, 3]);
    }

    #[test]
    fn test_take_skip() {
        let items = vec![1, 2, 3, 4, 5];

        assert_eq!(take(&items, 3), vec![1, 2, 3]);
        assert_eq!(take(&items, 10), vec![1, 2, 3, 4, 5]);
        assert_eq!(take(&items, 0), Vec::<i32>::new());

        assert_eq!(skip(&items, 2), vec![3, 4, 5]);
        assert_eq!(skip(&items, 10), Vec::<i32>::new());
        assert_eq!(skip(&items, 0), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_batch_by_size() {
        let items = vec![10, 20, 30, 40, 50];
        let batches = batch_by_size(items, |&x| x as usize, 60);

        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0], vec![10, 20, 30]); // Total size: 60
        assert_eq!(batches[1], vec![40]); // Size: 40
        assert_eq!(batches[2], vec![50]); // Size: 50
    }

    #[test]
    fn test_zip_with() {
        let a = vec![1, 2, 3];
        let b = vec![10, 20, 30];
        let result = zip_with(a, b, |x, y| x + y);
        assert_eq!(result, vec![11, 22, 33]);

        let a = vec![1, 2, 3, 4];
        let b = vec![10, 20];
        let result = zip_with(a, b, |x, y| x * y);
        assert_eq!(result, vec![10, 40]); // Stops at shorter vector
    }

    #[test]
    fn test_flatten() {
        let nested = vec![vec![1, 2], vec![3, 4, 5], vec![6]];
        let flat = flatten(nested);
        assert_eq!(flat, vec![1, 2, 3, 4, 5, 6]);

        let empty: Vec<Vec<i32>> = vec![];
        assert_eq!(flatten(empty), Vec::<i32>::new());
    }
}
