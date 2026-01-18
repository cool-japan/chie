//! Formal Verification Helpers
//!
//! This module provides utilities and helpers to support formal verification of
//! cryptographic implementations, including property-based testing, invariant checking,
//! and verification condition generation.
//!
//! # Features
//!
//! - **Property-based testing**: Automatic generation of test cases
//! - **Invariant checking**: Runtime verification of cryptographic properties
//! - **Pre/post-condition checking**: Function contract verification
//! - **State machine verification**: Verify state transitions are valid
//! - **Symbolic execution helpers**: Support for symbolic analysis
//! - **Proof obligations**: Generate verification conditions
//!
//! # Example
//!
//! ```
//! use chie_crypto::formal_verify::{Invariant, PropertyChecker, check_invariant};
//!
//! // Define an invariant
//! let inv = Invariant::new("key_length", |state: &[u8]| {
//!     state.len() == 32
//! });
//!
//! // Check the invariant
//! let key = [0u8; 32];
//! assert!(inv.check(&key));
//!
//! // Property-based testing
//! let mut checker = PropertyChecker::new();
//! checker.add_property("encryption_decryption_roundtrip", |data: &[u8]| {
//!     // Property: encrypt(decrypt(x)) == x
//!     true // simplified example
//! });
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type alias for post-condition predicates
type PostConditionFn<T, U> = Box<dyn Fn(&T, &U) -> bool>;

/// Type alias for property check functions
type PropertyFn = Box<dyn Fn(&[u8]) -> bool>;

/// Type alias for state machine transition functions
type TransitionFn<S> = Box<dyn Fn(&S, &str) -> Option<S>>;

/// Invariant that must hold for a cryptographic operation
pub struct Invariant<T: ?Sized> {
    /// Name of the invariant
    name: String,
    /// Predicate function that checks the invariant
    predicate: Box<dyn Fn(&T) -> bool>,
}

impl<T: ?Sized> Invariant<T> {
    /// Create a new invariant
    pub fn new<F>(name: &str, predicate: F) -> Self
    where
        F: Fn(&T) -> bool + 'static,
    {
        Self {
            name: name.to_string(),
            predicate: Box::new(predicate),
        }
    }

    /// Check if the invariant holds for the given state
    pub fn check(&self, state: &T) -> bool {
        (self.predicate)(state)
    }

    /// Get invariant name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Pre-condition for a function
pub struct PreCondition<T: ?Sized> {
    /// Name of the pre-condition
    name: String,
    /// Predicate that must be true before function execution
    predicate: Box<dyn Fn(&T) -> bool>,
}

impl<T: ?Sized> PreCondition<T> {
    /// Create a new pre-condition
    pub fn new<F>(name: &str, predicate: F) -> Self
    where
        F: Fn(&T) -> bool + 'static,
    {
        Self {
            name: name.to_string(),
            predicate: Box::new(predicate),
        }
    }

    /// Check if the pre-condition holds
    pub fn check(&self, input: &T) -> bool {
        (self.predicate)(input)
    }

    /// Get pre-condition name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Post-condition for a function
pub struct PostCondition<T: ?Sized, U: ?Sized> {
    /// Name of the post-condition
    name: String,
    /// Predicate that must be true after function execution
    predicate: PostConditionFn<T, U>,
}

impl<T: ?Sized, U: ?Sized> PostCondition<T, U> {
    /// Create a new post-condition
    pub fn new<F>(name: &str, predicate: F) -> Self
    where
        F: Fn(&T, &U) -> bool + 'static,
    {
        Self {
            name: name.to_string(),
            predicate: Box::new(predicate),
        }
    }

    /// Check if the post-condition holds
    pub fn check(&self, input: &T, output: &U) -> bool {
        (self.predicate)(input, output)
    }

    /// Get post-condition name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Property-based test checker
pub struct PropertyChecker {
    /// Properties to check
    properties: HashMap<String, PropertyFn>,
    /// Number of test cases per property
    num_cases: usize,
}

impl Default for PropertyChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl PropertyChecker {
    /// Create a new property checker
    pub fn new() -> Self {
        Self {
            properties: HashMap::new(),
            num_cases: 100,
        }
    }

    /// Set number of test cases
    pub fn with_num_cases(mut self, num: usize) -> Self {
        self.num_cases = num;
        self
    }

    /// Add a property to check
    pub fn add_property<F>(&mut self, name: &str, property: F)
    where
        F: Fn(&[u8]) -> bool + 'static,
    {
        self.properties.insert(name.to_string(), Box::new(property));
    }

    /// Check all properties with random inputs
    pub fn check_all(&self) -> PropertyCheckResult {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut results = HashMap::new();

        for (name, property) in &self.properties {
            let mut passed = 0;
            let mut failed = 0;

            for _ in 0..self.num_cases {
                // Generate random input
                let mut data = vec![0u8; 32];
                rng.fill_bytes(&mut data);

                if property(&data) {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }

            results.insert(
                name.clone(),
                PropertyResult {
                    passed,
                    failed,
                    total: self.num_cases,
                },
            );
        }

        PropertyCheckResult { results }
    }

    /// Check a specific property
    pub fn check_property(&self, name: &str) -> Option<PropertyResult> {
        use rand::RngCore;
        let property = self.properties.get(name)?;
        let mut rng = rand::thread_rng();

        let mut passed = 0;
        let mut failed = 0;

        for _ in 0..self.num_cases {
            let mut data = vec![0u8; 32];
            rng.fill_bytes(&mut data);

            if property(&data) {
                passed += 1;
            } else {
                failed += 1;
            }
        }

        Some(PropertyResult {
            passed,
            failed,
            total: self.num_cases,
        })
    }
}

/// Result of property checking
#[derive(Debug, Clone)]
pub struct PropertyCheckResult {
    /// Results for each property
    pub results: HashMap<String, PropertyResult>,
}

impl PropertyCheckResult {
    /// Check if all properties passed
    pub fn all_passed(&self) -> bool {
        self.results.values().all(|r| r.failed == 0)
    }

    /// Get failed properties
    pub fn failed_properties(&self) -> Vec<String> {
        self.results
            .iter()
            .filter(|(_, r)| r.failed > 0)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Result for a single property
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyResult {
    /// Number of test cases that passed
    pub passed: usize,
    /// Number of test cases that failed
    pub failed: usize,
    /// Total number of test cases
    pub total: usize,
}

impl PropertyResult {
    /// Get success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.passed as f64 / self.total as f64
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// State machine verifier
pub struct StateMachine<S> {
    /// Current state
    current_state: S,
    /// Valid transitions
    transitions: Vec<TransitionFn<S>>,
    /// State invariants
    invariants: Vec<Invariant<S>>,
}

impl<S: Clone> StateMachine<S> {
    /// Create a new state machine with initial state
    pub fn new(initial_state: S) -> Self {
        Self {
            current_state: initial_state,
            transitions: Vec::new(),
            invariants: Vec::new(),
        }
    }

    /// Add a transition function
    pub fn add_transition<F>(&mut self, transition: F)
    where
        F: Fn(&S, &str) -> Option<S> + 'static,
    {
        self.transitions.push(Box::new(transition));
    }

    /// Add a state invariant
    pub fn add_invariant(&mut self, invariant: Invariant<S>) {
        self.invariants.push(invariant);
    }

    /// Check if current state satisfies all invariants
    pub fn check_invariants(&self) -> Vec<String> {
        self.invariants
            .iter()
            .filter(|inv| !inv.check(&self.current_state))
            .map(|inv| inv.name().to_string())
            .collect()
    }

    /// Attempt a transition
    pub fn transition(&mut self, event: &str) -> Result<(), String> {
        // Try each transition function
        for trans in &self.transitions {
            if let Some(new_state) = trans(&self.current_state, event) {
                // Check invariants before transitioning
                let old_state = self.current_state.clone();
                self.current_state = new_state;

                let violations = self.check_invariants();
                if !violations.is_empty() {
                    // Rollback if invariants violated
                    self.current_state = old_state;
                    return Err(format!("Invariant violations: {:?}", violations));
                }

                return Ok(());
            }
        }

        Err(format!("No valid transition for event: {}", event))
    }

    /// Get current state
    pub fn current_state(&self) -> &S {
        &self.current_state
    }
}

/// Verification condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCondition {
    /// Name of the condition
    pub name: String,
    /// Description
    pub description: String,
    /// Formula (in informal notation)
    pub formula: String,
}

impl VerificationCondition {
    /// Create a new verification condition
    pub fn new(name: &str, description: &str, formula: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            formula: formula.to_string(),
        }
    }
}

/// Helper function to check an invariant and panic if it doesn't hold
pub fn check_invariant<T: ?Sized>(name: &str, state: &T, predicate: impl Fn(&T) -> bool) {
    if !predicate(state) {
        panic!("Invariant '{}' violated", name);
    }
}

/// Helper function to check a pre-condition
pub fn check_precondition<T: ?Sized>(name: &str, input: &T, predicate: impl Fn(&T) -> bool) {
    if !predicate(input) {
        panic!("Pre-condition '{}' violated", name);
    }
}

/// Helper function to check a post-condition
pub fn check_postcondition<T: ?Sized, U: ?Sized>(
    name: &str,
    input: &T,
    output: &U,
    predicate: impl Fn(&T, &U) -> bool,
) {
    if !predicate(input, output) {
        panic!("Post-condition '{}' violated", name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_creation() {
        let inv = Invariant::new("test", |x: &i32| *x > 0);
        assert_eq!(inv.name(), "test");
        assert!(inv.check(&5));
        assert!(!inv.check(&-5));
    }

    #[test]
    fn test_invariant_key_length() {
        let inv = Invariant::new("key_length_32", |key: &[u8]| key.len() == 32);
        assert!(inv.check(&[0u8; 32]));
        assert!(!inv.check(&[0u8; 16]));
    }

    #[test]
    fn test_precondition() {
        let pre = PreCondition::new("non_empty", |data: &[u8]| !data.is_empty());
        assert!(pre.check(&[1, 2, 3]));
        assert!(!pre.check(&[]));
    }

    #[test]
    fn test_postcondition() {
        let post = PostCondition::new("output_not_empty", |_input: &[u8], output: &[u8]| {
            !output.is_empty()
        });
        assert!(post.check(&[1, 2], &[3, 4]));
        assert!(!post.check(&[1, 2], &[]));
    }

    #[test]
    fn test_property_checker() {
        let mut checker = PropertyChecker::new().with_num_cases(10);
        checker.add_property("always_true", |_| true);
        checker.add_property("always_false", |_| false);

        let results = checker.check_all();
        assert!(results.results["always_true"].all_passed());
        assert!(!results.results["always_false"].all_passed());
        assert!(!results.all_passed());
    }

    #[test]
    fn test_property_result_success_rate() {
        let result = PropertyResult {
            passed: 75,
            failed: 25,
            total: 100,
        };
        assert_eq!(result.success_rate(), 0.75);
    }

    #[test]
    fn test_property_checker_single_property() {
        let mut checker = PropertyChecker::new().with_num_cases(20);
        checker.add_property("test_prop", |_| true);

        let result = checker.check_property("test_prop").unwrap();
        assert_eq!(result.passed, 20);
        assert_eq!(result.failed, 0);
        assert!(result.all_passed());
    }

    #[test]
    fn test_state_machine_basic() {
        #[derive(Clone, PartialEq, Debug)]
        enum State {
            Init,
            Ready,
            Running,
        }

        let mut sm = StateMachine::new(State::Init);

        // Add transition: Init -> Ready on "start"
        sm.add_transition(|state, event| match (state, event) {
            (State::Init, "start") => Some(State::Ready),
            (State::Ready, "run") => Some(State::Running),
            _ => None,
        });

        // Transition to Ready
        assert!(sm.transition("start").is_ok());
        assert_eq!(*sm.current_state(), State::Ready);

        // Transition to Running
        assert!(sm.transition("run").is_ok());
        assert_eq!(*sm.current_state(), State::Running);

        // Invalid transition
        assert!(sm.transition("start").is_err());
    }

    #[test]
    fn test_state_machine_with_invariant() {
        let mut sm = StateMachine::new(0i32);

        // Add invariant: state must be non-negative
        sm.add_invariant(Invariant::new("non_negative", |s: &i32| *s >= 0));

        // Add transition that increments state
        sm.add_transition(|state, event| {
            if event == "increment" {
                Some(state + 1)
            } else {
                None
            }
        });

        // Valid transition
        assert!(sm.transition("increment").is_ok());
        assert_eq!(*sm.current_state(), 1);
        assert!(sm.check_invariants().is_empty());
    }

    #[test]
    fn test_state_machine_invariant_violation() {
        let mut sm = StateMachine::new(5i32);

        // Add invariant: state must be <= 10
        sm.add_invariant(Invariant::new("max_10", |s: &i32| *s <= 10));

        // Add transition that adds 10
        sm.add_transition(|state, event| {
            if event == "add_10" {
                Some(state + 10)
            } else {
                None
            }
        });

        // This transition would violate the invariant
        assert!(sm.transition("add_10").is_err());
        // State should be unchanged
        assert_eq!(*sm.current_state(), 5);
    }

    #[test]
    fn test_check_invariant_helper() {
        let state = vec![1, 2, 3];
        check_invariant("non_empty", &state, |s| !s.is_empty());
    }

    #[test]
    #[should_panic(expected = "Invariant 'empty' violated")]
    fn test_check_invariant_helper_panic() {
        let state = vec![1, 2, 3];
        check_invariant("empty", &state, |s| s.is_empty());
    }

    #[test]
    fn test_verification_condition() {
        let vc = VerificationCondition::new(
            "encryption_correctness",
            "Decryption of encrypted data returns original",
            "forall m, k: decrypt(encrypt(m, k), k) = m",
        );

        assert_eq!(vc.name, "encryption_correctness");
        assert!(vc.formula.contains("decrypt"));
    }

    #[test]
    fn test_failed_properties() {
        let mut checker = PropertyChecker::new().with_num_cases(10);
        checker.add_property("pass1", |_| true);
        checker.add_property("fail1", |_| false);
        checker.add_property("pass2", |_| true);

        let results = checker.check_all();
        let failed = results.failed_properties();
        assert_eq!(failed.len(), 1);
        assert!(failed.contains(&"fail1".to_string()));
    }
}
