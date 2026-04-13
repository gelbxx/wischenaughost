//! # wghost-ffi
//!
//! FFI (Foreign Function Interface) bindings that expose the Rust API
//! to React Native via Mozilla's **uniffi**.
//!
//! ## How it works
//!
//! 1. We define the API in a UDL (Universal Definition Language) file
//! 2. uniffi generates Swift (iOS) and Kotlin (Android) bindings
//! 3. uniffi-bindgen-react-native wraps those as TurboModules
//! 4. React Native calls Rust functions as if they were native modules
//!
//! ## Architecture
//!
//! ```text
//! TypeScript (UI) -> TurboModule (JSI) -> Kotlin/Swift -> JNI/FFI -> Rust
//! ```
//!
//! The JSI (JavaScript Interface) layer provides synchronous, zero-copy
//! calls from JS into native code — no bridge serialization overhead.

// TODO: Implement FFI bindings as we build out the core functionality
// Phase 1: Identity key generation, basic crypto operations
// Phase 2: Message send/receive, contact management
// Phase 3: Group operations, file transfer
