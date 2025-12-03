//! This crate provides an interface to a hypervisor.

#![no_std]
#![feature(allocator_api)]
#![feature(const_trait_impl)]
#![feature(once_cell_try)]
#![feature(decl_macro)]

extern crate alloc;
extern crate static_assertions;

pub mod allocator;
pub mod error;
pub mod global_const;
pub mod intel;
pub mod logger;
pub mod vmm;
pub mod windows;

// Re-export key allocator functions for easy access
pub use allocator::{heap_init, init_allocator_with_memory, is_using_protected_memory};
