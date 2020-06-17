#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::similar_names)]

#[macro_use]
extern crate pest;

pub mod lsp;
pub mod options;
pub mod spicy;
