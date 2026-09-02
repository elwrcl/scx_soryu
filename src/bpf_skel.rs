// SPDX-License-Identifier: GPL-2.0
//
// libbpf-cargo generates the skeleton into OUT_DIR; this module just pulls it
// in. Kept separate so the generated code's lint profile stays isolated.
#![allow(dead_code)]
#![allow(clippy::all)]
include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
