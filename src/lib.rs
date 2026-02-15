// lib.rs

pub use std::{
    collections::{hash_map::Entry, HashMap},
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    net, path,
    sync::Arc,
};

pub use chrono::*;
pub use hex_literal::hex;
pub use pretty_hex::*;
pub use prost::Message;
pub use protobufs::{
    config::device_config::Role, mesh_packet::{PayloadVariant, Priority, TransportMechanism}, Data, HardwareModel, MeshPacket,
    PortNum,
    User,
};
pub use rand::{prelude::*, rngs::StdRng, SeedableRng};
pub use serde::{Deserialize, Serialize};
pub use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
};
pub use tracing::*;

pub use config::*;
pub use mesh::*;
pub use state::*;

mod config;
mod mesh;
mod state;

// This module contains structs and enums that are generated from the protocol buffer (protobuf)
// definitions of the `meshtastic/protobufs` Git submodule. These structs and enums
// are not edited directly, but are instead generated at build time.

pub mod protobufs {
    #![allow(missing_docs)]
    #![allow(non_snake_case)]
    #![allow(unknown_lints)]
    #![allow(clippy::empty_docs)]
    #![allow(clippy::doc_lazy_continuation)]
    #![allow(clippy::doc_overindented_list_items)]
    include!("generated/meshtastic.rs");
}

// don't ask (:facepalm:)
pub const DEFAULT_AES_KEY: [u8; 16] =
    hex!("d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01");

pub const DEFAULT_HOP_LIMIT: u8 = 5;
pub const DEFAULT_CHANNEL_NAME: &str = "EdgeFastLow";

pub fn get_wild<'a, T>(
    map: &'a HashMap<String, T>,
    key: &str,
) -> Option<&'a T> {
    map.get(key).or_else(|| map.get("*"))
}
// EOF
