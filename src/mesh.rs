// mesh.rs

use base64::prelude::*;
use ccm::{
    aead::Aead, consts::{U13, U8},
    Ccm,
    KeyInit,
};
use crypto::{
    aes::{self, KeySize},
    symmetriccipher::SynchronousStreamCipher,
};
use futures::future::BoxFuture;
use sha2::{Digest, Sha256};
use std::future::Future;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::*;

type Aes256Ccm = Ccm<::aes::Aes256, U8, U13>;

pub const MESH_BROADCAST_ADDR: u32 = u32::MAX;

/// Compute the Meshtastic channel hash (single-byte XOR of channel
/// name and PSK).  The firmware uses this value in the `channel` field
/// of encrypted MeshPackets to identify which channel key to decrypt
/// with.
pub fn channel_hash(name: &str, psk: &[u8]) -> u32 {
    let xor = |bytes: &[u8]| -> u8 { bytes.iter().fold(0u8, |acc, &b| acc ^ b) };
    (xor(name.as_bytes()) ^ xor(psk)) as u32
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MyNodeInfo {
    pub id: u32,
    pub id_s: String,
    pub mac_addr: [u8; 6],
    pub short_name: String,
    pub long_name: String,
    pub licensed: bool,
    pub hw_model: i32,
    pub hw_model_s: String,
    pub role: i32,
    pub role_s: String,
    pub public_key_b64: String,
    pub last_seen: i64,
    pub last_seen_s: String,
}

impl From<User> for MyNodeInfo {
    fn from(user: User) -> Self {
        let nodeid_s = &user.id;
        // nodeid has pattern "!abcd1234"
        let id = if nodeid_s.starts_with('!')
            && nodeid_s.len() == 9
            && let Ok(id) = u32::from_str_radix(&nodeid_s[1..9], 16)
        {
            id
        } else {
            warn!("From<User> invalid Nodeinfo ID: {:?}", nodeid_s);
            0
        };
        let hw_model: HardwareModel = user.hw_model.try_into().unwrap_or(HardwareModel::PrivateHw);
        let role: Role = user.role.try_into().unwrap_or(Role::Client);
        let now = Utc::now();
        #[allow(deprecated)]
        let mac_addr: [u8; 6] = user.macaddr.try_into().unwrap_or_default();
        Self {
            id,
            id_s: user.id,
            mac_addr,
            short_name: user.short_name,
            long_name: user.long_name,
            licensed: user.is_licensed,
            hw_model: hw_model.into(),
            hw_model_s: format!("{hw_model:?}"),
            role: role.into(),
            role_s: format!("{role:?}"),
            public_key_b64: BASE64_STANDARD.encode(&user.public_key),
            last_seen: now.timestamp(),
            last_seen_s: now.to_rfc3339(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NodeDb {
    pub db: HashMap<u32, MyNodeInfo>,
}
impl NodeDb {
    pub fn save(&self, opts: &CliOpts) -> anyhow::Result<()> {
        let file = &opts.nodedb_file;
        let sz = self.db.len();
        info!("Saving nodedb ({sz} entries) to {file}");
        BufWriter::new(File::create(file)?)
            .write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

pub enum HandlerStatus {
    Continue,
    Finished,
}

pub type MsgHandler = Box<
    dyn Fn(
        Arc<MyState>,
        net::SocketAddr,
        MeshPacket,
        Data,
    ) -> BoxFuture<'static, anyhow::Result<HandlerStatus>>,
>;

fn into_handler<Fut: Future<Output = anyhow::Result<HandlerStatus>> + Send + 'static>(
    f: impl Fn(Arc<MyState>, net::SocketAddr, MeshPacket, Data) -> Fut + 'static,
) -> MsgHandler {
    Box::new(move |st, a, p, d| Box::pin(f(st, a, p, d)))
}

pub struct MsgDispatcher {
    handlers: HashMap<PortNum, Vec<MsgHandler>>,
}

impl Default for MsgDispatcher {
    fn default() -> Self {
        let mut d = Self::new();

        // let mut foo = Vec::new();
        // foo.push(into_handler(handle_textmessage));
        // d.handlers.insert(PortNum::TextMessageApp, foo);

        d.add_handler(PortNum::TextMessageApp, handle_textmessage);
        d.add_handler(PortNum::NodeinfoApp, handle_nodeinfo);
        d.add_handler(PortNum::PositionApp, handle_position);
        d.add_handler(PortNum::RoutingApp, handle_routing);
        d.add_handler(PortNum::TracerouteApp, handle_traceroute);
        d
    }
}

impl MsgDispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
    pub fn add_handler<Fut: Future<Output = anyhow::Result<HandlerStatus>> + Send + 'static>(
        &mut self, port: PortNum,
        handler: impl Fn(Arc<MyState>, net::SocketAddr, MeshPacket, Data) -> Fut + 'static,
    ) {
        self.handlers
            .entry(port)
            .or_default()
            .push(into_handler(handler));
    }
    pub fn remove_handlers(&mut self, port: PortNum) {
        self.handlers.remove(&port);
    }

    pub async fn process(
        &self, state: Arc<MyState>, rx_addr: net::SocketAddr, rx_packet: MeshPacket, rx_data: Data,
    ) {
        let portnum = rx_data.portnum;
        let port = match portnum.try_into() {
            Err(e) => {
                error!("Unknown port number {portnum}: {e}");
                return;
            }
            Ok(port) => port,
        };
        let handlers = match self.handlers.get(&port) {
            None => {
                info!("No handlers for port {port:?}");
                return;
            }
            Some(handlers) => handlers,
        };
        for handler in handlers {
            match handler(state.clone(), rx_addr, rx_packet.clone(), rx_data.clone()).await {
                Ok(HandlerStatus::Finished) => break,
                Ok(HandlerStatus::Continue) => (),

                Err(err) => {
                    error!("Error handling payload: {err}");
                    break;
                }
            }
        }
    }
}

async fn handle_textmessage(
    _state: Arc<MyState>, _rx_addr: net::SocketAddr, _rx_packet: MeshPacket, rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    let msg = String::from_utf8_lossy(&rx_data.payload);
    info!("Got MSG: \"{msg}\"");
    Ok(HandlerStatus::Continue)
}

async fn handle_nodeinfo(
    state: Arc<MyState>, _rx_addr: net::SocketAddr, _rx_packet: MeshPacket, rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Nodeinfo message");
    // let info = String::from_utf8_lossy(&data.payload);
    // info!("Got Nodeinfo:\n{info}");

    let nodeinfo = protobufs::User::decode(rx_data.payload.as_slice())?;
    info!("Parsed Nodeinfo:\n{nodeinfo:?}");

    let nodeid_s = &nodeinfo.id;
    // nodeid has pattern "!abcd1234"
    let node_id = if nodeid_s.starts_with('!')
        && nodeid_s.len() == 9
        && let Ok(id) = u32::from_str_radix(&nodeid_s[1..9], 16)
    {
        id
    } else {
        warn!("Received invalid Nodeinfo ID: {:?}", nodeid_s);
        return Ok(HandlerStatus::Continue);
    };

    // Nodeinfo ID ok, store it to db
    let mut nodedb = state.nodedb.write().await;
    nodedb.db.insert(node_id, nodeinfo.into());
    nodedb.save(&state.opts)?;
    Ok(HandlerStatus::Continue)
}

async fn handle_position(
    _state: Arc<MyState>, _rx_addr: net::SocketAddr, _rx_packet: MeshPacket, rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Position message");
    let pos = protobufs::Position::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed Position:\n{pos:?}");
    Ok(HandlerStatus::Continue)
}

async fn handle_routing(
    _state: Arc<MyState>, _rx_addr: net::SocketAddr, _rx_packet: MeshPacket, rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Routing message");
    let routing = protobufs::Routing::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed Routing:\n{routing:?}");
    Ok(HandlerStatus::Continue)
}

async fn handle_traceroute(
    _state: Arc<MyState>, _rx_addr: net::SocketAddr, _rx_packet: MeshPacket, rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Traceroute message");
    let trace = protobufs::RouteDiscovery::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed traceroute:\n{trace:?}");

    Ok(HandlerStatus::Continue)
}

/// Encrypt a Data payload with AES-128-CTR (channel encryption).
/// Uses the same IV scheme as decrypt_payload: [packet_id LE, 0..4, from LE, 0..4].
pub fn encrypt_payload(plaintext: &[u8], packet_id: u32, from: u32, key: &[u8; 16]) -> Vec<u8> {
    let mut aes_iv: [u8; 16] = [0; 16];
    aes_iv[0..4].copy_from_slice(&packet_id.to_le_bytes());
    aes_iv[8..12].copy_from_slice(&from.to_le_bytes());
    let mut cipher = aes::ctr(KeySize::KeySize128, key, &aes_iv);
    let mut outbuf = vec![0; plaintext.len()];
    cipher.process(plaintext, &mut outbuf);
    outbuf
}

pub fn decrypt_payload(rx_packet: &MeshPacket, config: &MyConfig) -> Option<Vec<u8>> {
    let enc_data = match &rx_packet.payload_variant {
        Some(PayloadVariant::Encrypted(enc_data)) => enc_data,
        _ => return None, // we ignore non-encrypted packets
    };

    let data_len = enc_data.len();
    info!("Attempting to decrypt {data_len} bytes");
    debug!("Encrypted payload:\n{:?}", enc_data.hex_dump());

    if rx_packet.pki_encrypted || rx_packet.to != MESH_BROADCAST_ADDR {
        debug!("Attempting PKI decrypt");
        return decrypt_payload_pki(enc_data, rx_packet, config);
    }

    // Channel encryption: AES-128-CTR
    debug!("Attempting channel decrypt");
    let mut aes_iv: [u8; 16] = [0; 16];
    aes_iv[0..4].copy_from_slice(&rx_packet.id.to_le_bytes());
    aes_iv[8..12].copy_from_slice(&rx_packet.from.to_le_bytes());
    let mut cipher = aes::ctr(KeySize::KeySize128, &config.aes_key, &aes_iv);
    let mut outbuf = vec![0; data_len];
    cipher.process(enc_data, &mut outbuf);
    Some(outbuf)
}

/// Encrypt a payload using the Meshtastic PKI scheme:
/// X25519 ECDH → SHA-256 → AES-256-CCM.
///
/// Returns the encrypted payload:
/// `[ciphertext || auth_tag (8 bytes) || extra_nonce (4 bytes)]`
pub fn encrypt_payload_pki(
    plaintext: &[u8], packet_id: u32, from_node: u32, extra_nonce: u32,
    local_private_key: &[u8; 32], remote_public_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    // X25519 ECDH key agreement
    let secret = StaticSecret::from(*local_private_key);
    let public = PublicKey::from(*remote_public_key);
    let shared_secret = secret.diffie_hellman(&public);

    // SHA-256 key derivation
    let aes_key = Sha256::digest(shared_secret.as_bytes());

    // 13-byte CCM nonce: [packet_id(4), extra_nonce(4), from_node(4), 0x00]
    let mut nonce = [0u8; 13];
    nonce[0..4].copy_from_slice(&packet_id.to_le_bytes());
    nonce[4..8].copy_from_slice(&extra_nonce.to_le_bytes());
    nonce[8..12].copy_from_slice(&from_node.to_le_bytes());

    // AES-256-CCM encrypt (produces ciphertext + 8-byte tag)
    let cipher = Aes256Ccm::new((&*aes_key).into());
    let ciphertext_and_tag = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|e| anyhow::anyhow!("AES-256-CCM encryption failed: {e}"))?;

    // Append extra_nonce so the recipient can reconstruct the nonce
    let mut out = ciphertext_and_tag;
    out.extend_from_slice(&extra_nonce.to_le_bytes());
    Ok(out)
}

/// Decrypt a PKI-encrypted payload (AES-256-CCM with X25519 ECDH key).
/// Encrypted layout: `[ciphertext || auth_tag (8) || extra_nonce (4)]`
fn decrypt_payload_pki(
    enc_data: &[u8], rx_packet: &MeshPacket, config: &MyConfig,
) -> Option<Vec<u8>> {
    // 8-byte tag + 4-byte extra_nonce = 12 bytes minimum overhead
    if enc_data.len() < 12 {
        warn!("PKI payload too short ({} bytes)", enc_data.len());
        return None;
    }

    let remote_pub_bytes: [u8; 32] = match rx_packet.public_key.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => {
            warn!(
                "PKI packet from !{:08x} has invalid public key length ({})",
                rx_packet.from,
                rx_packet.public_key.len()
            );
            return None;
        }
    };

    // Extract extra_nonce from last 4 bytes
    let extra_nonce_bytes: [u8; 4] = enc_data[enc_data.len() - 4..].try_into().unwrap();
    let extra_nonce = u32::from_le_bytes(extra_nonce_bytes);
    let ccm_input = &enc_data[..enc_data.len() - 4]; // ciphertext + tag

    // X25519 ECDH + SHA-256 key derivation
    let secret = StaticSecret::from(config.private_key);
    let public = PublicKey::from(remote_pub_bytes);
    let shared_secret = secret.diffie_hellman(&public);
    let aes_key = Sha256::digest(shared_secret.as_bytes());

    // 13-byte CCM nonce: [packet_id(4), extra_nonce(4), from_node(4), 0x00]
    let mut nonce = [0u8; 13];
    nonce[0..4].copy_from_slice(&rx_packet.id.to_le_bytes());
    nonce[4..8].copy_from_slice(&extra_nonce.to_le_bytes());
    nonce[8..12].copy_from_slice(&rx_packet.from.to_le_bytes());

    let cipher = Aes256Ccm::new((&*aes_key).into());
    match cipher.decrypt((&nonce).into(), ccm_input) {
        Ok(plaintext) => {
            info!("PKI decryption succeeded ({} bytes)", plaintext.len());
            Some(plaintext)
        }
        Err(e) => {
            warn!("PKI decryption failed for !{:08x}: {e}", rx_packet.from);
            None
        }
    }
}

pub async fn send_text_msg(
    state: Arc<MyState>, tx_addr: net::SocketAddr, to: u32, text: &str,
) -> anyhow::Result<()> {
    let tx_data = Data {
        portnum: PortNum::TextMessageApp.into(),
        want_response: false,
        bitfield: Some(0),
        payload: text.as_bytes().to_vec(),
        ..Default::default()
    };
    let plaintext = tx_data.encode_to_vec();

    let packet_id = state.rng.lock().await.random_range(65536..u32::MAX);
    let encrypted = encrypt_payload(
        &plaintext,
        packet_id,
        state.config.node_id,
        &state.config.aes_key,
    );

    let ch_hash = channel_hash(&state.config.channel_name, &state.config.aes_key);
    let tx_packet = MeshPacket {
        channel: ch_hash,
        transport_mechanism: TransportMechanism::TransportInternal.into(),
        priority: Priority::High.into(),
        from: state.config.node_id,
        to,
        id: packet_id,
        hop_limit: state.config.hop_limit.into(),
        hop_start: state.config.hop_limit.into(),
        payload_variant: Some(PayloadVariant::Encrypted(encrypted)),
        ..Default::default()
    };

    debug!("Response meshpacket:\n{:?}", tx_packet);
    let udp_packet = tx_packet.encode_to_vec();
    debug!("Sending textmsg:\n{:?}", udp_packet.hex_dump());
    let n_sent = state.sock_tx.send_to(&udp_packet, tx_addr).await?;
    info!("Sent {n_sent} bytes via udp to {tx_addr}");

    Ok(())
}

pub async fn send_nodeinfo(state: Arc<MyState>) -> anyhow::Result<()> {
    #[allow(deprecated)]
    let nodeinfo = User {
        id: state.config.node_id_s.clone(),
        long_name: state.config.long_name.clone(),
        short_name: state.config.short_name.clone(),
        macaddr: state.config.mac.to_vec(),
        hw_model: HardwareModel::PrivateHw.into(),
        role: Role::Client.into(),
        is_unmessagable: Some(false),
        is_licensed: false,
        public_key: state.config.public_key.to_vec(),
    };
    debug!("My nodeinfo:\n{nodeinfo:?}");

    let tx_data = Data {
        portnum: PortNum::NodeinfoApp.into(),
        want_response: false,
        bitfield: Some(0),
        payload: nodeinfo.encode_to_vec(),
        ..Default::default()
    };
    let plaintext = tx_data.encode_to_vec();
    debug!("My nodeinfo data ({} bytes)", plaintext.len());

    let ch_hash = channel_hash(&state.config.channel_name, &state.config.aes_key);

    loop {
        let packet_id = state.rng.lock().await.random_range(65536..u32::MAX);
        let encrypted = encrypt_payload(
            &plaintext,
            packet_id,
            state.config.node_id,
            &state.config.aes_key,
        );

        let tx_packet = MeshPacket {
            channel: ch_hash,
            transport_mechanism: TransportMechanism::TransportInternal.into(),
            priority: Priority::High.into(),
            from: state.config.node_id,
            to: MESH_BROADCAST_ADDR,
            id: packet_id,
            hop_limit: state.config.hop_limit.into(),
            hop_start: state.config.hop_limit.into(),
            payload_variant: Some(PayloadVariant::Encrypted(encrypted)),
            ..Default::default()
        };
        debug!("Sending nodeinfo meshpacket:\n{tx_packet:?}");

        let tx_addr = state.multi_sockaddr;
        let udp_packet = tx_packet.encode_to_vec();
        debug!("Sending nodeinfo:\n{:?}", udp_packet.hex_dump());
        let n_sent = state.sock_tx.send_to(&udp_packet, tx_addr).await?;
        info!("Sent {n_sent} bytes via udp to {tx_addr}");

        tokio::time::sleep(tokio::time::Duration::from_secs(
            state.config.nodeinfo_interval,
        ))
        .await;
    }

    // shut up, clippy
    #[allow(unreachable_code)]
    Ok(())
}

/// Send a PKI-encrypted direct message to a specific node.
///
/// Looks up the recipient's public key from the node database,
/// encrypts with X25519+AES-256-CCM, and sends via UDP.
pub async fn send_private_msg(
    state: Arc<MyState>, tx_addr: net::SocketAddr, to: u32, text: &str,
) -> anyhow::Result<()> {
    // Look up recipient's public key

    let node = state
        .nodedb
        .read()
        .await
        .db
        .get(&to)
        .ok_or_else(|| anyhow::anyhow!("Node !{to:08x} not in nodedb"))?
        .clone();

    let remote_pub_key = {
        if node.public_key_b64.is_empty() {
            anyhow::bail!("Node !{to:08x} has no public key");
        }
        let decoded = BASE64_STANDARD.decode(&node.public_key_b64)?;
        let key: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!(
                "Bad public key length for !{to:08x}: {} (expected 32)",
                v.len()
            )
        })?;
        key
    };

    // Build the Data payload
    let tx_data = Data {
        portnum: PortNum::TextMessageApp.into(),
        want_response: false,
        bitfield: Some(0),
        payload: text.as_bytes().to_vec(),
        ..Default::default()
    };
    let plaintext = tx_data.encode_to_vec();

    // Generate packet ID and extra nonce
    let mut rng = state.rng.lock().await;
    let packet_id = rng.random_range(65536..u32::MAX);
    let extra_nonce: u32 = rng.random();
    drop(rng);

    // Encrypt
    let encrypted = encrypt_payload_pki(
        &plaintext,
        packet_id,
        state.config.node_id,
        extra_nonce,
        &state.config.private_key,
        &remote_pub_key,
    )?;

    // Build and send MeshPacket
    let tx_packet = MeshPacket {
        channel: 0,
        transport_mechanism: TransportMechanism::TransportMulticastUdp.into(),

        priority: Priority::High.into(),
        from: state.config.node_id,
        to,
        id: packet_id,
        hop_limit: state.config.hop_limit.into(),
        hop_start: state.config.hop_limit.into(),
        pki_encrypted: true,
        public_key: state.config.public_key.to_vec(),
        payload_variant: Some(PayloadVariant::Encrypted(encrypted)),
        ..Default::default()
    };

    debug!("PKI encrypted meshpacket:\n{tx_packet:?}");
    let udp_packet = tx_packet.encode_to_vec();
    debug!("Sending private msg:\n{:?}", udp_packet.hex_dump());
    let n_sent = state.sock_tx.send_to(&udp_packet, tx_addr).await?;
    info!(
        "Sent {} bytes ({:?}) PKI-encrypted to {} ({} / {}, {}) via {}",
        n_sent, text, node.short_name, node.id, node.id_s, node.long_name, tx_addr
    );

    Ok(())
}
// EOF
