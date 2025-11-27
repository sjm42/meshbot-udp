// mesh.rs

use base64::prelude::*;
use crypto::{
    aes::{self, KeySize},
    symmetriccipher::SynchronousStreamCipher,
};
use futures::future::BoxFuture;
use std::future::Future;

use crate::*;

pub const MESH_BROADCAST_ADDR: u32 = u32::MAX;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MyNodeInfo {
    pub id: u32,
    pub id_s: String,
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
        let hw_model: HardwareModel =
            user.hw_model.try_into().unwrap_or(HardwareModel::PrivateHw);
        let role: Role = user.role.try_into().unwrap_or(Role::Client);
        let now = Utc::now();
        Self {
            id,
            id_s: user.id,
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

fn into_handler<
    Fut: Future<Output = anyhow::Result<HandlerStatus>> + Send + 'static,
>(
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
    pub fn add_handler<
        Fut: Future<Output = anyhow::Result<HandlerStatus>> + Send + 'static,
    >(
        &mut self,
        port: PortNum,
        handler: impl Fn(Arc<MyState>, net::SocketAddr, MeshPacket, Data) -> Fut
        + 'static,
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
        &self,
        state: Arc<MyState>,
        rx_addr: net::SocketAddr,
        rx_packet: MeshPacket,
        rx_data: Data,
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
            match handler(
                state.clone(),
                rx_addr,
                rx_packet.clone(),
                rx_data.clone(),
            )
            .await
            {
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
    _state: Arc<MyState>,
    _rx_addr: net::SocketAddr,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    let msg = String::from_utf8_lossy(&rx_data.payload);
    info!("Got MSG: \"{msg}\"");
    Ok(HandlerStatus::Continue)
}

async fn handle_nodeinfo(
    state: Arc<MyState>,
    _rx_addr: net::SocketAddr,
    _rx_packet: MeshPacket,
    rx_data: Data,
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
    _state: Arc<MyState>,
    _rx_addr: net::SocketAddr,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Position message");
    let pos = protobufs::Position::decode(rx_data.payload.as_slice())
        .unwrap_or_default();
    info!("Parsed Position:\n{pos:?}");
    Ok(HandlerStatus::Continue)
}

async fn handle_routing(
    _state: Arc<MyState>,
    _rx_addr: net::SocketAddr,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Routing message");
    let routing = protobufs::Routing::decode(rx_data.payload.as_slice())
        .unwrap_or_default();
    info!("Parsed Routing:\n{routing:?}");
    Ok(HandlerStatus::Continue)
}

async fn handle_traceroute(
    _state: Arc<MyState>,
    _rx_addr: net::SocketAddr,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Traceroute message");
    let trace = protobufs::RouteDiscovery::decode(rx_data.payload.as_slice())
        .unwrap_or_default();
    info!("Parsed traceroute:\n{trace:?}");

    Ok(HandlerStatus::Continue)
}

pub fn decrypt_payload(
    rx_packet: &MeshPacket,
    key: &[u8; 16],
) -> Option<Vec<u8>> {
    let enc_data = match &rx_packet.payload_variant {
        Some(PayloadVariant::Encrypted(enc_data)) => enc_data,
        _ => return None, // we ignore non-encrypted packets
    };

    let data_len = enc_data.len();
    info!("Attempting to decrypt {data_len} bytes");
    debug!("Encrypted payload:\n{:?}", enc_data.hex_dump());

    let mut aes_iv: [u8; 16] = [0; 16];
    aes_iv[0..4].copy_from_slice(&rx_packet.id.to_le_bytes());
    aes_iv[8..12].copy_from_slice(&rx_packet.from.to_le_bytes());
    let mut cipher = aes::ctr(KeySize::KeySize128, key, &aes_iv);
    let mut outbuf = vec![0; data_len];
    cipher.process(enc_data, &mut outbuf);
    Some(outbuf)
}

pub async fn send_text_msg(
    state: Arc<MyState>,
    tx_addr: net::SocketAddr,
    to: u32,
    text: &str,
) -> anyhow::Result<()> {
    let tx_data = Data {
        portnum: PortNum::TextMessageApp.into(),
        want_response: false,
        bitfield: Some(0),
        payload: text.as_bytes().to_vec(),
        ..Default::default()
    };

    let packet_id = if to == MESH_BROADCAST_ADDR {
        state.rng.lock().await.random_range(65536..u32::MAX)
    } else {
        0
    };

    // Create the payload variant
    let tx_packet = MeshPacket {
        channel: 0,
        transport_mechanism: TransportMechanism::TransportMulticastUdp.into(),
        priority: Priority::High.into(),
        // rx_time: Utc::now().timestamp() as u32,
        from: state.config.node_id,
        to,
        id: packet_id,
        hop_limit: state.config.hop_limit.into(),
        hop_start: state.config.hop_limit.into(),
        payload_variant: Some(PayloadVariant::Decoded(tx_data)),
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
    let nodeinfo = User {
        id: state.config.node_id_s.clone(),
        long_name: state.config.long_name.clone(),
        short_name: state.config.short_name.clone(),
        hw_model: HardwareModel::PrivateHw.into(),
        role: Role::Client.into(),
        is_unmessagable: Some(false),
        is_licensed: false,
        ..Default::default()
    };
    debug!("My nodeinfo:\n{nodeinfo:?}");

    let tx_data = Data {
        portnum: PortNum::NodeinfoApp.into(),
        want_response: false,
        bitfield: Some(0),
        payload: nodeinfo.encode_to_vec(),
        ..Default::default()
    };
    debug!("My nodeinfo data: {tx_data:?}");

    loop {
        let packet_id = state.rng.lock().await.random_range(65536..u32::MAX);
        let tx_packet = MeshPacket {
            channel: 0,
            transport_mechanism: TransportMechanism::TransportMulticastUdp
                .into(),
            priority: Priority::High.into(),
            from: state.config.node_id,
            to: MESH_BROADCAST_ADDR,
            id: packet_id,
            hop_limit: state.config.hop_limit.into(),
            hop_start: state.config.hop_limit.into(),
            payload_variant: Some(PayloadVariant::Decoded(tx_data.clone())),
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
// EOF
