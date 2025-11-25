// mesh.rs

use crypto::{
    aes::{self, KeySize},
    symmetriccipher::SynchronousStreamCipher,
};
use futures::future::BoxFuture;
use std::future::Future;

use crate::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MyNodeInfo {
    pub id_s: String,
    pub short_name: String,
    pub long_name: String,
    pub hw_model: i32,
    pub licensed: bool,
    pub role: i32,
    pub last_seen: i64,
}

impl From<User> for MyNodeInfo {
    fn from(user: User) -> Self {
        Self {
            id_s: user.id,
            short_name: user.short_name,
            long_name: user.long_name,
            hw_model: user.hw_model,
            licensed: user.is_licensed,
            role: user.role,
            last_seen: Utc::now().timestamp(),
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
        info!("Saving nodedb to {file}");
        BufWriter::new(File::create(file)?).write_all(serde_json::to_string(self)?.as_bytes())?;
        Ok(())
    }
}

pub enum HandlerStatus {
    Continue,
    Finished,
}

pub type MsgHandler = Box<
    dyn Fn(Arc<MyState>, MeshPacket, Data) -> BoxFuture<'static, anyhow::Result<HandlerStatus>>,
>;

fn into_handler<Fut: Future<Output = anyhow::Result<HandlerStatus>> + Send + 'static>(
    f: impl Fn(Arc<MyState>, MeshPacket, Data) -> Fut + 'static,
) -> MsgHandler {
    Box::new(move |st, p, d| Box::pin(f(st, p, d)))
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
        &mut self,
        port: PortNum,
        handler: impl Fn(Arc<MyState>, MeshPacket, Data) -> Fut + 'static,
    ) {
        self.handlers
            .entry(port)
            .or_default()
            .push(into_handler(handler));
    }
    pub fn remove_handlers(&mut self, port: PortNum) {
        self.handlers.remove(&port);
    }

    pub async fn process(&self, state: Arc<MyState>, rx_packet: MeshPacket, rx_data: Data) {
        let port = match rx_data.portnum.try_into() {
            Err(e) => {
                error!("Unknown port number: {e}");
                return;
            }
            Ok(port) => port,
        };
        let handlers = match self.handlers.get(&port) {
            None => {
                error!("No handlers for port {port:?}");
                return;
            }
            Some(handlers) => handlers,
        };
        for handler in handlers {
            match handler(state.clone(), rx_packet.clone(), rx_data.clone()).await {
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
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    let msg = String::from_utf8_lossy(&rx_data.payload);
    info!("Got MSG: \"{msg}\"");
    Ok(HandlerStatus::Continue)
}

async fn handle_nodeinfo(
    state: Arc<MyState>,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Nodeinfo message");
    // let info = String::from_utf8_lossy(&data.payload);
    // info!("Got Nodeinfo:\n{info}");

    let nodeinfo = protobufs::User::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed Nodeinfo:\n{nodeinfo:?}");

    let mut nodedb = state.nodedb.write().await;
    nodedb.db.insert(123, nodeinfo.into());
    nodedb.save(&state.opts)?;
    Ok(HandlerStatus::Continue)
}

async fn handle_position(
    _state: Arc<MyState>,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Position message");
    let pos = protobufs::Position::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed Position:\n{pos:?}");
    Ok(HandlerStatus::Continue)
}

async fn handle_routing(
    _state: Arc<MyState>,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Routing message");
    let routing = protobufs::Routing::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed Routing:\n{routing:?}");
    Ok(HandlerStatus::Continue)
}

async fn handle_traceroute(
    _state: Arc<MyState>,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    info!("Got Traceroute message");
    let trace = protobufs::RouteDiscovery::decode(rx_data.payload.as_slice()).unwrap_or_default();
    info!("Parsed traceroute:\n{trace:?}");

    Ok(HandlerStatus::Continue)
}

pub fn decrypt_payload(rx_packet: &MeshPacket, key: &[u8; 16]) -> Option<Vec<u8>> {
    let enc_data = match &rx_packet.payload_variant {
        Some(PayloadVariant::Encrypted(enc_data)) => enc_data,
        _ => return None, // we ignore non-encrypted packets
    };

    let data_len = enc_data.len();
    info!("Attempting to decrypt {data_len} bytes");
    info!("Encrypted payload:\n{:?}", enc_data.hex_dump());

    let mut aes_iv: [u8; 16] = [0; 16];
    aes_iv[0..4].copy_from_slice(&rx_packet.id.to_le_bytes());
    aes_iv[8..12].copy_from_slice(&rx_packet.from.to_le_bytes());
    let mut cipher = aes::ctr(KeySize::KeySize128, key, &aes_iv);
    let mut outbuf = vec![0; data_len];
    cipher.process(enc_data, &mut outbuf);
    Some(outbuf)
}

pub async fn send_text_msg(state: Arc<MyState>, to: u32, text: &str) -> anyhow::Result<()> {
    let tx_data = Data {
        portnum: PortNum::TextMessageApp as i32,
        payload: text.as_bytes().to_vec(),
        ..Default::default()
    };

    // Create the payload variant
    let tx_packet = MeshPacket {
        channel: 0,
        transport_mechanism: TransportMechanism::TransportInternal.into(),
        from: state.config.node_id,
        to,
        id: state.rng.lock().await.random_range(65536..u32::MAX),
        priority: Priority::Default as i32,
        hop_limit: DEFAULT_HOP_LIMIT,
        payload_variant: Some(PayloadVariant::Decoded(tx_data)),
        ..Default::default()
    };

    let udp_packet = tx_packet.encode_to_vec();
    info!("Sending response:\n{:?}", udp_packet.hex_dump());
    let n_sent = state
        .sock_tx
        .send_to(&udp_packet, state.multi_sockaddr)
        .await?;
    info!("Sent {n_sent} bytes.");

    Ok(())
}

// EOF
