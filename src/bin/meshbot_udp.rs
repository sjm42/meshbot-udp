// bin/tcp_server.rs

use clap::Parser;
use prost::Message;

use meshbot_udp::*;

const BUFSZ: usize = 65536; // for XXL jumbo frames :)

fn main() -> anyhow::Result<()> {
    let mut opts = CliOpts::parse();
    opts.start_pgm(env!("CARGO_BIN_NAME"))?;
    let config = MyConfig::new(&opts)?;
    debug!("Config: {:?}", config);

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move { run_server(opts, config).await })?;

    Ok(())
}

async fn run_server(opts: CliOpts, config: MyConfig) -> anyhow::Result<()> {
    let state = Arc::new(MyState::new(opts, config).await?);

    debug!("Binding to multicast address {}", state.multi_sockaddr);
    let sock_rx = tokio::net::UdpSocket::bind(state.multi_sockaddr).await?;

    debug!("Joining multicast group");
    if let (net::IpAddr::V4(multi), net::IpAddr::V4(iface)) =
        (state.multicast_addr, state.interface_addr)
    {
        sock_rx.join_multicast_v4(multi, iface)?;
    } else {
        anyhow::bail!("Unfortunately we don't support IPv6 here just yet.")
    }

    info!(
        "Listening on {} ({})",
        sock_rx.local_addr()?,
        String::from_utf8_lossy(
            sock_rx.device()?.unwrap_or_default().as_slice()
        )
    );

    tokio::task::spawn(send_nodeinfo(state.clone()));

    let mut dispatcher = MsgDispatcher::default();
    dispatcher.add_handler(PortNum::TextMessageApp, reply_to_ping);

    let mut udp_rx_buf = [0; BUFSZ];
    loop {
        let (len, rx_addr) = sock_rx.recv_from(&mut udp_rx_buf).await?;
        info!("Received {len} bytes from {rx_addr}");

        if rx_addr == state.tx_sockaddr {
            info!("Ignoring udp from self");
            continue;
        }
        match get_wild(&state.config.udp_whitelist, &rx_addr.to_string()) {
            Some(true) => (), // pass it
            _ => {
                info!("RX address not whitelisted. Packet ignored.");
                continue;
            }
        }
        // attempting to decode mesh packet structure
        let rx_packet = match MeshPacket::decode(&udp_rx_buf[..len]) {
            Ok(packet) => packet,
            Err(e) => {
                error!("Packet decode error: {e:?}");
                continue;
            }
        };
        info!("Decoded packet:\n{rx_packet:?}");

        {
            // inner scope to release write lock
            let mut pcache = state.packet_cache.write().await;
            if pcache.get(&rx_packet.id).is_some() {
                info!("Duplicate packet ignored.");
                continue;
            }
            pcache.insert(rx_packet.id, Utc::now().timestamp());
        }

        // outer structure of mesh packet was successfully parsed,
        // now attempt decryption

        let payload = match decrypt_payload(&rx_packet, &state.config.aes_key) {
            None => continue, // skipping non-encrypted packets here
            Some(p) => p,
        };
        debug!("Decrypted payload:\n{:?}", payload.hex_dump());

        // attempting to decode the inner payload that was supposedly decrypted

        let rx_data = match Data::decode(payload.as_slice()) {
            Ok(rx_data) => rx_data,
            Err(e) => {
                error!("Payload decode error: {e:?}");
                continue;
            }
        };
        info!("Decoded payload:\n{rx_data:?}");
        dispatcher
            .process(state.clone(), rx_addr, rx_packet.clone(), rx_data.clone())
            .await;
    }

    // shut up, clippy
    #[allow(unreachable_code)]
    Ok(())
}

async fn reply_to_ping(
    state: Arc<MyState>,
    _rx_addr: net::SocketAddr,
    _rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    if rx_data.payload != "Pim".as_bytes() {
        debug!("Not sending a response");
        return Ok(HandlerStatus::Continue);
    }

    let reply = "Pom";
    let tx_addr = state.multi_sockaddr;

    // for some reason, sending to the node is not working
    // send_text_msg(state, tx_addr, rx_packet.from, reply).await?;

    // ...but sending to broadcast works, sigh.
    send_text_msg(state, tx_addr, MESH_BROADCAST_ADDR, reply).await?;
    Ok(HandlerStatus::Continue)
}
// EOF
