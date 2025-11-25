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

    info!("Binding to multicast address {}", state.multi_sockaddr);
    let sock_rx = tokio::net::UdpSocket::bind(state.multi_sockaddr).await?;

    info!("Joining multicast group");
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
        String::from_utf8_lossy(sock_rx.device()?.unwrap_or_default().as_slice())
    );

    let mut dispatcher = MsgDispatcher::default();
    dispatcher.add_handler(PortNum::TextMessageApp, reply_to_ping);

    let mut udp_rx_buf = [0; BUFSZ];
    loop {
        let (len, addr) = sock_rx.recv_from(&mut udp_rx_buf).await?;
        info!(
            "Received {len} bytes from {addr}:\n{:02x?}",
            &udp_rx_buf[0..len]
        );

        // attempting to decode mesh packet structure
        let rx_packet = match MeshPacket::decode(&udp_rx_buf[..len]) {
            Ok(packet) => packet,
            Err(e) => {
                error!("Packet decode error: {e:?}");
                continue;
            }
        };
        info!("Decoded packet:\n{rx_packet:?}");

        // outer structure of mesh packet was successfully parsed,
        // now attempt decryption

        let payload = match decrypt_payload(&rx_packet, &state.config.aes_key) {
            None => continue, // skipping non-encrypted packets here
            Some(p) => p,
        };
        info!("Decrypted payload:\n{:?}", payload.hex_dump());

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
            .process(state.clone(), rx_packet.clone(), rx_data.clone())
            .await;
    }

    // shut up, clippy
    #[allow(unreachable_code)]
    Ok(())
}

async fn reply_to_ping(
    state: Arc<MyState>,
    rx_packet: MeshPacket,
    rx_data: Data,
) -> anyhow::Result<HandlerStatus> {
    if rx_data.payload != "Pim".as_bytes() {
        debug!("Not sending a response");
        return Ok(HandlerStatus::Continue);
    }

    let reply = "Pom";
    send_text_msg(state, rx_packet.from, reply).await?;
    Ok(HandlerStatus::Continue)
}
// EOF
