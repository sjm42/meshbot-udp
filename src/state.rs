// state.rs

use crate::*;

#[derive(Debug)]
pub struct MyState {
    pub opts: CliOpts,
    pub config: MyConfig,
    pub nodedb: RwLock<NodeDb>,

    pub packet_cache: RwLock<HashMap<u32, i64>>,
    pub interface_addr: net::IpAddr,
    pub multicast_addr: net::IpAddr,
    pub multi_sockaddr: net::SocketAddr,
    pub tx_sockaddr: net::SocketAddr,
    pub rng: Mutex<StdRng>,
    pub sock_tx: UdpSocket,
}

impl MyState {
    pub async fn new(opts: CliOpts, config: MyConfig) -> anyhow::Result<Self> {
        let interface_addr = opts.interface_addr.parse()?;
        let multicast_addr = opts.multicast_addr.parse()?;
        let multi_sockaddr = net::SocketAddr::new(multicast_addr, opts.port);
        let tx_sockaddr = net::SocketAddr::new(interface_addr, opts.port);

        let rng = Mutex::new(StdRng::from_os_rng());
        info!("Binding to local address {}", tx_sockaddr);
        let sock_tx = tokio::net::UdpSocket::bind(tx_sockaddr).await?;

        let db_file = &opts.nodedb_file;
        info!("Attempt reading nodedb file {db_file}");
        let nodedb = match File::open(db_file) {
            // if the file does exist, the contents must be valid
            Ok(bfile) => serde_json::from_reader(BufReader::new(bfile))?,
            Err(e) => {
                info!(
                    "Cannot read nodedb from {db_file}: {e} -- Using empty nodedb"
                );
                let db = NodeDb::default();
                db.save(&opts)?;
                info!("New nodedb file saved.");
                db
            }
        };
        info!("We have nodedb with {} entries.", nodedb.db.len());

        Ok(Self {
            opts,
            config,
            nodedb: RwLock::new(nodedb),

            packet_cache: RwLock::new(HashMap::new()),
            interface_addr,
            multicast_addr,
            multi_sockaddr,
            tx_sockaddr,
            rng,
            sock_tx,
        })
    }
}
// EOF
