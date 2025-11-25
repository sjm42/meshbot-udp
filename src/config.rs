// config.rs

use crate::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize, clap::Parser)]
pub struct CliOpts {
    #[arg(short, long)]
    pub verbose: bool,
    #[arg(short, long)]
    pub debug: bool,
    #[arg(short, long)]
    pub trace: bool,

    #[arg(short, long, default_value = "10.0.0.1")]
    pub interface_addr: String,
    #[arg(short, long, default_value = "224.0.0.69")]
    pub multicast_addr: String,
    #[arg(short, long, default_value = "4403")]
    pub port: u16,

    #[arg(short, long, default_value = "$HOME/meshbot/config.json")]
    pub config_file: String,
    #[arg(short, long, default_value = "$HOME/meshbot/nodedb.json")]
    pub nodedb_file: String,
}

impl CliOpts {
    pub fn finalize(&mut self) -> anyhow::Result<()> {
        self.config_file = shellexpand::full(&self.config_file)?.into_owned();
        self.nodedb_file = shellexpand::full(&self.nodedb_file)?.into_owned();
        Ok(())
    }

    pub fn get_loglevel(&self) -> Level {
        if self.trace {
            Level::TRACE
        } else if self.debug {
            Level::DEBUG
        } else if self.verbose {
            Level::INFO
        } else {
            Level::ERROR
        }
    }

    pub fn start_pgm(&mut self, name: &str) -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(self.get_loglevel())
            .with_target(false)
            .init();

        self.finalize()?;
        info!("Starting up {name} v{}...", env!("CARGO_PKG_VERSION"));
        debug!("Git branch: {}", env!("GIT_BRANCH"));
        debug!("Git commit: {}", env!("GIT_COMMIT"));
        debug!("Source timestamp: {}", env!("SOURCE_TIMESTAMP"));
        debug!("Compiler version: {}", env!("RUSTC_VERSION"));
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MyConfig {
    pub send_nodeinfo: bool,
    pub nodeinfo_interval: i64,
    pub aes_key: [u8; 16],

    pub mac: [u8; 6],
    pub node_id: u32,
    pub node_id_s: String,
    pub short_name: String,
    pub long_name: String,
}

impl Default for MyConfig {
    fn default() -> Self {
        let mut rng = rand::rng();

        let mut mac = [0; 6];
        rng.fill_bytes(&mut mac);
        mac[0] &= 0b1111_1110; // make sure it's unicast
        mac[0] |= 0b0000_0010; // make it "locally administered"
        let node_id =
            (mac[2] as u32) << 24 | (mac[3] as u32) << 16 | (mac[4] as u32) << 8 | mac[5] as u32;
        Self {
            send_nodeinfo: true,
            nodeinfo_interval: 3600,
            aes_key: DEFAULT_AES_KEY,

            mac,
            node_id,
            node_id_s: format!("!{:02x}{:02x}{:02x}{:02x}", mac[2], mac[3], mac[4], mac[5]),
            short_name: format!("{:02x}{:02x}", mac[4], mac[5]),
            long_name: format!("Example node {:02x}{:02x}", mac[4], mac[5]),
        }
    }
}

impl MyConfig {
    pub fn new(opts: &CliOpts) -> anyhow::Result<Self> {
        let file = &opts.config_file;
        info!("Attempt reading config file {file}");
        let config: MyConfig = match File::open(file) {
            // if the file does exist, the contents must be valid
            Ok(bfile) => serde_json::from_reader(BufReader::new(bfile))?,
            Err(e) => {
                info!("Error reading config file {file}: {e} -- Using default config");
                let c = MyConfig::default();
                info!("Writing new config to {file}");
                BufWriter::new(File::create(file)?)
                    .write_all(serde_json::to_string(&c)?.as_bytes())?;
                info!("New config file saved.");
                c
            }
        };

        Ok(config)
    }
}
// EOF
