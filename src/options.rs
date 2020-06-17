use structopt::StructOpt;

#[derive(Debug, Default, StructOpt)]
pub struct Options {
    #[structopt(long="verbosity", possible_values=&["error", "warn", "info", "debug"], default_value="info")]
    /// Logging verbosity.
    pub verbosity: String,

    #[structopt(long = "log-directory")]
    /// Location of the log file. If not given log to stderr.
    pub log_directory: Option<String>,

    /// Path to 'spicyc', if not given looked up in '$PATH'.
    #[structopt(long = "spicyc")]
    pub spicyc: Option<String>,
}
