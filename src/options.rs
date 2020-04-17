use structopt::StructOpt;

#[derive(Debug, Default, StructOpt)]
pub struct Options {
    #[structopt(long="verbosity", possible_values=&["error", "warn", "info", "debug"], default_value="info")]
    pub verbosity: String,

    #[structopt(long = "log-directory", default_value = "/tmp")]
    pub log_directory: String,

    /// Path to 'spicyc', if not given looked up in '$PATH'.
    #[structopt(long = "spicyc")]
    pub spicyc: Option<String>,
}
