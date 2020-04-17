use {
    anyhow::Result,
    log::{debug, info},
    lsp_server::Connection,
    spicy_language_server::{lsp, options::Options},
    structopt::StructOpt,
};

fn main() -> Result<()> {
    let opt = Options::from_args();

    // Set up logging. Because `stdio_transport` gets a lock on stdout and stdin, we must have
    // our logging only write out to stderr.
    flexi_logger::Logger::with_env_or_str(opt.verbosity.as_str())
        .log_to_file()
        .directory(opt.log_directory.as_str())
        .start()?;
    info!("Starting Spicy LSP server");
    debug!("Options at startup: {:?}", &opt);

    // Create the transport. Includes the stdio (stdin and stdout) versions but this could
    // also be implemented to use sockets or HTTP.
    let (connection, io_threads) = Connection::stdio();

    // Run the server and wait for the two threads to end (typically by trigger LSP Exit event).
    lsp::run_server(connection, opt)?;
    io_threads.join()?;

    Ok(())
}
