use {
    anyhow::Result,
    log::{debug, info},
    lsp_server::Connection,
    spicy_language_server::{lsp, options::Options},
    structopt::StructOpt,
};

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Options::from_args();

    // Set up logging. Because `stdio_transport` gets a lock on stdout and stdin, we must have
    // our logging only write out to stderr.
    let mut logger = flexi_logger::Logger::with_env_or_str(opt.verbosity.as_str());

    if let Some(log_dir) = &opt.log_directory {
        // If the user specified a log directory, log to a file in that directory. Otherwise log to stderr.
        logger = logger.directory(log_dir).log_to_file();
    }

    logger.start()?;

    info!("Starting Spicy LSP server");
    debug!("Options at startup: {:?}", &opt);

    // Create the transport. Includes the stdio (stdin and stdout) versions but this could
    // also be implemented to use sockets or HTTP.
    let (connection, io_threads) = Connection::stdio();

    // Run the server and wait for the two threads to end (typically by trigger LSP Exit event).
    lsp::run_server(connection, opt).await?;
    io_threads.join()?;

    Ok(())
}
