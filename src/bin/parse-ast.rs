use {
    anyhow::Result,
    spicy_language_server::{options::Options, spicy},
    std::env,
};

#[tokio::main]
async fn main() -> Result<()> {
    for input in env::args().skip(1) {
        let contents = std::fs::read_to_string(&input)?;

        spicy::parse(input, &contents, &Options::default()).await?;
    }

    Ok(())
}
