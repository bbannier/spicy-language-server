use {
    anyhow::Result,
    spicy_language_server::{options::Options, spicy},
    std::{env, path::Path},
};

fn main() -> Result<()> {
    for input in env::args().skip(1) {
        spicy::parse(&Path::new(&input).to_path_buf(), &Options::default())?;
    }

    Ok(())
}
