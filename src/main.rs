use spicy_language_server::Lsp;

#[tokio::main]
async fn main() {
    Lsp::run().await;
}
