use std::collections::BTreeMap;

use itertools::Itertools;
use serde::Deserialize;
use tokio::sync::RwLock;
use tower_lsp::{
    LanguageServer, LspService, Server,
    jsonrpc::{Error, Result},
    lsp_types::{
        CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams,
        CompletionResponse, DidChangeTextDocumentParams, DidOpenTextDocumentParams,
        DocumentFormattingParams, DocumentRangeFormattingParams, InitializeParams,
        InitializeResult, InsertTextFormat, OneOf, Position, Range, ServerCapabilities,
        TextDocumentItem, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url,
    },
};

#[derive(Default)]
pub struct Lsp {
    state: State,
}

impl Lsp {
    pub async fn run() {
        let (service, socket) = LspService::new(|_client| Lsp::default());

        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();

        Server::new(stdin, stdout, socket).serve(service).await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Lsp {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(CompletionOptions::default()),
                document_formatting_provider: Some(tower_lsp::lsp_types::OneOf::Left(true)),
                document_range_formatting_provider: Some(OneOf::Left(true)),
                ..ServerCapabilities::default()
            },
            ..InitializeResult::default()
        })
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let TextDocumentItem { uri, text, .. } = params.text_document;
        let mut sources = self.state.sources.write().await;
        sources.insert(uri, text);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let Some(changes) = params.content_changes.into_iter().next() else {
            return;
        };
        assert!(changes.range.is_none(), "unexpected diff mode");

        let uri = params.text_document.uri;

        let mut sources = self.state.sources.write().await;
        sources.insert(uri, changes.text);
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        let sources = self.state.sources.read().await;

        let Some(source) = sources.get(&uri) else {
            return Ok(None);
        };

        let Some(trigger) = source.lines().nth(position.line as usize) else {
            return Ok(None);
        };

        let snippets = [(
            "unit",
            "type ${1:X} = unit {
    ${2:a}: ${3:uint8};
};
",
        )];

        let completions: Vec<_> = snippets
            .iter()
            .filter_map(|s| {
                let (key, snippet) = *s;

                if !key.contains(trigger) {
                    return None;
                }

                Some(CompletionItem {
                    label: key.into(),
                    insert_text: Some(snippet.into()),
                    kind: Some(CompletionItemKind::SNIPPET),
                    insert_text_format: Some(InsertTextFormat::SNIPPET),
                    ..CompletionItem::default()
                })
            })
            .chain(keywords().into_iter().filter_map(|k| {
                if k.contains(trigger) {
                    Some(CompletionItem {
                        label: k.clone(),
                        insert_text: Some(k),
                        kind: Some(CompletionItemKind::KEYWORD),
                        ..CompletionItem::default()
                    })
                } else {
                    None
                }
            }))
            .collect();

        Ok(Some(CompletionResponse::from(completions)))
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;

        let source = {
            let sources = self.state.sources.read().await;
            sources.get(&uri).cloned()
        };
        let Some(source) = source else {
            return Ok(None);
        };

        let (num_lines, num_last_line_chars) = source
            .lines()
            .enumerate()
            .last()
            .map_or((0, 0), |(lines, line)| (lines, line.len()));

        let range = Range::new(
            Position::new(0, 0),
            Position::new(
                u32::try_from(num_lines).map_err(|_| Error::internal_error())?,
                u32::try_from(num_last_line_chars).map_err(|_| Error::internal_error())?,
            ),
        );

        Ok(format(&source).map(|formatted| vec![TextEdit::new(range, formatted)]))
    }

    async fn range_formatting(
        &self,
        params: DocumentRangeFormattingParams,
    ) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;

        let source = {
            let sources = self.state.sources.read().await;
            sources.get(&uri).cloned()
        };
        let Some(source) = source else {
            return Ok(None);
        };

        let Range { start, end } = params.range;
        let num_lines = if start.line > end.line {
            return Ok(None);
        } else {
            end.line - start.line
        };

        let lines = source
            .lines()
            .skip(start.line as usize)
            .take(num_lines as usize)
            .join("\n");

        Ok(format(&lines).map(|formatted| vec![TextEdit::new(params.range, formatted)]))
    }
}

#[derive(Default)]
struct State {
    sources: RwLock<BTreeMap<Url, String>>,
}

fn keywords() -> Vec<String> {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct NodeType {
        #[serde(rename = "type")]
        type_: String,
        named: bool,
    }

    let Ok(node_types) = serde_json::from_str::<Vec<NodeType>>(tree_sitter_spicy::NODE_TYPES)
    else {
        return Vec::default();
    };

    node_types
        .into_iter()
        .filter(|t| !t.named)
        .map(|t| t.type_)
        .collect()
}

fn format(source: &str) -> Option<String> {
    spicy_format::format(source, false, true).ok()
}

#[cfg(test)]
mod test {
    use std::u32;

    use insta::assert_debug_snapshot;
    use tower_lsp::{
        LanguageServer,
        jsonrpc::Result,
        lsp_types::{
            CompletionParams, CompletionResponse, DidChangeTextDocumentParams,
            DidOpenTextDocumentParams, DocumentFormattingParams, DocumentRangeFormattingParams,
            FormattingOptions, InitializeParams, PartialResultParams, Position, Range,
            TextDocumentContentChangeEvent, TextDocumentIdentifier, TextDocumentItem,
            TextDocumentPositionParams, TextEdit, Url, VersionedTextDocumentIdentifier,
            WorkDoneProgressParams,
        },
    };

    use crate::Lsp;

    #[derive(Default)]
    struct Server(Lsp);

    impl Server {
        async fn initialize(self) -> Result<ServerInitialized> {
            let _ = self.0.initialize(InitializeParams::default()).await;
            Ok(ServerInitialized(self.0))
        }
    }

    struct ServerInitialized(Lsp);

    impl ServerInitialized {
        async fn did_open(&self, params: DidOpenTextDocumentParams) {
            self.0.did_open(params).await
        }

        async fn did_change(&self, params: DidChangeTextDocumentParams) {
            self.0.did_change(params).await
        }

        async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
            self.0.completion(params).await
        }

        async fn formatting(
            &self,
            params: DocumentFormattingParams,
        ) -> Result<Option<Vec<TextEdit>>> {
            self.0.formatting(params).await
        }

        async fn range_formatting(
            &self,
            params: DocumentRangeFormattingParams,
        ) -> Result<Option<Vec<TextEdit>>> {
            self.0.range_formatting(params).await
        }
    }

    #[tokio::test]
    async fn lifecycle() {
        Server::default()
            .initialize()
            .await
            .unwrap()
            .0
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn did_change() {
        let server = Server::default().initialize().await.unwrap();

        let uri = Url::from_file_path("/x.spicy").unwrap();

        server
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(uri.clone(), "spicy".into(), 0, "".into()),
            })
            .await;

        assert_eq!(server.0.state.sources.read().await.get(&uri).unwrap(), "");

        server
            .did_change(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(uri.clone(), 1),
                content_changes: vec![],
            })
            .await;

        assert_eq!(server.0.state.sources.read().await.get(&uri).unwrap(), "");

        server
            .did_change(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(uri.clone(), 1),
                content_changes: vec![TextDocumentContentChangeEvent {
                    text: "foo".into(),
                    range: None,
                    range_length: None,
                }],
            })
            .await;

        assert_eq!(
            server.0.state.sources.read().await.get(&uri).unwrap(),
            "foo"
        );
    }

    #[tokio::test]
    async fn completion() {
        let server = Server::default().initialize().await.unwrap();

        let uri = Url::from_file_path("/x.spicy").unwrap();

        server
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "spicy".into(),
                    0,
                    "
COMPLETELY_UNKNOWN
uni
"
                    .into(),
                ),
            })
            .await;

        // Completion out of bounds.
        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(u32::MAX, 0),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );

        // Completion for unknown file.
        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(
                            Url::from_file_path("/does_not_exist.spicy").unwrap()
                        ),
                        Position::new(u32::MAX, 0),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );

        // Complete on empty line.
        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(0, 0),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );

        // Complete on line with `COMPLETELY_UNKNOWN`.
        assert_eq!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(1, 0),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await,
            Ok(Some(CompletionResponse::from(vec![])))
        );

        // Complete on line with `uni`.
        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(2, 0),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );
    }

    #[tokio::test]
    async fn formatting() {
        let server = Server::default().initialize().await.unwrap();

        let uri = Url::from_file_path("/x.spicy").unwrap();

        server
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "spicy".into(),
                    0,
                    "    module   foo    ;      ".into(),
                ),
            })
            .await;

        assert_debug_snapshot!(
            server
                .formatting(DocumentFormattingParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    options: FormattingOptions::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_eq!(
            server
                .formatting(DocumentFormattingParams {
                    text_document: TextDocumentIdentifier::new(
                        Url::from_file_path("/does_not_exist.spicy").unwrap()
                    ),
                    options: FormattingOptions::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn range_formatting() {
        let server = Server::default().initialize().await.unwrap();

        let uri = Url::from_file_path("/x.spicy").unwrap();

        server
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "spicy".into(),
                    0,
                    "
module   foo    ;

type X =unit (){  };
"
                    .into(),
                ),
            })
            .await;

        assert_debug_snapshot!(
            server
                .range_formatting(DocumentRangeFormattingParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    range: Range::new(Position::new(1, 0), Position::new(2, 0)),
                    options: FormattingOptions::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_eq!(
            server
                .range_formatting(DocumentRangeFormattingParams {
                    text_document: TextDocumentIdentifier::new(
                        Url::from_file_path("/does_not_exist.spicy").unwrap()
                    ),
                    range: Range::new(Position::new(1, 0), Position::new(2, 0)),
                    options: FormattingOptions::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await,
            Ok(None)
        );
    }
}
