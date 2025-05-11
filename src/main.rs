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

#[tokio::main]
async fn main() -> Result<()> {
    Lsp::run().await;
    Ok(())
}

#[derive(Default)]
struct Lsp {
    state: State,
}

impl Lsp {
    async fn run() {
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

        let Ok(formatted) = spicy_format::format(&source, false, true) else {
            return Ok(None);
        };

        Ok(Some(vec![TextEdit::new(
            Range::new(
                Position::new(0, 0),
                Position::new(
                    u32::try_from(num_lines).map_err(|_| Error::internal_error())?,
                    u32::try_from(num_last_line_chars).map_err(|_| Error::internal_error())?,
                ),
            ),
            formatted,
        )]))
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

        let Ok(formatted) = spicy_format::format(&lines, false, true) else {
            return Ok(None);
        };

        Ok(Some(vec![TextEdit::new(params.range, formatted)]))
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
