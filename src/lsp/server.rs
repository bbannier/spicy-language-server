use {
    crate::{lsp::ast, options::Options, spicy},
    anyhow::{anyhow, Result},
    crossbeam_channel::{select, Receiver, RecvError, Sender},
    log::{debug, info},
    lsp_server::{Connection, Message, Notification, Request, RequestId, Response},
    lsp_types::*,
    serde::{Deserialize, Serialize},
    static_assertions::assert_eq_size,
    std::{collections::HashMap, fs::read_to_string, path::Path},
};

async fn main_loop(server: Server) -> Result<()> {
    info!("starting main loop");

    let mut server = server;

    loop {
        let event = select! {
            recv(server.connection.receiver) -> msg => match msg {
                Ok(msg) => Event::Api(msg),
                Err(RecvError) => return Err(anyhow!("client exited without shutdown")),
            },
            recv(server.tasks.receiver) -> task => match task {
                Ok(task) => Event::Task(task),
                Err(RecvError) => continue,
            }
        };

        debug!("processing event: {:?}", event);

        match event {
            Event::Api(api) => match api {
                Message::Request(req) => {
                    if server.connection.handle_shutdown(&req)? {
                        break;
                    }

                    on_request(req, &mut server)?;
                }
                Message::Notification(not) => {
                    on_notification(not, &mut server)?;
                }
                Message::Response(_resp) => {}
            },
            Event::Task(task) => match task {
                Task::UpdateDocument(uri, text, version) => {
                    server.update_document(uri, text, version).await?
                }

                Task::PublishDiagnostics() => server.publish_diagnostics()?,
            },
        }
    }

    info!("finished main loop");

    Ok(())
}

pub async fn run_server(connection: Connection, options: Options) -> Result<()> {
    let server_capabilities = server_capabilities();
    let initialize_params = connection.initialize(serde_json::to_value(server_capabilities)?)?;
    let initialize_params: InitializeParams = serde_json::from_value(initialize_params)?;

    let cwd = Url::from_file_path(std::env::current_dir()?).ok();
    let _root_uri = initialize_params
        .root_uri
        .unwrap_or_else(|| cwd.expect("could not determine root_uri"));

    let tasks = Tasks::new();

    let server = Server {
        options,
        connection,
        tasks,
        documents: Documents::new(),
        _root_uri,
        open_document: None,
    };

    main_loop(server).await
}

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        // TODO(bbannier): enable more capabilities.
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                change: Some(TextDocumentSyncKind::Full), // TODO(bbannier): check if we can support incremental mode.
                open_close: Some(true),
                save: Some(SaveOptions {
                    include_text: Some(false),
                }),
                ..Default::default()
            },
        )),
        // completion_provider: Some(CompletionOptions {
        //     trigger_characters: Some(vec!["](".into()]),
        //     ..Default::default()
        // }),
        hover_provider: Some(true),
        // references_provider: Some(true),
        // definition_provider: Some(true),
        // folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
        // document_symbol_provider: Some(true),
        // workspace_symbol_provider: Some(true),
        // rename_provider: Some(RenameProviderCapability::Simple(true)),
        ..Default::default()
    }
}

pub struct Server {
    options: Options,
    connection: Connection,
    tasks: Tasks,
    documents: Documents,
    _root_uri: Url,
    open_document: Option<Url>,
}

impl Server {
    fn respond(&self, response: Response) -> Result<()> {
        debug!("sending response: {:?}", response);

        self.connection
            .sender
            .send(Message::Response(response))
            .map_err(|err| err.into())
    }

    fn notify<N>(&self, params: N::Params) -> Result<()>
    where
        N: notification::Notification,
        N::Params: Serialize,
    {
        self.connection
            .sender
            .send(Message::Notification(Notification::new(
                N::METHOD.into(),
                params,
            )))
            .map_err(|err| err.into())
    }

    fn add_task(&self, task: Task) -> Result<()> {
        debug!("adding task: {:?}", task);

        self.tasks.sender.send(task)?;
        Ok(())
    }

    async fn update_document(
        &mut self,
        uri: Url,
        text: Option<Vec<String>>,
        version: Option<i64>,
    ) -> Result<()> {
        if let Some(document) = self.documents.get_mut(&uri) {
            if version.is_some() && document.version > version {
                info!("not updating {} as more recent version is known", &uri);
                document.updating = false;
                return Ok(());
            }

            if text.is_some() && Some(&document.text) == text.as_ref() {
                info!("not updating {} as document contents are unchanged", &uri);
                document.updating = false;
                return Ok(());
            }
        }

        let path = Path::new(uri.path()).to_path_buf();

        let text = match text {
            Some(text) => text,
            None => read_to_string(&path)?.lines().map(|l| l.into()).collect(),
        };

        let (asts, diagnostics) = match spicy::parse(
            path.file_name()
                .ok_or_else(|| anyhow!("could not extract filename from path '{:?}", &path))?
                .to_string_lossy()
                .to_string(),
            &text.join("\n"),
            &self.options,
        )
        .await
        {
            Ok(asts) => asts,
            Err(_) => {
                // TODO(bbannier): send parsing errors as diagnostics.
                return Ok(());
            }
        };

        let diagnostics = diagnostics
            .iter()
            .filter_map(|d| {
                if !path.ends_with(&d.file) {
                    return None;
                }

                let start = Position::new(d.start.line - 1, d.start.character - 1);
                let end = Position::new(d.end.line - 1, d.end.character - 1);
                Some(Diagnostic::new_simple(
                    Range::new(start, end),
                    d.message.clone(),
                ))
            })
            .collect();

        self.documents.insert(
            uri.clone(),
            Document {
                uri: uri.clone(),
                version,
                text,
                asts,
                updating: false,
                diagnostics,
            },
        );

        self.add_task(Task::PublishDiagnostics())?;

        info!("updated {} to version {:?}", &uri, version);

        Ok(())
    }

    fn publish_diagnostics(&self) -> Result<()> {
        // FIXME(bbannier): display Decl.errors.
        if let Some(open_document) = &self.open_document {
            self.documents.get(&open_document).map(|document| {
                self.notify::<notification::PublishDiagnostics>(PublishDiagnosticsParams::new(
                    open_document.clone(),
                    document.diagnostics.clone(),
                    document.version,
                ))
            });
        }

        Ok(())
    }

    fn handle_did_open_text_document(&mut self, params: DidOpenTextDocumentParams) -> Result<()> {
        let uri = params.text_document.uri;
        let text = params
            .text_document
            .text
            .lines()
            .map(|l| l.into())
            .collect();
        let version = params.text_document.version;

        if let Some(document) = self.documents.get_mut(&uri) {
            document.updating = true;
        }

        self.open_document = Some(uri.clone());

        self.add_task(Task::UpdateDocument(uri, Some(text), Some(version)))
    }

    fn handle_did_save_test_document(&mut self, params: DidSaveTextDocumentParams) -> Result<()> {
        let uri = params.text_document.uri;

        if let Some(document) = self.documents.get_mut(&uri) {
            document.updating = true;
        }

        self.open_document = Some(uri.clone());

        self.add_task(Task::UpdateDocument(uri, None, None))
    }

    fn handle_did_change_text_document(
        &mut self,
        params: DidChangeTextDocumentParams,
    ) -> Result<()> {
        if params.content_changes.len() > 1 {
            std::unimplemented!("cannot handle incremental changes");
        }

        for change in params.content_changes {
            self.add_task(Task::UpdateDocument(
                params.text_document.uri.clone(),
                Some(change.text.lines().map(|l| l.into()).collect()),
                params.text_document.version,
            ))?;
        }

        Ok(())
    }

    fn handle_status(&self, id: lsp_server::RequestId) -> Response {
        // This function does not accept parameters since `StatusRequest` is empty.
        assert_eq_size!(StatusRequest, ());

        Response::new_ok(
            id,
            StatusResponse {
                is_idle: self.tasks.receiver.is_empty(),
            },
        )
    }

    fn handle_hover(&self, id: RequestId, params: HoverParams) -> Response {
        let result = self
            .documents
            .get(&params.text_document_position_params.text_document.uri)
            .and_then(|d| d.hover(&params.text_document_position_params));

        Response::new_ok(id, result)
    }
}

pub struct Tasks {
    sender: Sender<Task>,
    receiver: Receiver<Task>,
}

impl Tasks {
    pub fn new() -> Tasks {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Tasks { sender, receiver }
    }
}

#[derive(Debug)]
enum Task {
    UpdateDocument(Url, Option<Vec<String>>, Option<i64>),
    PublishDiagnostics(),
}

#[derive(Debug)]
enum Event {
    Api(lsp_server::Message),
    Task(Task),
}

type Documents = HashMap<Url, Document>;

#[derive(Debug)]
pub struct Document {
    uri: Url,
    version: Option<i64>,
    pub text: Vec<String>,
    asts: spicy::types::ASTs,
    updating: bool,
    diagnostics: Vec<Diagnostic>,
}

pub trait Query {
    fn hover(&self, params: &TextDocumentPositionParams) -> Option<Hover>;
}

impl Query for Document {
    fn hover(&self, params: &TextDocumentPositionParams) -> Option<Hover> {
        ast::Node::new(&self.text, &self.asts).hover(params)
    }
}

fn on_request(req: Request, server: &mut Server) -> Result<()> {
    match handle_request(req, server) {
        None => Ok(()),
        Some(response) => server.respond(response),
    }
}

fn handle_request(req: Request, server: &mut Server) -> Option<Response> {
    let _req = match request_cast::<request::HoverRequest>(req) {
        Ok((id, params)) => {
            return Some(server.handle_hover(id, params));
        }
        Err(req) => req,
    };
    let _req = match request_cast::<StatusRequest>(_req) {
        Ok((id, _)) => {
            return Some(server.handle_status(id));
        }
        Err(req) => req,
    };

    std::unimplemented!(); // TODO(bbannier): make this `None` once we have some ground covered.
}

fn on_notification(not: Notification, server: &mut Server) -> Result<()> {
    let _not = match notification_cast::<notification::DidOpenTextDocument>(not) {
        Ok(params) => {
            return server.handle_did_open_text_document(params);
        }
        Err(not) => not,
    };
    let _not = match notification_cast::<notification::DidSaveTextDocument>(_not) {
        Ok(params) => {
            return server.handle_did_save_test_document(params);
        }
        Err(not) => not,
    };
    let _not = match notification_cast::<notification::DidChangeTextDocument>(_not) {
        Ok(params) => {
            return server.handle_did_change_text_document(params);
        }
        Err(not) => not,
    };

    debug!("Unhandled notification: {:?}", _not);
    Ok(())
}

fn request_cast<R>(
    req: lsp_server::Request,
) -> std::result::Result<(RequestId, R::Params), lsp_server::Request>
where
    R: request::Request,
    R::Params: serde::de::DeserializeOwned,
{
    req.extract(R::METHOD)
}

fn notification_cast<N>(
    not: lsp_server::Notification,
) -> std::result::Result<N::Params, lsp_server::Notification>
where
    N: notification::Notification,
    N::Params: serde::de::DeserializeOwned,
{
    not.extract(N::METHOD)
}

struct StatusRequest;

#[derive(Debug, Deserialize, Serialize)]
struct StatusResponse {
    is_idle: bool,
}

impl request::Request for StatusRequest {
    type Params = ();
    type Result = StatusResponse;
    const METHOD: &'static str = "common-mark-language-server/status";
}
#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{cell::Cell, thread::sleep, time},
        textwrap::dedent,
        tokio::task,
    };

    struct TestServer {
        _handle: task::JoinHandle<Result<()>>,
        client: Connection,
        req_id: Cell<u64>,
        notifications: (Sender<Notification>, Receiver<Notification>),
    }

    impl TestServer {
        #[allow(deprecated)]
        fn start() -> Result<TestServer> {
            // Set up logging. This might fail if another test thread already set up logging.
            let _ = flexi_logger::Logger::with_env().start();

            let (connection, client) = Connection::memory();
            let _handle = task::spawn(run_server(connection, Options::default()));

            let req_id = Cell::new(0);

            let notifications = crossbeam_channel::unbounded();

            let server = TestServer {
                _handle,
                client,
                req_id,
                notifications,
            };

            server.send_request::<request::Initialize>(InitializeParams {
                capabilities: ClientCapabilities::default(),
                initialization_options: None,
                process_id: None,
                root_uri: None,
                root_path: None,
                trace: None,
                workspace_folders: None,
                client_info: None,
            })?;

            server.send_notification::<notification::Initialized>(InitializedParams {})?;

            Ok(server)
        }

        fn send_request<R>(&self, params: R::Params) -> Result<R::Result>
        where
            R: request::Request,
            R::Params: Serialize,
            for<'de> <R as request::Request>::Result: Deserialize<'de>,
        {
            let id = self.req_id.get();
            self.req_id.set(id + 1);

            self.client
                .sender
                .send(lsp_server::Message::from(lsp_server::Request::new(
                    id.into(),
                    R::METHOD.into(),
                    params,
                )))?;

            loop {
                let response = match self.client.receiver.recv() {
                    Ok(response) => response,
                    Err(err) => return Err(err.into()),
                };

                let response = match response {
                    lsp_server::Message::Response(response) => response,
                    lsp_server::Message::Notification(not) => {
                        self.notifications.0.send(not)?;
                        continue;
                    }
                    otherwise => {
                        info!("Dropping message '{:?}'", otherwise);
                        continue;
                    }
                }
                .result
                .ok_or_else(|| anyhow!("could not get response value"))?;

                return Ok(serde_json::from_value(response)?);
            }
        }

        fn send_notification<N>(&self, params: N::Params) -> Result<()>
        where
            N: notification::Notification,
            N::Params: Serialize,
        {
            let not = lsp_server::Notification::new(N::METHOD.into(), params);
            self.client
                .sender
                .send(lsp_server::Message::Notification(not))?;

            // Loop until the server has processed the notification.
            loop {
                debug!("Getting server status");

                match self.send_request::<StatusRequest>(()) {
                    Ok(status) => {
                        debug!("Server status is {:?}", status);
                        if status.is_idle {
                            break;
                        }
                    }
                    // We might receive an `RecvError` if no message is available, yet, in which
                    // case we continue. For other errors like e.g., `SendError` we should break;
                    Err(err) => {
                        if !err.is::<RecvError>() {
                            break;
                        }
                    }
                };

                sleep(time::Duration::from_millis(10));
            }

            Ok(())
        }

        fn notification<N>(&self) -> Result<N::Params>
        where
            N: notification::Notification,
            N::Params: serde::de::DeserializeOwned,
        {
            let not: Notification = self.notifications.1.recv().map_err(|err| err)?;
            serde_json::from_value(not.params).map_err(|err| err.into())
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            assert!(
                self.notifications.1.is_empty(),
                "terminating server with unprocessed notification(s): {:?}",
                &self.notifications.1.try_iter().collect::<Vec<_>>(),
            );

            self.send_request::<request::Shutdown>(()).unwrap();
            self.send_notification::<notification::Exit>(()).unwrap();
        }
    }

    #[tokio::test(threaded_scheduler)]
    async fn change() -> Result<()> {
        let server = TestServer::start()?;

        let uri = Url::from_file_path("/foo.spicy").map_err(|_| anyhow!("could not create uri"))?;

        server.send_notification::<notification::DidOpenTextDocument>(
            DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "spicy".into(),
                    1,
                    "module Foo;".into(),
                ),
            },
        )?;

        assert_eq!(
            server.notification::<notification::PublishDiagnostics>()?,
            PublishDiagnosticsParams::new(uri.clone(), vec![], Some(1))
        );

        server.send_notification::<notification::DidChangeTextDocument>(
            DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(uri.clone(), 2),
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: "module Foo; print a;".into(),
                }],
            },
        )?;

        assert_eq!(
            server.notification::<notification::PublishDiagnostics>()?,
            PublishDiagnosticsParams::new(
                uri.clone(),
                vec![Diagnostic::new_simple(
                    Range::new(Position::new(0, 18), Position::new(0, 18)),
                    "unknown ID \'a\'".into()
                )],
                Some(2)
            )
        );

        // Fixing the document leads to the diagnostic to go away.
        server.send_notification::<notification::DidOpenTextDocument>(
            DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "spicy".into(),
                    3,
                    "module Foo;".into(),
                ),
            },
        )?;

        assert_eq!(
            server.notification::<notification::PublishDiagnostics>()?,
            PublishDiagnosticsParams::new(uri.clone(), vec![], Some(3))
        );

        Ok(())
    }

    #[tokio::test(threaded_scheduler)]
    async fn hover() -> Result<()> {
        let server = TestServer::start()?;

        let path = spicy::test::spicy_test_file("spicy/doc/hello.spicy")
            .ok_or_else(|| anyhow!("test file not found"))?;
        let uri = Url::from_file_path(&path)
            .map_err(|_| anyhow!("could not convert '{:?}' to URI", &path))?;

        let text = read_to_string(&path)?;

        // Prime the server with a minimal module.
        server.send_notification::<notification::DidOpenTextDocument>(
            DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(uri.clone(), "spicy".into(), 1, text),
            },
        )?;

        assert!(server
            .notification::<notification::PublishDiagnostics>()?
            .diagnostics
            .is_empty());

        // Hover on comment line.
        assert_eq!(
            server.send_request::<request::HoverRequest>(HoverParams {
                text_document_position_params: TextDocumentPositionParams::new(
                    TextDocumentIdentifier { uri: uri.clone() },
                    Position::new(1, 2),
                ),
                work_done_progress_params: WorkDoneProgressParams {
                    work_done_token: None
                }
            })?,
            None
        );

        // Hover on module decl.
        assert_eq!(
            server.send_request::<request::HoverRequest>(HoverParams {
                text_document_position_params: TextDocumentPositionParams::new(
                    TextDocumentIdentifier { uri: uri.clone() },
                    Position::new(3, 10),
                ),
                work_done_progress_params: WorkDoneProgressParams {
                    work_done_token: None
                }
            })?,
            None
        );

        // Hover on print.
        assert_eq!(
            server.send_request::<request::HoverRequest>(HoverParams {
                text_document_position_params: TextDocumentPositionParams::new(
                    TextDocumentIdentifier { uri: uri.clone() },
                    Position::new(5, 2),
                ),
                work_done_progress_params: WorkDoneProgressParams {
                    work_done_token: None
                }
            })?,
            Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: ":: spicy::statement::Print".into()
                }),
                range: Some(Range::new(Position::new(5, 1), Position::new(5, 5))),
            })
        );

        drop(server);
        Ok(())
    }

    #[tokio::test(threaded_scheduler)]
    async fn diagnostics() -> Result<()> {
        let server = TestServer::start()?;

        {
            let uri =
                Url::from_file_path("/foo.spicy").map_err(|_| anyhow!("could not create uri"))?;

            let text = dedent(
                r#"
                    module Foo;
                    print a;
                    "#,
            );

            server.send_notification::<notification::DidOpenTextDocument>(
                DidOpenTextDocumentParams {
                    text_document: TextDocumentItem::new(uri.clone(), "spicy".into(), 1, text),
                },
            )?;

            assert_eq!(
                server.notification::<notification::PublishDiagnostics>()?,
                PublishDiagnosticsParams::new(
                    uri,
                    vec![Diagnostic::new_simple(
                        Range::new(Position::new(2, 6), Position::new(2, 6)),
                        "unknown ID \'a\'".into(),
                    )],
                    Some(1),
                ),
            );
        }

        {
            let uri = Url::from_file_path(Path::new("/foo.spicy"))
                .map_err(|_| anyhow!("could not create uri"))?;

            let text = dedent(
                r#"
                    module Test;

                    type Type = unit {
                        : Enum;  # Type expected here.
                    };

                    type Enum = enum {
                        FOO
                    };
                    "#,
            );

            server.send_notification::<notification::DidOpenTextDocument>(
                DidOpenTextDocumentParams {
                    text_document: TextDocumentItem::new(uri.clone(), "spicy".into(), 1, text),
                },
            )?;

            assert_eq!(
                server.notification::<notification::PublishDiagnostics>()?,
                PublishDiagnosticsParams::new(
                    uri,
                    vec![Diagnostic::new_simple(
                        Range::new(Position::new(3, 18), Position::new(4, 11)),
                        "not a parseable type (Test::Enum)".into(),
                    )],
                    Some(1),
                ),
            );
        }

        Ok(())
    }
}
