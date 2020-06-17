use {
    crate::{lsp::server, spicy},
    lsp_types::{Position, Range, TextDocumentPositionParams},
    std::convert::TryFrom,
};

#[derive(Debug)]
pub struct Node<'a> {
    text: &'a [String],
    asts: &'a spicy::types::ASTs,
}

impl<'a> server::Query for Node<'a> {
    fn hover(&self, params: &TextDocumentPositionParams) -> Option<lsp_types::Hover> {
        use lsp_types::{Hover, HoverContents, MarkupContent, MarkupKind};

        let (_token, range) = self.get_token_at_pos(&params.position)?;

        // TODO(bbannier): Figure out information on the identifier.

        let decl = self.get_decl(params)?;

        let value = {
            let mut x = String::new();
            x += &format!(":: {}", decl.type_);
            if !decl.properties.0.is_empty() {
                x += "\n\nProperties:";
                for (k, v) in &decl.properties.0 {
                    x += &format!("\n  - {}: {}", &k, v.as_deref().unwrap_or(""));
                }
            }
            x
        };

        Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value,
            }),
            range: Some(range),
        })
    }
}

impl<'a> Node<'a> {
    pub fn new(text: &'a [String], asts: &'a spicy::types::ASTs) -> Node<'a> {
        Node { text, asts }
    }

    fn get_token_at_pos(&self, position: &Position) -> Option<(&str, Range)> {
        let (token, range) = self
            .text
            .get(usize::try_from(position.line).ok()?)?
            .split_terminator(|c: char| c.is_whitespace() || c == '.' || c == '=' || c == ';')
            .scan(0, |length, word| {
                *length += word.len() + 1;
                Some((*length, word))
            })
            .skip_while(|(end, _)| {
                (*end - 1)
                    < (usize::try_from(position.character)
                        .expect("character position not convertible to 'usize'"))
            })
            .map(|(end, word)| (word, (end - word.len(), end - 1)))
            .next()?;

        Some((
            token,
            Range::new(
                Position::new(position.line, range.0 as u64),
                Position::new(position.line, range.1 as u64),
            ),
        ))
    }

    fn get_decl(&self, params: &TextDocumentPositionParams) -> Option<&spicy::types::Decl> {
        use itertools::Itertools;

        get_decls_from_asts(self.asts, 0)
            .iter()
            // Filter out decl in the requested file.
            .filter(|(_, d)| {
                if let Some(location) = &d.location {
                    if params
                        .text_document
                        .uri
                        .path()
                        .ends_with(location.file.as_str())
                    {
                        return true;
                    }
                }
                false
            })
            // Filter out uninteresting nodes.
            .filter(
                |(_, decl)|
            // TODO(bbannier): render ID externally.
            decl.type_ != "ID", // TODO(bbannier): actually render this one with information on the resolved ID.
            ) // && decl.type_ != "type::ResolvedID")
            // Filter out decls matching the requested position.
            .filter_map(|(depth, decl)| {
                // Spicy location indixes are 1-based, LSP ones 0-based.
                let position = spicy::types::Position {
                    line: params.position.line + 1,
                    character: params.position.character + 1,
                };

                // TODO(bbannier): match multi-line decls which start on other lines.
                if let Some(location) = &decl.location {
                    // Only match decls on the same line.
                    if position.line != location.start.line {
                        return None;
                    }

                    // Possibly calculate a midpoint for declarations spanning a range.
                    // For decls with end point require decls span a single line, only.
                    let mid = if let Some(end) = &location.end {
                        if end.line != location.start.line {
                            return None;
                        }
                        end.character - location.start.character
                    } else {
                        // Ranges without end have their midpoint at their location.
                        location.start.character
                    };

                    // Return a tuple of (distance, decl) for later distance minimization.
                    return Some((
                        i64::abs(
                            i64::try_from(position.character).ok()? - i64::try_from(mid).ok()?,
                        )
                        .abs(),
                        depth,
                        decl,
                    ));
                }
                None
            })
            // Select the closest decl. We use the node depth as tie breaker, preferring deeper nodes.
            .group_by(|(distance, _, _)| *distance)
            .into_iter()
            .flat_map(|(_, g)| g.min_by(|(_, depth1, _), (_, depth2, _)| depth2.cmp(depth1)))
            .min_by(|(distance1, _, _), (distance2, _, _)| distance1.cmp(distance2))
            .map(|(_, _, &d)| d)
    }
}

fn get_decls_from_decl(decl: &spicy::types::Decl, depth: u64) -> Vec<(u64, &spicy::types::Decl)> {
    std::iter::once((depth, decl))
        .chain(
            decl.decls
                .iter()
                .flat_map(|d| get_decls_from_decl(d, depth + 1)),
        )
        .collect()
}

fn get_decls_from_ast(ast: &spicy::types::AST, depth: u64) -> Vec<(u64, &spicy::types::Decl)> {
    ast.decls
        .iter()
        .flat_map(|d| get_decls_from_decl(d, depth))
        .collect()
}

fn get_decls_from_asts(asts: &spicy::types::ASTs, depth: u64) -> Vec<(u64, &spicy::types::Decl)> {
    asts.values()
        .flat_map(|ast| get_decls_from_ast(ast, depth))
        .collect()
}
