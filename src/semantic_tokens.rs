use std::sync::LazyLock;

use itertools::Itertools;
use tower_lsp_server::lsp_types::{
    Position, Range, SemanticToken, SemanticTokenType, SemanticTokens, SemanticTokensLegend,
};
use tree_sitter_highlight::{Highlight, HighlightConfiguration, HighlightEvent};

pub(crate) fn legend() -> SemanticTokensLegend {
    let token_types = highlights()
        .iter()
        .map(|hl| SemanticTokenType::from(*hl))
        .collect();

    SemanticTokensLegend {
        token_types,
        ..SemanticTokensLegend::default()
    }
}

const SPICY: &str = "spicy";
const REGEX: &str = "regex";

static SPICY_CONFIG: LazyLock<HighlightConfiguration> =
    LazyLock::new(|| config(SPICY).expect("invalid config for 'spicy'"));

static REGEX_CONFIG: LazyLock<HighlightConfiguration> =
    LazyLock::new(|| config(REGEX).expect("invalid config for 'regex'"));

fn highlights() -> &'static [&'static str] {
    static ALL: LazyLock<Vec<&str>> = LazyLock::new(|| {
        (SPICY_CONFIG.query.capture_names().iter())
            .chain(REGEX_CONFIG.query.capture_names())
            .copied()
            // tree-sitter-highlight leaks injection queries, remove it.
            .filter(|hl| *hl != "injection.content")
            // LSP does not standardize names with subscopes, preserve only the top-level scope.
            .map(|hl| hl.split_once('.').map_or(hl, |(hl, _)| hl))
            .unique()
            .collect::<Vec<_>>()
    });

    &ALL
}

fn config(lang: &str) -> Option<HighlightConfiguration> {
    match lang {
        SPICY => {
            let language = tree_sitter::Language::new(tree_sitter_spicy::LANGUAGE);
            tree_sitter_highlight::HighlightConfiguration::new(
                language,
                SPICY,
                tree_sitter_spicy::HIGHLIGHTS_QUERY,
                tree_sitter_spicy::INJECTIONS_QUERY,
                "",
            )
            .ok()
        }
        REGEX => {
            let language = tree_sitter::Language::new(tree_sitter_regex::LANGUAGE);
            tree_sitter_highlight::HighlightConfiguration::new(
                language,
                REGEX,
                tree_sitter_regex::HIGHLIGHTS_QUERY,
                "",
                "",
            )
            .ok()
        }
        _ => None,
    }
}

fn highlight_config(lang: &str) -> Option<HighlightConfiguration> {
    let mut config = config(lang)?;

    config.configure(highlights());
    Some(config)
}

pub(crate) fn highlight(source: &str, legend: &SemanticTokensLegend) -> Option<SemanticTokens> {
    let spicy_config = highlight_config(SPICY)?;

    let line_index = line_index::LineIndex::new(source);

    let mut data = Vec::new();

    let regex_config = highlight_config(REGEX)?;

    let mut highlighter = tree_sitter_highlight::Highlighter::new();
    let items = highlighter
        .highlight(&spicy_config, source.as_bytes(), None, |lang| match lang {
            REGEX => Some(&regex_config),
            _ => None,
        })
        .ok()?;

    let mut labels = Vec::new();

    for event in items {
        let Ok(event) = event else { return None };
        match event {
            HighlightEvent::HighlightStart(Highlight(idx)) => {
                labels.push(idx);
            }
            HighlightEvent::Source { start, end } => {
                if let Some(idx) = labels.last() {
                    data.push((*idx, (start, end)));
                }
            }
            HighlightEvent::HighlightEnd => {
                labels.pop();
            }
        }
    }

    let highlight_names = highlights();
    let data: Vec<_> = data
        .into_iter()
        .filter_map(|(ty, range)| {
            let name = highlight_names.get(ty)?;
            let ty = SemanticTokenType::from(*name);

            // Skip token types we didn't previously advertise.
            let token_type =
                u32::try_from(legend.token_types.iter().position(|x| *x == ty)?).ok()?;

            Some((token_type, range))
        })
        .sorted_by(|(_, (a, _)), (_, (b, _))| Ord::cmp(&a, &b))
        .filter_map(|(token_type, (start, end))| {
            let range = end - start;
            let start = line_index.line_col(start.try_into().ok()?);
            let end = line_index.line_col(end.try_into().ok()?);

            Some((
                token_type,
                (
                    Range::new(
                        Position::new(start.line, start.col),
                        Position::new(end.line, end.col),
                    ),
                    range,
                ),
            ))
        })
        .collect();

    let mut tokens = Vec::new();
    let mut prev = Range::default();
    for (token_type, (range, length)) in data {
        let token = {
            let delta_line = range.start.line - prev.start.line;
            let delta_start = if delta_line == 0 {
                range.start.character - prev.start.character
            } else {
                range.start.character
            };

            SemanticToken {
                delta_line,
                delta_start,
                length: length.try_into().ok()?,
                token_type,
                ..SemanticToken::default()
            }
        };

        tokens.push(token);

        prev = range;
    }

    Some(SemanticTokens {
        data: tokens,
        ..SemanticTokens::default()
    })
}

#[cfg(test)]
mod test {
    use crate::semantic_tokens::{highlight, legend};
    use insta::assert_debug_snapshot;
    use tower_lsp_server::lsp_types::SemanticToken;

    #[test]
    fn injection_regex() {
        let legend = legend();
        let result = highlight("local x = /abc/;", &legend).unwrap();
        let xs: Vec<_> = result
            .data
            .into_iter()
            .map(|SemanticToken { token_type, .. }| {
                &legend.token_types[usize::try_from(token_type).unwrap()]
            })
            .collect();
        assert_debug_snapshot!(xs);
    }
}
