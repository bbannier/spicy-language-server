use itertools::Itertools;
use tower_lsp_server::lsp_types::{
    Position, Range, SemanticToken, SemanticTokenType, SemanticTokens, SemanticTokensLegend,
};
use tree_sitter_highlight::{Highlight, HighlightEvent};

pub(crate) fn legend() -> SemanticTokensLegend {
    let token_types = highlights().map(SemanticTokenType::from).collect();

    SemanticTokensLegend {
        token_types,
        ..SemanticTokensLegend::default()
    }
}

fn highlights() -> impl Iterator<Item = &'static str> {
    tree_sitter_spicy::HIGHLIGHTS_QUERY
        .lines()
        .flat_map(|line| line.split_whitespace())
        .filter_map(|xs| {
            let xs = xs.strip_prefix('@')?;
            Some(xs.strip_suffix(')').unwrap_or(xs))
        })
        .unique()
}

pub(crate) fn highlight(source: &str, legend: &SemanticTokensLegend) -> Option<SemanticTokens> {
    let Ok(mut config) = tree_sitter_highlight::HighlightConfiguration::new(
        tree_sitter::Language::new(tree_sitter_spicy::LANGUAGE),
        "spicy",
        tree_sitter_spicy::HIGHLIGHTS_QUERY,
        "",
        "",
    ) else {
        return None;
    };
    config.configure(&highlights().collect::<Vec<_>>());

    let line_index = line_index::LineIndex::new(source);

    let mut data = Vec::new();

    let mut cur = None;

    let mut highlighter = tree_sitter_highlight::Highlighter::new();
    let items = highlighter
        .highlight(&config, source.as_bytes(), None, |_| None)
        .ok()?;

    for event in items {
        let Ok(event) = event else { return None };
        match event {
            HighlightEvent::HighlightStart(Highlight(idx)) => {
                cur = Some((idx, None));
            }
            HighlightEvent::Source { start, end } => {
                if let Some((_, range)) = &mut cur {
                    *range = Some((start, end));
                }
            }
            HighlightEvent::HighlightEnd => {
                if let Some((idx, Some(cur_range))) = cur {
                    data.push((idx, cur_range));
                }
                cur = None;
            }
        }
    }

    let highlight_names: Vec<_> = highlights().collect();
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
