use {
    crate::{options::Options, pest::Parser},
    anyhow::{anyhow, Context, Result},
    pest_derive::Parser,
    regex::Regex,
    std::{
        collections::HashMap,
        convert::TryFrom,
        error, fmt,
        process::{Command, Output},
        str::from_utf8,
    },
};

pub mod types {
    use super::*;

    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    pub struct AST {
        pub decls: Vec<Decl>,
    }

    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    pub struct Decl {
        pub type_: String,
        pub id: Option<String>,
        pub properties: Properties,
        pub location: Option<Location>,
        pub flags: Vec<String>,
        pub decls: Vec<Decl>,
        pub scope: Vec<Scope>,
        pub type2: Option<String>,
        pub original: Option<String>,
        pub errors: Vec<String>,
    }

    impl<'a> TryFrom<pest::iterators::Pairs<'a, Rule>> for Decl {
        type Error = anyhow::Error;

        fn try_from(decl: pest::iterators::Pairs<Rule>) -> Result<Self> {
            let mut type_ = None;
            let mut id = None;
            let mut properties = Properties::default();
            let mut location = None;
            let mut flags = vec![];
            let mut decls = vec![];
            let mut scope = vec![];
            let mut type2 = None;
            let mut original = None;
            let mut errors = vec![];

            for rule in decl {
                match rule.as_rule() {
                    Rule::type_ => type_ = Some(rule.as_str().to_owned()),
                    Rule::id => id = Some(rule.as_str().to_owned()),
                    Rule::properties => properties = Properties::try_from(rule.into_inner())?,
                    Rule::location => location = Some(Location::try_from(rule.into_inner())?),
                    Rule::flag => flags.push(rule.as_str().to_owned()),
                    Rule::decl => decls.push(Decl::try_from(rule.into_inner())?),
                    Rule::scope => scope.push(Scope::try_from(rule.into_inner())?),
                    Rule::type2 => type2 = Some(rule.into_inner().as_str().into()),
                    Rule::original => original = Some(rule.into_inner().as_str().into()),
                    Rule::error => errors.push(rule.into_inner().as_str().into()),
                    _ => std::unreachable!(format!(
                        "unexpected child node '{:?}'",
                        dbg!(rule).as_rule()
                    )),
                }
            }

            Ok(Decl {
                type_: type_.ok_or_else(|| anyhow!("every decl must have a type"))?,
                id,
                properties,
                location,
                flags,
                decls,
                scope,
                type2,
                original,
                errors,
            })
        }
    }

    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    pub struct Properties(pub HashMap<String, Option<String>>);

    impl Properties {
        fn try_from(properties: pest::iterators::Pairs<Rule>) -> Result<Self> {
            let mut xs = HashMap::new();

            for property in properties {
                let mut property = property.into_inner();

                let key = property
                    .next()
                    .ok_or_else(|| anyhow!("properties need to at least have a key"))?
                    .as_str()
                    .to_owned();
                let value = property.next().map(|v| v.as_str().to_owned());

                xs.insert(key, value);
            }

            Ok(Self(xs))
        }
    }

    #[derive(Debug, Default, PartialEq, Eq, Clone, PartialOrd)]
    pub struct Position {
        pub line: u64,
        pub character: u64,
    }

    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    pub struct Location {
        pub file: String,
        pub start: Position,
        pub end: Option<Position>,
    }

    impl Location {
        fn try_from(location: pest::iterators::Pairs<Rule>) -> Result<Self> {
            let mut result = Location {
                ..Default::default()
            };
            for rule in location {
                match rule.as_rule() {
                    Rule::file => result.file = rule.as_str().to_owned(),
                    Rule::line_number_start => result.start.line = rule.as_str().parse()?,
                    Rule::column_number_start => result.start.character = rule.as_str().parse()?,
                    Rule::line_number_end => {
                        result.end = Some(Position {
                            line: rule.as_str().parse()?,
                            ..Default::default()
                        })
                    }
                    Rule::column_number_end => {
                        if let Some(end) = result.end.as_mut() {
                            end.character = rule.as_str().parse()?
                        }
                    }
                    _ => std::unreachable!(format!(
                        "unexpected child node '{:?}'",
                        dbg!(rule).as_rule()
                    )),
                }
            }

            Ok(result)
        }
    }

    #[derive(Debug, Default, PartialEq, Eq, Clone)]
    pub struct Scope {
        pub identifier: String,
        pub type_: String,
        pub id: Option<String>,
        pub properties: Properties,
        pub type2: Option<String>,
        pub flags: Vec<String>,
        pub original: Option<String>,
        pub errors: Vec<String>,
    }

    impl<'a> TryFrom<pest::iterators::Pairs<'a, Rule>> for Scope {
        type Error = anyhow::Error;

        fn try_from(scope: pest::iterators::Pairs<Rule>) -> Result<Self> {
            let mut identifier = None;
            let mut type_ = None;
            let mut id = None;
            let mut properties = Properties::default();
            let mut type2 = None;
            let mut flags = vec![];
            let mut original = None;
            let mut errors = vec![];

            for rule in scope {
                match rule.as_rule() {
                    Rule::identifier => identifier = Some(rule.as_str().to_owned()),
                    Rule::properties => properties = Properties::try_from(rule.into_inner())?,
                    Rule::type_ => type_ = Some(rule.as_str().to_owned()),
                    Rule::id => id = Some(rule.as_str().to_owned()),
                    Rule::flag => flags.push(rule.as_str().to_owned()),
                    Rule::original => original = Some(rule.into_inner().as_str().into()),
                    Rule::error => errors.push(rule.into_inner().as_str().into()),
                    Rule::type2 => type2 = Some(rule.into_inner().as_str().into()),
                    _ => std::unreachable!(format!(
                        "unexpected child node '{:?}'",
                        dbg!(rule).as_rule()
                    )),
                }
            }

            Ok(Scope {
                identifier: identifier
                    .ok_or_else(|| anyhow!("every scope must have an identifier"))?,
                type_: type_.ok_or_else(|| anyhow!("every scope must have a type"))?,
                id,
                properties,
                type2,
                flags,
                original,
                errors,
            })
        }
    }

    pub type ASTs = HashMap<String, AST>;
}

#[derive(Parser, PartialEq)]
#[grammar = "ast.pest"]
struct ASTParser;

#[derive(Debug, PartialEq)]
struct Spicyc {
    ast_resolved: String,
    diagnostics: Vec<SpicycDiagnostics>,
}

#[derive(Debug, PartialEq)]
pub struct SpicycDiagnostics {
    pub file: String,
    pub start: types::Position,
    pub end: types::Position,
    pub message: String,
}

impl Spicyc {
    fn try_from(tmp_file: &str, real_file: &str, value: Output) -> Result<Self> {
        let stderr = from_utf8(&value.stderr)?.replace(&tmp_file, &real_file);

        let (ast_resolved, other): (Vec<_>, _) = stderr
            .lines()
            .partition(|&l| l.starts_with("[debug/ast-resolved] "));

        let ast_resolved = ast_resolved
            .iter()
            .map(|l| l[21..].to_owned())
            .collect::<Vec<_>>()
            .join("\n");

        let re_error = Regex::new(
            r"(?x)
            \[error\]
            \s(?P<file>(?:\w|/|-|\.)+).*
            :(?P<start_line>\d+)
            :(?P<start_char>\d+)
            (?:(-(?P<end_line>\d+):(?P<end_char>\d+))?)
            :\s(?P<msg>.*)$",
        )?;

        let diagnostics = other
            .iter()
            .filter_map(|&l| {
                let captures = re_error.captures(&l)?;
                let _file = captures.name("file")?.as_str();

                let start_line = captures.name("start_line")?.as_str().parse::<u64>().ok()?;
                let start_character = captures.name("start_char")?.as_str().parse::<u64>().ok()?;

                let end_line = if let Some(l) = captures.name("end_line") {
                    l.as_str().parse::<u64>().ok()?
                } else {
                    start_line
                };

                let end_character = if let Some(c) = captures.name("end_char") {
                    c.as_str().parse::<u64>().ok()?
                } else {
                    start_character
                };

                let message = captures.name("msg")?.as_str().into();
                Some(SpicycDiagnostics {
                    file: real_file.to_string(),
                    start: types::Position {
                        line: start_line,
                        character: start_character,
                    },
                    end: types::Position {
                        line: end_line,
                        character: end_character,
                    },
                    message,
                })
            })
            .collect();

        Ok(Spicyc {
            ast_resolved,
            diagnostics,
        })
    }
}

pub struct File {
    file_path: String,
    contents: String,
}

// TODO(bbannier): return Spicy errors here.
async fn spicyc(file: &File, options: &Options) -> Result<Spicyc> {
    let path = tempfile::Builder::new().suffix(".spicy").tempfile()?;
    std::fs::write(path.path(), file.contents.as_bytes())?;

    let output = Command::new(options.spicyc.as_deref().unwrap_or("spicyc"))
        .arg(&path.path())
        .args(&["-p", "-D", "ast-resolved"])
        .output()
        .with_context(|| "Could not execute 'spicyc'".to_owned())
        .expect("");

    Spicyc::try_from(
        &path
            .path()
            .file_name()
            .ok_or_else(|| anyhow!("could not extract expected filename from path {:?}", &path))?
            .to_string_lossy()
            .to_string(),
        &file.file_path,
        output,
    )
}

#[derive(Debug)]
struct IncompleteParseError(String);

impl error::Error for IncompleteParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl fmt::Display for IncompleteParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn parse_rule(input: &str, r: Rule) -> Result<pest::iterators::Pair<Rule>> {
    let result: pest::iterators::Pair<Rule> = ASTParser::parse(r, &input)?
        .next()
        .ok_or_else(|| anyhow!("parse yielded no results"))?;

    // Check if we successfully parsed the input.
    let unparsed = input
        .strip_prefix(result.as_str())
        .ok_or_else(|| IncompleteParseError(input.to_owned()))?;
    if !unparsed.is_empty() {
        return Err(IncompleteParseError(unparsed.to_owned()).into());
    }

    Ok(result)
}

fn parse_resolved_asts(input: &str) -> Result<types::ASTs> {
    let result = parse_rule(&input, Rule::resolved_ast)?;

    let mut asts = types::ASTs::new();

    for module in result.into_inner() {
        let mut ast = None;
        // let mut ast: Option<&mut types::AST> = None;

        for decl in module.into_inner() {
            match decl.as_rule() {
                Rule::resolved => {
                    let mut inner_rules = decl.into_inner();
                    let identifier = inner_rules.next().expect("expected node absent").as_str();
                    let _round = inner_rules.next().expect("expected node absent").as_str();

                    if let Some(xs) = asts.get_mut(identifier) {
                        *xs = types::AST::default()
                    } else {
                        asts.insert(identifier.into(), types::AST::default());
                    }
                    ast = Some(
                        asts.get_mut(identifier)
                            .ok_or_else(|| anyhow!("AST should be created"))?,
                    );
                }
                Rule::decl => {
                    ast.as_mut()
                        .ok_or_else(|| anyhow!("declarations can only appear in an AST"))?
                        .decls
                        .push(types::Decl::try_from(decl.into_inner())?);
                }
                _ => std::unreachable!(format!(
                    "unexpected child node '{:?}'",
                    dbg!(decl).as_rule()
                )),
            };
        }
    }

    Ok(asts)
}

pub async fn parse(
    file_path: String,
    contents: &str,
    options: &Options,
) -> Result<(types::ASTs, Vec<SpicycDiagnostics>)> {
    let result = spicyc(
        &File {
            file_path,
            contents: contents.to_string(),
        },
        options,
    )
    .await?;

    Ok((
        parse_resolved_asts(&result.ast_resolved)?,
        result.diagnostics,
    ))
}

#[cfg(test)]
pub mod test {
    use {
        super::*,
        futures::future::join_all,
        std::{
            fs::{read_to_string, File},
            io::{self, BufRead},
            path::{Path, PathBuf},
            result,
        },
        textwrap::dedent,
        walkdir::WalkDir,
    };

    pub fn spicy_test_file(file: &str) -> Option<PathBuf> {
        for test in spicy_test_files() {
            if test.ends_with(file) {
                return Some(test);
            }
        }

        None
    }

    fn spicy_test_files() -> Vec<PathBuf> {
        let spicy_test_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        assert!(
            spicy_test_root.exists(),
            "expected Spicy 'tests/' directory linked into the project root"
        );

        WalkDir::new(spicy_test_root)
            .into_iter()
            .filter_map(result::Result::ok)
            .filter(|e| {
                !e.file_type().is_dir()
                    && e.path().extension().and_then(|ext| ext.to_str()) == Some("spicy")
            })
            .map(|e| e.path().to_path_buf())
            .filter_map(|e| {
                if let Some(path) = e.to_str() {
                    // Filter out BTest temp files.
                    if path.contains("/.tmp/") {
                        return None;
                    }

                    // Filter out input expected to create failures.
                    if path.ends_with("-fail.spicy") {
                        return None;
                    }

                    // Filter out know failures.
                    if path.ends_with("spicy/types/id/validation.spicy")
                        || path.ends_with("tests/zeek/lib/protocols/http.spicy")
                        || path.ends_with("tests/zeek/lib/protocols/dns.spicy")
                        || path.ends_with("tests/spicy/lib/protocols/http/reply-chunked.spicy")
                        || path.ends_with("tests/spicy/lib/protocols/http/requests.spicy")
                        || path.ends_with("tests/spicy/lib/protocols/http/reply-eod.spicy")
                        || path.ends_with("tests/spicy/lib/protocols/http/reply-multipart.spicy")
                        || path
                            .ends_with("tests/spicy/lib/protocols/http/reply-chunked-trailer.spicy")
                        || path
                            .ends_with("tests/spicy/lib/protocols/http/reply-content-length.spicy")
                    {
                        return None;
                    }
                }

                let file = File::open(&e).ok()?;
                let cannot_parse_standalone = io::BufReader::new(&file).lines().any(|l| {
                    if let Ok(l) = l {
                        // Filter out inputs containing raw BTest instructions.
                        l.starts_with('@') ||
                            // Filter out inputs containing multiple files (which might depend on
                            // one another).
                            l.contains("TEST-START-FILE") || l.contains("TEST-START-NEXT")
                    } else {
                        false
                    }
                });
                if cannot_parse_standalone {
                    return None;
                }

                Some(e)
            })
            .collect::<Vec<_>>()
    }

    #[tokio::test]
    async fn test_spicyc() -> Result<()> {
        let file = "foo-fail.spicy";
        let contents = dedent(
            r#"
            module Foo;

            print a;
        "#,
        )
        .into();

        let result = spicyc(
            &super::File {
                file_path: file.into(),
                contents,
            },
            &Options::default(),
        )
        .await?;

        assert!(
            result
                .ast_resolved
                .lines()
                .any(|l| l.contains("| Foo -> declaration::Module")),
            "unexpected ast: {:?}",
            &result.ast_resolved[0..3]
        );

        assert_eq!(
            result.diagnostics,
            vec![SpicycDiagnostics {
                file: "foo-fail.spicy".into(),
                start: types::Position {
                    line: 4,
                    character: 7
                },
                end: types::Position {
                    line: 4,
                    character: 7
                },
                message: "unknown ID \'a\'".into()
            }],
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_parse_all() -> Result<()> {
        let ast_resolved = spicyc(
            &super::File {
                file_path: "foo.spicy".into(),
                contents: "module Foo;".into(),
            },
            &Options::default(),
        )
        .await?
        .ast_resolved;

        let result = parse_rule(&ast_resolved, Rule::resolved_ast);
        assert!(result.is_ok(), format!("{:#?}", result));

        Ok(())
    }

    #[test]
    fn parse_module_round1() {
        let input = concat!(
            "# Foo: AST after resolving (round 1)\n",
            "  - Module %1 (foo.spicy:1:1)\n",
            "      | Foo -> Module %1\n",
            "    - ID <name=Foo> (foo.spicy:1:1)\n",
            "    - statement::Block (foo.spicy:1:1)\n",
        );

        if let Err(err) = parse_rule(&input, Rule::resolved_ast) {
            assert!(false, format!("{:?}", err));
        }

        let asts = parse_resolved_asts(&input);

        let expected = {
            let mut m = types::ASTs::new();

            let decl = types::Decl {
                type_: "Module".into(),
                id: Some("1".into()),
                location: Some(types::Location {
                    file: "foo.spicy".into(),
                    start: types::Position {
                        line: 1,
                        character: 1,
                    },
                    ..Default::default()
                }),
                scope: vec![types::Scope {
                    identifier: "Foo".into(),
                    type_: "Module".into(),
                    id: Some("1".into()),
                    ..Default::default()
                }],
                decls: vec![
                    types::Decl {
                        type_: "ID".into(),
                        properties: {
                            let mut m = HashMap::new();
                            m.insert("name".into(), Some("Foo".into()));
                            types::Properties(m)
                        },
                        location: Some(types::Location {
                            file: "foo.spicy".into(),
                            start: types::Position {
                                line: 1,
                                character: 1,
                            },
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    types::Decl {
                        type_: "statement::Block".into(),
                        location: Some(types::Location {
                            file: "foo.spicy".into(),
                            start: types::Position {
                                line: 1,
                                character: 1,
                            },
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            };
            m.insert("Foo".into(), types::AST { decls: vec![decl] });

            m
        };

        assert_eq!(asts.ok(), Some(expected));
    }

    #[test]
    fn parse_properties() {
        let input = "<extension=.hlt path= scope=->";
        let properties = ASTParser::parse(Rule::properties, &input)
            .unwrap()
            .next()
            .unwrap();

        let mut prop_map = HashMap::new();
        for prop in properties.into_inner() {
            let kv = prop.into_inner().map(|x| x.as_str()).collect::<Vec<_>>();
            prop_map.insert(kv[0], if kv.len() == 2 { Some(kv[1]) } else { None });
        }

        let expected = {
            let mut m = HashMap::new();
            m.insert("extension", Some(".hlt"));
            m.insert("path", None);
            m.insert("scope", Some("-"));
            m
        };

        assert_eq!(prop_map, expected);
    }

    #[test]
    fn parse_location() {
        let input = "(hilti.hlt:2:1)";
        assert_eq!(
            &ASTParser::parse(Rule::location, &input)
                .unwrap()
                .next()
                .unwrap()
                .as_str(),
            &input
        );

        let input = "(hilti.hlt:2:1-32:1)";
        assert_eq!(
            &ASTParser::parse(Rule::location, &input)
                .unwrap()
                .next()
                .unwrap()
                .as_str(),
            &input
        );
    }

    #[tokio::test]
    #[ignore]
    async fn spicy_tests() -> Result<()> {
        let mut tasks = vec![];
        for file in spicy_test_files() {
            let path = spicy_test_file(file.to_str().unwrap()).unwrap();
            let result = async move {
                parse(
                    path.file_name()
                        .ok_or(anyhow!("could not extract filename from path {:?}", &path))?
                        .to_string_lossy()
                        .to_string(),
                    &read_to_string(&path)?,
                    &Options::default(),
                )
                .await
                .and_then(|_| {
                    println!("Processed {:?}", &path);
                    Ok(())
                })
                .or_else(|e| Err(anyhow!("Error parsing '{:?}': {}", &path, &e)))
            };
            tasks.push(result);
        }

        join_all(tasks)
            .await
            .into_iter()
            .collect::<Result<Vec<()>>>()
            .and_then(|_| Ok(()))
    }
}
