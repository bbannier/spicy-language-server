use {
    super::Rule,
    anyhow::{anyhow, Result},
    std::{collections::HashMap, convert::TryFrom},
};

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
            ..Location::default()
        };
        for rule in location {
            match rule.as_rule() {
                Rule::file => result.file = rule.as_str().to_owned(),
                Rule::line_number_start => result.start.line = rule.as_str().parse()?,
                Rule::column_number_start => result.start.character = rule.as_str().parse()?,
                Rule::line_number_end => {
                    result.end = Some(Position {
                        line: rule.as_str().parse()?,
                        ..Position::default()
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
            identifier: identifier.ok_or_else(|| anyhow!("every scope must have an identifier"))?,
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
