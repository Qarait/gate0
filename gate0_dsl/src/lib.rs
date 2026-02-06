use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    token::{Brace, Paren},
    Expr, Ident, LitBool, LitInt, LitStr, Result, Token,
};

#[proc_macro]
pub fn policy_builder(input: TokenStream) -> TokenStream {
    let policy_def = parse_macro_input!(input as PolicyDefinition);
    let expanded = policy_def.expand();
    TokenStream::from(expanded)
}

struct PolicyDefinition {
    config: Option<ConfigBlock>,
    use_builder: Option<Expr>,
    rules: Vec<RuleDefinition>,
}

impl Parse for PolicyDefinition {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut config = None;
        let mut use_builder = None;
        let mut rules = Vec::new();

        if input.peek(Ident) {
            let lookahead = input.fork();
            if let Ok(ident) = lookahead.parse::<Ident>() {
                if ident == "USE" {
                    let _: Ident = input.parse()?;
                    let builder_expr: Expr = input.parse()?;
                    input.parse::<Token![;]>()?;
                    use_builder = Some(builder_expr);
                }
            }
        }

        if input.peek(Ident) {
            let lookahead = input.fork();
            if let Ok(ident) = lookahead.parse::<Ident>() {
                if ident == "CONFIG" {
                    let _: Ident = input.parse()?;
                    config = Some(input.parse()?);
                }
            }
        }

        while !input.is_empty() {
            rules.push(input.parse()?);
        }

        Ok(PolicyDefinition {
            config,
            use_builder,
            rules,
        })
    }
}

impl PolicyDefinition {
    fn expand(&self) -> TokenStream2 {
        let builder_init = if let Some(ref builder_expr) = self.use_builder {
            quote! { let mut builder = #builder_expr; }
        } else {
            quote! { let mut builder = ::gate0::Policy::builder(); }
        };

        let config_setup = if let Some(ref cfg) = self.config {
            let config_fields = &cfg.fields;
            quote! {
                builder = builder.config(::gate0::PolicyConfig {
                    #(#config_fields)*
                    ..::gate0::PolicyConfig::default()
                });
            }
        } else {
            quote! {}
        };

        let rule_additions = self.rules.iter().map(|rule| {
            let rule_expr = rule.expand();
            quote! {
                builder = builder.rule(#rule_expr);
            }
        });

        quote! {
            {
                #builder_init
                #config_setup
                #(#rule_additions)*
                builder
            }
        }
    }
}

struct ConfigBlock {
    fields: Vec<ConfigField>,
}

impl Parse for ConfigBlock {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::braced!(content in input);
        input.parse::<Token![;]>()?;

        let mut fields = Vec::new();
        while !content.is_empty() {
            let name: Ident = content.parse()?;
            content.parse::<Token![:]>()?;
            let value: Expr = content.parse()?;
            fields.push(ConfigField { name, value });

            if !content.is_empty() {
                content.parse::<Token![,]>()?;
            }
        }

        Ok(ConfigBlock { fields })
    }
}

struct ConfigField {
    name: Ident,
    value: Expr,
}

impl ToTokens for ConfigField {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let name = &self.name;
        let value = &self.value;
        tokens.extend(quote! { #name: #value, });
    }
}

struct RuleDefinition {
    effect: Effect,
    target: TargetSpec,
    condition: Option<ConditionExpr>,
    reason_code: ReasonCode,
}

impl Parse for RuleDefinition {
    fn parse(input: ParseStream) -> Result<Self> {
        let effect: Effect = input.parse()?;
        let target: TargetSpec = input.parse()?;

        let condition = if input.peek(Ident) {
            let lookahead = input.fork();
            if let Ok(ident) = lookahead.parse::<Ident>() {
                if ident == "WHERE" {
                    let _: Ident = input.parse()?;
                    Some(input.parse()?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        input.parse::<Token![=>]>()?;
        let reason_code: ReasonCode = input.parse()?;
        input.parse::<Token![;]>()?;

        Ok(RuleDefinition {
            effect,
            target,
            condition,
            reason_code,
        })
    }
}

impl RuleDefinition {
    fn expand(&self) -> TokenStream2 {
        let effect = self.effect.expand();
        let target = self.target.expand();
        let condition = if let Some(ref cond) = self.condition {
            let cond_expr = cond.expand();
            quote! { Some(#cond_expr) }
        } else {
            quote! { None }
        };
        let reason = self.reason_code.expand();

        quote! {
            ::gate0::Rule::new(
                #effect,
                #target,
                #condition,
                #reason
            )
        }
    }
}

enum Effect {
    Allow,
    Deny,
}

impl Parse for Effect {
    fn parse(input: ParseStream) -> Result<Self> {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "ALLOW" => Ok(Effect::Allow),
            "DENY" => Ok(Effect::Deny),
            _ => Err(syn::Error::new(ident.span(), "expected ALLOW or DENY")),
        }
    }
}

impl Effect {
    fn expand(&self) -> TokenStream2 {
        match self {
            Effect::Allow => quote! { ::gate0::Effect::Allow },
            Effect::Deny => quote! { ::gate0::Effect::Deny },
        }
    }
}

enum TargetSpec {
    #[allow(dead_code)]
    Any(Ident),
    Tuple(TupleTarget),
    Struct(StructTarget),
}

impl Parse for TargetSpec {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.peek(Token![*]) {
            input.parse::<Token![*]>()?;
            Ok(TargetSpec::Any(Ident::new("star", Span::call_site())))
        } else if input.peek(Ident) {
            let ident: Ident = input.parse()?;
            if ident == "ANY" {
                Ok(TargetSpec::Any(ident))
            } else {
                Err(syn::Error::new(
                    ident.span(),
                    "expected ANY, *, tuple, or struct",
                ))
            }
        } else if input.peek(Paren) {
            Ok(TargetSpec::Tuple(input.parse()?))
        } else if input.peek(Brace) {
            Ok(TargetSpec::Struct(input.parse()?))
        } else {
            Err(syn::Error::new(
                input.span(),
                "expected *, ANY, tuple, or struct",
            ))
        }
    }
}

impl TargetSpec {
    fn expand(&self) -> TokenStream2 {
        match self {
            TargetSpec::Any(_) => quote! { ::gate0::Target::any() },
            TargetSpec::Tuple(t) => t.expand(),
            TargetSpec::Struct(s) => s.expand(),
        }
    }
}

struct TupleTarget {
    principal: FieldValue,
    action: FieldValue,
    resource: FieldValue,
}

impl Parse for TupleTarget {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::parenthesized!(content in input);

        let principal = content.parse()?;
        let action = content.parse()?;
        let resource = content.parse()?;

        Ok(TupleTarget {
            principal,
            action,
            resource,
        })
    }
}

impl TupleTarget {
    fn expand(&self) -> TokenStream2 {
        let principal = self.principal.to_matcher();
        let action = self.action.to_matcher();
        let resource = self.resource.to_matcher();

        quote! {
            ::gate0::Target {
                principal: #principal,
                action: #action,
                resource: #resource,
            }
        }
    }
}

struct StructTarget {
    fields: Vec<StructTargetField>,
}

impl Parse for StructTarget {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::braced!(content in input);

        let mut fields = Vec::new();
        while !content.is_empty() {
            fields.push(content.parse()?);
            if !content.is_empty() {
                content.parse::<Token![,]>()?;
            }
        }

        Ok(StructTarget { fields })
    }
}

impl StructTarget {
    fn expand(&self) -> TokenStream2 {
        let mut principal = None;
        let mut action = None;
        let mut resource = None;

        for field in &self.fields {
            match field.name.to_string().as_str() {
                "principal" => principal = Some(&field.value),
                "action" => action = Some(&field.value),
                "resource" => resource = Some(&field.value),
                _ => {}
            }
        }

        let principal_matcher = principal
            .map(|v| v.to_matcher())
            .unwrap_or_else(|| quote! { ::gate0::Matcher::Any });
        let action_matcher = action
            .map(|v| v.to_matcher())
            .unwrap_or_else(|| quote! { ::gate0::Matcher::Any });
        let resource_matcher = resource
            .map(|v| v.to_matcher())
            .unwrap_or_else(|| quote! { ::gate0::Matcher::Any });

        quote! {
            ::gate0::Target {
                principal: #principal_matcher,
                action: #action_matcher,
                resource: #resource_matcher,
            }
        }
    }
}

struct StructTargetField {
    name: Ident,
    value: FieldValue,
}

impl StructTargetField {
    fn valid_field_names() -> &'static [&'static str] {
        &["principal", "action", "resource"]
    }
}

impl Parse for StructTargetField {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        let valid_field_names = Self::valid_field_names();
        if !valid_field_names.contains(&name.to_string().as_str()) {
            return Err(syn::Error::new(
                name.span(),
                format!("expected one of: {}", valid_field_names.join(", ")),
            ));
        }
        input.parse::<Token![:]>()?;
        let value: FieldValue = input.parse()?;
        Ok(StructTargetField { name, value })
    }
}

enum FieldValue {
    Literal(LitStr),
    Array(Vec<LitStr>),
    #[allow(dead_code)]
    Any(Ident),
}

impl Parse for FieldValue {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.peek(Token![*]) {
            input.parse::<Token![*]>()?;
            Ok(FieldValue::Any(Ident::new("star", Span::call_site())))
        } else if input.peek(Ident) {
            let ident: Ident = input.parse()?;
            if ident == "ANY" {
                Ok(FieldValue::Any(ident))
            } else {
                Err(syn::Error::new(
                    ident.span(),
                    "expected ANY, *, a string literal, or an array",
                ))
            }
        } else if input.peek(syn::token::Bracket) {
            let content;
            syn::bracketed!(content in input);
            let mut values = Vec::new();
            while !content.is_empty() {
                values.push(content.parse()?);
                if !content.is_empty() {
                    content.parse::<Token![,]>()?;
                }
            }
            Ok(FieldValue::Array(values))
        } else {
            Ok(FieldValue::Literal(input.parse()?))
        }
    }
}

impl FieldValue {
    fn to_matcher(&self) -> TokenStream2 {
        match self {
            FieldValue::Literal(lit) => quote! { ::gate0::Matcher::Exact(#lit) },
            FieldValue::Array(arr) => quote! { ::gate0::Matcher::OneOf(&[#(#arr),*]) },
            FieldValue::Any(_) => quote! { ::gate0::Matcher::Any },
        }
    }
}

enum ReasonCode {
    Literal(LitInt),
    Ident(Ident),
}

impl Parse for ReasonCode {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.peek(LitInt) {
            Ok(ReasonCode::Literal(input.parse()?))
        } else {
            Ok(ReasonCode::Ident(input.parse()?))
        }
    }
}

impl ReasonCode {
    fn expand(&self) -> TokenStream2 {
        match self {
            ReasonCode::Literal(lit) => quote! { ::gate0::ReasonCode(#lit) },
            ReasonCode::Ident(ident) => quote! { #ident },
        }
    }
}

struct ConditionExpr {
    expr: Box<Condition>,
}

impl Parse for ConditionExpr {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::braced!(content in input);
        let expr = Box::new(content.parse()?);
        Ok(ConditionExpr { expr })
    }
}

impl ConditionExpr {
    fn expand(&self) -> TokenStream2 {
        self.expr.expand()
    }
}

enum Condition {
    Equals { attr: Ident, value: syn::Lit },
    NotEquals { attr: Ident, value: syn::Lit },
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
    True,
    False,
    Ident(Ident),
}

impl Parse for Condition {
    fn parse(input: ParseStream) -> Result<Self> {
        parse_condition_inner(input)
    }
}

fn parse_condition_inner(input: ParseStream) -> Result<Condition> {
    if let Ok(lit_bool) = input.parse::<LitBool>() {
        if lit_bool.value {
            return Ok(Condition::True);
        } else {
            return Ok(Condition::False);
        }
    }

    if input.peek(Ident) {
        let lookahead = input.fork();
        if let Ok(ident) = lookahead.parse::<Ident>() {
            if ident == "NOT" {
                let _: Ident = input.parse()?;
                let inner = if input.peek(Paren) {
                    let content;
                    syn::parenthesized!(content in input);
                    Box::new(parse_condition_inner(&content)?)
                } else {
                    Box::new(parse_atom(input, false)?)
                };
                return Ok(Condition::Not(inner));
            }
        }
    }

    let left_span = input.span();
    let left = parse_atom(input, true)?;

    if input.peek(Ident) {
        let lookahead = input.fork();
        if let Ok(ident) = lookahead.parse::<Ident>() {
            let condition = match ident.to_string().as_str() {
                "AND" => {
                    if left.is_ident() {
                        return Err(syn::Error::new(
                            left_span,
                            "expected true, false, or a parenthesized condition",
                        ));
                    }
                    let _: Ident = input.parse()?;
                    let right = Box::new(parse_condition_inner(input)?);
                    Condition::And(Box::new(left), right)
                }
                "OR" => {
                    if left.is_ident() {
                        return Err(syn::Error::new(
                            left_span,
                            "expected true, false, or a parenthesized condition",
                        ));
                    }
                    let _: Ident = input.parse()?;
                    let right = Box::new(parse_condition_inner(input)?);
                    Condition::Or(Box::new(left), right)
                }
                "EQ" => {
                    let _: Ident = input.parse()?;
                    let value: syn::Lit = input.parse()?;
                    if let Condition::Ident(attr) = left {
                        Condition::Equals { attr, value }
                    } else {
                        return Err(syn::Error::new(
                            input.span(),
                            "EQ requires an identifier on the left",
                        ));
                    }
                }
                "NEQ" => {
                    let _: Ident = input.parse()?;
                    let value: syn::Lit = input.parse()?;
                    if let Condition::Ident(attr) = left {
                        Condition::NotEquals { attr, value }
                    } else {
                        return Err(syn::Error::new(
                            input.span(),
                            "NEQ requires an identifier on the left",
                        ));
                    }
                }
                _ => {
                    return Err(syn::Error::new(
                        input.span(),
                        "expected one of: EQ, NEQ, AND, OR",
                    ));
                }
            };
            if let Ok(ident) = input.parse::<Ident>() {
                match ident.to_string().as_str() {
                    "AND" => {
                        let right = Box::new(parse_condition_inner(input)?);
                        return Ok(Condition::And(Box::new(condition), right));
                    }
                    "OR" => {
                        let right = Box::new(parse_condition_inner(input)?);
                        return Ok(Condition::Or(Box::new(condition), right));
                    }
                    _ => {
                        return Err(syn::Error::new(input.span(), "expected one of: AND, OR"));
                    }
                }
            }
            return Ok(condition);
        }
    }

    Ok(left)
}

fn parse_atom(input: ParseStream, ident_allowed: bool) -> Result<Condition> {
    if input.peek(Paren) {
        let content;
        syn::parenthesized!(content in input);
        return parse_condition_inner(&content);
    }

    if input.peek(LitBool) {
        let lit_bool: LitBool = input.parse()?;
        return match lit_bool.value {
            true => Ok(Condition::True),
            false => Ok(Condition::False),
        };
    }
    if ident_allowed && input.peek(Ident) {
        let ident: Ident = input.parse()?;
        Ok(Condition::Ident(ident))
    } else {
        Err(syn::Error::new(
            input.span(),
            "expected true, false, or a parenthesized condition",
        ))
    }
}

impl Condition {
    fn expand(&self) -> TokenStream2 {
        match self {
            Condition::Equals { attr, value } => {
                let attr_str = attr.to_string();
                quote! {
                    ::gate0::Condition::Equals {
                        attr: #attr_str,
                        value: ::gate0::Value::from(#value),
                    }
                }
            }
            Condition::NotEquals { attr, value } => {
                let attr_str = attr.to_string();
                quote! {
                    ::gate0::Condition::NotEquals {
                        attr: #attr_str,
                        value: ::gate0::Value::from(#value),
                    }
                }
            }
            Condition::And(left, right) => {
                let left_expr = left.expand();
                let right_expr = right.expand();
                quote! {
                    ::gate0::Condition::And(
                        Box::new(#left_expr),
                        Box::new(#right_expr)
                    )
                }
            }
            Condition::Or(left, right) => {
                let left_expr = left.expand();
                let right_expr = right.expand();
                quote! {
                    ::gate0::Condition::Or(
                        Box::new(#left_expr),
                        Box::new(#right_expr)
                    )
                }
            }
            Condition::Not(inner) => {
                let inner_expr = inner.expand();
                quote! {
                    ::gate0::Condition::Not(Box::new(#inner_expr))
                }
            }
            Condition::True => quote! { ::gate0::Condition::True },
            Condition::False => quote! { ::gate0::Condition::False },
            Condition::Ident(ident) => quote! { #ident },
        }
    }
    fn is_ident(&self) -> bool {
        match self {
            Condition::Ident(_) => true,
            _ => false,
        }
    }
}
