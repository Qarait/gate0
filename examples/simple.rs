use gate0::{Matcher, Policy, PolicyConfig, ReasonCode, Request, Rule, Target};

macro_rules! policy_builder {
    [ use $builder:ident; config { $($key:ident: $value:expr),* $(,)? }; $($t:tt)* ] => {
        {
            $builder = $builder.config(PolicyConfig {
                $(
                    $key: $value,
                )*
                ..PolicyConfig::default()
            });
            policy_builder![
                use $builder;
                $($t)*
            ]
        }
    };

    [ config { $($key:ident: $value:expr),* $(,)? }; $($t:tt)* ] => {
        {
            let mut builder = Policy::builder();
            policy_builder![
                use builder;
                config { $($key: $value),* };
                $($t)*
            ]
        }
    };

    [ use $builder:ident; $( $effect:ident $t:tt => reason $rc:tt; )* ] => {
        {
            $(
                $builder = $builder.rule( rule!($effect $t => reason $rc;) );
            )*
            $builder
        }
    };

    [ $($t:tt)* ] => {
        {
            let mut builder = Policy::builder();
            policy_builder![
                use builder;
                $($t)*
            ]
        }
    };
}

macro_rules! rule {
    ($effect:ident ($p:tt $a:tt $r:tt) => reason $rc:literal;) => {
        Rule::$effect(
            Target {
                principal: field_matcher!(principal, principal: $p,),
                action:field_matcher!(action, action: $a,),
                resource: field_matcher!(resource, resource: $r,),
            },
            reason_code!($rc),
        )
    };
    ($effect:ident {$($a:tt: $b:tt),* $(,)?} => reason $rc:literal;) => {
        Rule::$effect(
            Target {
                principal: field_matcher!(principal, $($a: $b,)*),
                action: field_matcher!(action, $($a: $b,)*),
                resource: field_matcher!(resource, $($a: $b,)*),
            },
            reason_code!($rc),
        )
    };
    ($effect:ident $any:tt => reason $rc:tt;) => {
        Rule::$effect(any_target!($any), reason_code!($rc))
    };
}

macro_rules! reason_code {
    ( $rc:literal ) => {
        ReasonCode($rc)
    };
    ( $rc:ident ) => {
        $rc
    };
}

macro_rules! any_target {
    (*) => { Target::any() };
    (any) => { Target::any() };
}

macro_rules! field_value_to_matcher {
    (*) => { Matcher::Any };
    (any) => { Matcher::Any };
    ([ $($vals:literal),* $(,)? ]) => { Matcher::OneOf(&[ $($vals),* ]) };
    ($val:literal) => { Matcher::Exact($val) };
    ($other:tt) => {
        compile_error!("field value must be: *, any, a literal, or a list of literals");
    };
}

macro_rules! field_matcher {
    (principal, $($pairs:tt)*) => { field_matcher!(@find_principal, $($pairs)*) };
    (action,    $($pairs:tt)*) => { field_matcher!(@find_action,    $($pairs)*) };
    (resource,  $($pairs:tt)*) => { field_matcher!(@find_resource,  $($pairs)*) };

    (@find_principal, principal : $val:tt, $($rest:tt)*) => { field_value_to_matcher!($val) };
    (@find_principal, $other:ident : $val:tt, $($rest:tt)*) => { field_matcher!(@find_principal, $($rest)*) };
    (@find_principal,) => { Matcher::Any };

    (@find_action, action : $val:tt, $($rest:tt)*) => { field_value_to_matcher!($val) };
    (@find_action, $other:ident : $val:tt, $($rest:tt)*) => { field_matcher!(@find_action, $($rest)*) };
    (@find_action,) => { Matcher::Any };

    (@find_resource, resource : $val:tt, $($rest:tt)*) => { field_value_to_matcher!($val) };
    (@find_resource, $other:ident : $val:tt, $($rest:tt)*) => { field_matcher!(@find_resource, $($rest)*) };
    (@find_resource,) => { Matcher::Any };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Policy::builder();
    let policy = policy_builder![
        use builder; // optional. A new builder is created if no builder is provided
        config { // optional. Default config values are used if no config is provided
            max_rules: 1000,
            max_condition_depth: 10,
            max_context_attrs: 64,
            max_matcher_options: 64,
            // max_string_len: 256, // missing values use defaults
        };
        // allow any => reason 1;
        allow * => reason 1;
        allow ("alice" "read" "something") => reason 2;
        // allow ("alice" ["read", "write"] any) => reason 2;
        // allow (* "read" *) => reason 2;
        // allow (["alice", "bob"] ["read", "write"] ["res1", "res2"]) => reason 2;
        // allow ("alice" ["test"] *) => reason 3;

        // deny {
        //     principal: ["bob", "eve"],
        //     action: ["delete", "update"],
        //     resource: any,
        // } => reason 4;
    ]
    .build()?;
    println!("Policy: {:#?}", policy);

    let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
    println!("{:?}", decision);
    Ok(())
}
