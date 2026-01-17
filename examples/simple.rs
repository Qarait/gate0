use gate0::{Matcher, Policy, PolicyConfig, ReasonCode, Request, Rule, Target};

macro_rules! policy_builder {
    [ use $builder:ident; config { $($key:ident: $value:expr),* $(,)? }; $($t1:tt $t2:tt $t3:tt $t4:tt $t5:tt;)+ ] => {
        {
            $builder = $builder.config(PolicyConfig {
                $(
                    $key: $value,
                )*
                ..PolicyConfig::default()
            });
            policy_builder![
                use $builder;
                $($t1 $t2 $t3 $t4 $t5;)+
            ]
        }
    };
    [ use $builder:ident; $($t1:tt $t2:tt $t3:tt $t4:tt $t5:tt;)+ ] => {
        {
            $(
                $builder = $builder.rule( rule!($t1 $t2 $t3 $t4 $t5) );
            )+
            $builder
        }
    };
    [ config { $($key:ident: $value:expr),* $(,)? }; $($t1:tt $t2:tt $t3:tt $t4:tt $t5:tt;)+ ] => {
        {
            let mut builder = Policy::builder();
            policy_builder![
                use builder;
                config { $($key: $value),* };
                $($t1 $t2 $t3 $t4 $t5;)+
            ]
        }
    };
    [ $($t1:tt $t2:tt $t3:tt $t4:tt $t5:tt;)+ ] => {
        {
            let mut builder = Policy::builder();
            policy_builder![
                use builder;
                $($t1 $t2 $t3 $t4 $t5;)+
            ]
        }
    };
}

macro_rules! rule {
    ($effect:ident $($t:tt)+) => {
        rule_inner!($effect, $($t)+)
    };
}

macro_rules! rule_inner {
    ($effect:ident, * => reason $rc:tt) => {
        Rule::$effect(Target::any(), reason_code!($rc))
    };
    ($effect:ident, any => reason $rc:tt) => {
        Rule::$effect(Target::any(), reason_code!($rc))
    };
    ($effect:ident, ($p:tt $a:tt $r:tt) => reason $rc:literal) => {
        Rule::$effect(
            Target {
                principal: field_matcher!(principal, principal: $p,),
                action:field_matcher!(action, action: $a,),
                resource: field_matcher!(resource, resource: $r,),
            },
            reason_code!($rc),
        )
    };
    ($effect:ident, {$($a:tt: $b:tt)*} => reason $rc:literal) => {
        Rule::$effect(
            Target {
                principal: field_matcher!(principal, $($a: $b,)*),
                action: field_matcher!(action, $($a: $b,)*),
                resource: field_matcher!(resource, $($a: $b,)*),
            },
            reason_code!($rc),
        )
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

macro_rules! field_matcher {
    (@find $wanted:ident, $wanted2:ident : [ $($vals:literal),* $(,)? ], $($rest:tt)*) => {
        Matcher::OneOf(&[ $($vals),* ])
    };

    (@find $wanted:ident, $wanted2:ident : *, $($rest:tt)*) => {
        Matcher::Any
    };

    (@find $wanted:ident, $wanted2:ident : any, $($rest:tt)*) => {
        Matcher::Any
    };

    (@find $wanted:ident, $wanted2:ident : $val:literal, $($rest:tt)*) => {
        Matcher::Exact($val)
    };

    (@find $wanted:ident, $other:ident : $val:tt, $($rest:tt)*) => {
        field_matcher!(@find $wanted, $($rest)*)
    };

    (@find $wanted:ident,) => {
        Matcher::Any
    };

    ($wanted:ident, $($pairs:tt)*) => {
        field_matcher!(@find $wanted, $($pairs)*)
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = policy_builder![
        config {
            max_rules: 1000,
            max_condition_depth: 10,
            max_context_attrs: 64,
            max_matcher_options: 64,
            max_string_len: 256,
        };
        allow any => reason 1;
        allow ("alice" ["read"] any) => reason 2;
        allow ("alice" [*, *, *, "test"] *) => reason 3;
        deny { principal: ["bob", "eve"] action: ["delete", "update"] resource: any } => reason 4;
    ]
    .build()?;
    println!("Policy: {:#?}", policy);

    let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
    println!("{:?}", decision);
    Ok(())
}
