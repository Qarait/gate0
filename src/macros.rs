#[macro_export]
macro_rules! policy_builder {
    [ USE $builder:ident; CONFIG { $($key:ident: $value:expr),* $(,)? }; $($t:tt)* ] => {
        {
            $builder = $builder.config($crate::PolicyConfig {
                $(
                    $key: $value,
                )*
                ..$crate::PolicyConfig::default()
            });
            policy_builder![
                USE $builder;
                $($t)*
            ]
        }
    };

    [ CONFIG { $($key:ident: $value:expr),* $(,)? }; $($t:tt)* ] => {
        {
            let mut builder = $crate::Policy::builder();
            policy_builder![
                USE builder;
                CONFIG { $($key: $value),* };
                $($t)*
            ]
        }
    };

    [ USE $builder:ident; $( $effect:ident $t:tt $(WHERE { $($cond:tt)+ })? => $rc:tt; )* ] => {
        {
            $(
                $builder = $builder.rule( $crate::rule!($effect $t $(WHERE { $($cond)+ })? => $rc;) );
            )*
            $builder
        }
    };

    [ $($t:tt)* ] => {
        {
            let mut builder = $crate::Policy::builder();
            policy_builder![
                USE builder;
                $($t)*
            ]
        }
    };
}

#[macro_export]
macro_rules! ctx {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {
        &{
            let context: [(&str, Value); _] = [
                $(
                    ($key, ::core::convert::Into::<Value>::into($value)),
                )*
            ];
            context
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! rule {
    ($effect:ident ($p:tt, $a:tt, $r:tt) $(WHERE { $($cond:tt)+ })? => $rc:tt;) => {
        $crate::Rule::new(
            $crate::effect!($effect),
            $crate::Target {
                principal: $crate::field_matcher!(principal, PRINCIPAL: $p,),
                action: $crate::field_matcher!(action, ACTION: $a,),
                resource: $crate::field_matcher!(resource, RESOURCE: $r,),
            },
            $crate::option!($($crate::condition!($cond))?),
            $crate::reason_code!($rc),
        )
    };
    ($effect:ident {$($a:tt: $b:tt),* $(,)?} $(WHERE { $($cond:tt)+ })? => $rc:tt;) => {
        $crate::Rule::new(
            $crate::effect!($effect),
            $crate::Target {
                principal: $crate::field_matcher!(principal, $($a: $b,)*),
                action: $crate::field_matcher!(action, $($a: $b,)*),
                resource: $crate::field_matcher!(resource, $($a: $b,)*),
            },
            $crate::option!($($crate::condition!($($cond)+))?),
            $crate::reason_code!($rc),
        )
    };
    ($effect:ident $any:tt $(WHERE { $($cond:tt)+ })? => $rc:tt;) => {
        $crate::Rule::new(
            $crate::effect!($effect),
            $crate::any_matcher!($any, $crate::Target::any()),
            $crate::option!($($crate::condition!($($cond)+))?),
            $crate::reason_code!($rc),
        )
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! effect {
    (ALLOW) => {
        $crate::Effect::Allow
    };
    (DENY) => {
        $crate::Effect::Deny
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! option {
    ($cond:expr) => {{
        Some($cond)
    }};
    () => {{
        None
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! condition {
    () => {};
    (($attr:ident = $value:literal)) => {{
        $crate::Condition::Equals {
            attr: stringify!($attr),
            value: $crate::Value::from($value),
        }
    }};
    (($attr:ident EQ $value:literal)) => {{
        $crate::Condition::Equals {
            attr: stringify!($attr),
            value: $crate::Value::from($value),
        }
    }};
    (($attr:ident != $value:literal)) => {{
        $crate::Condition::NotEquals {
            attr: stringify!($attr),
            value: $crate::Value::from($value),
        }
    }};
    (($attr:ident NEQ $value:literal)) => {{
        $crate::Condition::NotEquals {
            attr: stringify!($attr),
            value: $crate::Value::from($value),
        }
    }};
    ((($($a:tt)+) AND ($($b:tt)+))) => {{
        $crate::Condition::And(
            Box::new($crate::condition!(($($a)+))),
            Box::new($crate::condition!(($($b)+))))
    }};
    ((($($a:tt)+) OR ($($b:tt)+))) => {{
        $crate::Condition::Or(
            Box::new($crate::condition!(($($a)+))),
            Box::new($crate::condition!(($($b)+))))
    }};
    ((NOT ($($a:tt)+))) => {{
        $crate::Condition::Not(Box::new($crate::condition!(($($a)+))))
    }};
    ((TRUE)) => {{
        $crate::Condition::True
    }};
    ((FALSE)) => {{
        $crate::Condition::False
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! reason_code {
    ( $rc:literal ) => {
        $crate::ReasonCode($rc)
    };
    ( $rc:ident ) => {
        $rc
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! any_matcher {
    (*, $result:expr) => {
        $result
    };
    (ANY, $result:expr) => {
        $result
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! field_value_to_matcher {
    ([ $($vals:literal),* $(,)? ]) => { $crate::Matcher::OneOf(&[ $($vals),* ]) };
    ($val:literal) => { $crate::Matcher::Exact($val) };
    ($e:tt) => { $crate::any_matcher!($e, $crate::Matcher::Any) };
    ($other:tt) => {
        compile_error!("field value must be: *, any, a literal, or a list of literals");
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! field_matcher {
    (principal, $($pairs:tt)*) => { $crate::field_matcher!(@find_principal, $($pairs)*) };
    (action,    $($pairs:tt)*) => { $crate::field_matcher!(@find_action,    $($pairs)*) };
    (resource,  $($pairs:tt)*) => { $crate::field_matcher!(@find_resource,  $($pairs)*) };

    (@find_principal, PRINCIPAL : $val:tt, $($rest:tt)*) => { $crate::field_value_to_matcher!($val) };
    (@find_principal, $other:ident : $val:tt, $($rest:tt)*) => { $crate::field_matcher!(@find_principal, $($rest)*) };
    (@find_principal,) => { Matcher::Any };

    (@find_action, ACTION : $val:tt, $($rest:tt)*) => { $crate::field_value_to_matcher!($val) };
    (@find_action, $other:ident : $val:tt, $($rest:tt)*) => { $crate::field_matcher!(@find_action, $($rest)*) };
    (@find_action,) => { Matcher::Any };

    (@find_resource, RESOURCE : $val:tt, $($rest:tt)*) => { $crate::field_value_to_matcher!($val) };
    (@find_resource, $other:ident : $val:tt, $($rest:tt)*) => { $crate::field_matcher!(@find_resource, $($rest)*) };
    (@find_resource,) => { Matcher::Any };
}

#[cfg(test)]
mod test {
    use crate::{Effect, Matcher, Policy, PolicyConfig, ReasonCode, Rule, Target};

    #[test]
    fn test_simple_any_rules() {
        const REASON_ONE: ReasonCode = ReasonCode(1);
        const REASON_TWO: ReasonCode = ReasonCode(2);
        const REASON_THREE: ReasonCode = ReasonCode(3);
        let policy = policy_builder![
            ALLOW *   => 1;
            ALLOW *   => REASON_ONE;

            ALLOW ANY => 2;
            ALLOW ANY => REASON_TWO;

            DENY  *   => 3;
            DENY  ANY => REASON_THREE;
        ]
        .build()
        .unwrap();
        let rules = policy.rules();
        assert_eq!(rules.len(), 6);
        assert_eq!(rules, &[
            Rule::new(Effect::Allow, Target::any(), None, ReasonCode(1)),
            Rule::new(Effect::Allow, Target::any(), None, REASON_ONE),
            Rule::new(Effect::Allow, Target::any(), None, ReasonCode(2)),
            Rule::new(Effect::Allow, Target::any(), None, REASON_TWO),
            Rule::new(Effect::Deny,  Target::any(), None, ReasonCode(3)),
            Rule::new(Effect::Deny,  Target::any(), None, REASON_THREE),
        ]);
    }

    #[test]
    fn test_simple_tuple_rules() {
        const REASON_ONE: ReasonCode = ReasonCode(1);
        const REASON_TWO: ReasonCode = ReasonCode(2);
        let policy = policy_builder![
            ALLOW ("alice", "read",  "doc1") => 1;
            ALLOW ("bob"  , "write", "doc2") => REASON_ONE;

            DENY  ("eve", *, ANY) => 2;
            DENY  (["eve", "carl"], "write", *) => 2;
            DENY  ("mallory", "delete", "doc3") => REASON_TWO;
        ]
        .build()
        .unwrap();

        let rules = policy.rules();

        assert_eq!(rules.len(), 5);
        assert_eq!(rules, &[
            Rule::new(
                Effect::Allow,
                Target {
                    principal: Matcher::Exact("alice"),
                    action:    Matcher::Exact("read"),
                    resource:  Matcher::Exact("doc1"),
                },
                None,
                ReasonCode(1),
            ),
            Rule::new(
                Effect::Allow,
                Target {
                    principal: Matcher::Exact("bob"),
                    action:    Matcher::Exact("write"),
                    resource:  Matcher::Exact("doc2"),
                },
                None,
                REASON_ONE,
            ),
            Rule::new(
                Effect::Deny,
                Target {
                    principal: Matcher::Exact("eve"),
                    action:    Matcher::Any,
                    resource:  Matcher::Any,
                },
                None,
                ReasonCode(2),
            ),
            Rule::new(
                Effect::Deny,
                Target {
                    principal: Matcher::OneOf(&["eve", "carl"]),
                    action:    Matcher::Exact("write"),
                    resource:  Matcher::Any,
                },
                None,
                ReasonCode(2),
            ),
            Rule::new(
                Effect::Deny,
                Target {
                    principal: Matcher::Exact("mallory"),
                    action:    Matcher::Exact("delete"),
                    resource:  Matcher::Exact("doc3"),
                },
                None,
                REASON_TWO,
            ),
        ]);
    }

    #[test]
    fn test_field_rules() {
        const REASON_ONE: ReasonCode = ReasonCode(1);
        const REASON_TWO: ReasonCode = ReasonCode(2);
        let policy = policy_builder![
            ALLOW {
                PRINCIPAL: "alice",
                ACTION:    "read",
                RESOURCE:  "doc1",
            } => 1;

            ALLOW {
                PRINCIPAL: ["bob", "carl"],
                ACTION:    ["write", "update"],
                RESOURCE:  ANY,
            } => REASON_ONE;

            DENY {
                PRINCIPAL: "eve",
                ACTION:    *,
                RESOURCE:  ANY,
            } => 2;

            DENY {
                PRINCIPAL: ["mallory", "trent"],
                ACTION:    "delete",
                RESOURCE:  ["doc2", "doc3"],
            } => REASON_TWO;
        ]
        .build()
        .unwrap();
        assert_eq!(policy.rule_count(), 4);
    }

    #[test]
    fn test_mixed_rules() {
        const REASON_TWO: ReasonCode = ReasonCode(2);
        const REASON_THREE: ReasonCode = ReasonCode(3);
        let policy = policy_builder![
            ALLOW * => 1;
            ALLOW ("alice", "read", "doc1") => REASON_TWO;
            DENY {
                PRINCIPAL: "eve",
                ACTION:    *,
                RESOURCE:  ANY,
            }=> REASON_THREE;
        ]
        .build()
        .unwrap();
        let rules = policy.rules();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules, &[
            Rule::new(Effect::Allow, Target::any(), None, ReasonCode(1)),
            Rule::new(
                Effect::Allow,
                Target {
                    principal: Matcher::Exact("alice"),
                    action:    Matcher::Exact("read"),
                    resource:  Matcher::Exact("doc1"),
                },
                None,
                REASON_TWO,
            ),
            Rule::new(
                Effect::Deny,
                Target {
                    principal: Matcher::Exact("eve"),
                    action:    Matcher::Any,
                    resource:  Matcher::Any,
                },
                None,
                REASON_THREE,
            ),
        ]);
    }

    #[test]
    fn test_config() {
        let policy = policy_builder![
            CONFIG {
                max_rules: 500,
                max_condition_depth: 5,
            };
            ALLOW * => 1;
        ]
        .build()
        .unwrap();
        assert_eq!(policy.config().max_rules, 500);
        assert_eq!(policy.config().max_condition_depth, 5);
    }

    #[test]
    fn test_where() {
        let policy = policy_builder![
            ALLOW ANY
                WHERE { (role = "admin") } => 1;
            ALLOW ANY
                WHERE { (role != "admin") } => 1;
            ALLOW ANY
                WHERE { (NOT (role = "admin")) } => 1;
            ALLOW ANY
                WHERE { (NOT ((role != "admin") AND (TRUE))) } => 2;
        ]
        .build()
        .unwrap();
        assert_eq!(policy.config().max_rules, 500);
        assert_eq!(policy.config().max_condition_depth, 5);
    }

    #[test]
    fn test_external_builder() {
        let mut builder = Policy::builder().config(PolicyConfig {
            max_rules: 200,
            ..PolicyConfig::default()
        });
        let policy = policy_builder![
            USE builder;
            ALLOW * => 1;
        ]
        .build()
        .unwrap();
        assert_eq!(policy.config().max_rules, 200);
        assert_eq!(policy.rule_count(), 1);
    }
}
