use gate0::{Matcher, Policy, ReasonCode, Request, Rule, Target};

macro_rules! rule {
    (allow any => $rc:literal) => {
        Rule::allow(Target::any(), ReasonCode($rc))
    };
    (deny any => $rc:literal) => {
        Rule::deny(Target::any(), ReasonCode($rc))
    };
    (allow {$($a:tt: $b:tt,)*} => $rc:literal) => {
        Rule::allow(
            Target {
                principal: principal!($($a: $b,)*),
                action: action!($($a: $b,)*),
                resource: resource!($($a: $b,)*),
            },
            ReasonCode($rc),
        )
    };
    // (deny $($a:tt: $b:tt,)+ => $rc:literal) => {
    //     Rule::deny(
    //         Target {
    //             $(
    //                 target!($a: $b)
    //             )*
    //         },
    //         ReasonCode($rc),
    //     )
    // };
}

macro_rules! principal {
    (principal: any, $($a2:tt: $b2:tt,)*) => {
        Matcher::Any
    };
    (principal: $principal:literal, $($a2:tt: $b2:tt,)*) => {
        Matcher::Exact($principal)
    };
    (principal: [$($principal:literal,)*], $($a2:tt: $b2:tt,)*) => {
        Matcher::OneOf(&[$($principal ,)*])
    };
    ($a1:tt: $b1:tt, $($a2:tt: $b2:tt,)+) => {
        principal!( $($a2: $b2,)+ )
    };
    () => {
        Matcher::Any
    };
}

macro_rules! action {
    (action: any, $($a2:tt: $b2:tt,)*) => {
        Matcher::Any
    };
    (action: $action:literal, $($a2:tt: $b2:tt,)*) => {
        Matcher::Exact($action)
    };
    (action: [$($action:literal,)*], $($a2:tt: $b2:tt,)*) => {
        Matcher::OneOf(&[$($action ,)*])
    };
    ($a1:tt: $b1:tt, $($a2:tt: $b2:tt,)+) => {
        action!( $($a2: $b2,)+ )
    };
    () => {
        Matcher::Any
    };
}

macro_rules! resource {
    (resource: any, $($a2:tt: $b2:tt,)*) => {
        Matcher::Any
    };
    (resource: $resource:literal, $($a2:tt: $b2:tt,)*) => {
        Matcher::Exact($resource)
    };
    (resource: [$($resource:literal,)*], $($a2:tt: $b2:tt,)*) => {
        Matcher::OneOf(&[$($resource ,)*])
    };
    ($a1:tt: $b1:tt, $($a2:tt: $b2:tt,)+) => {
        resource!( $($a2: $b2,)+ )
    };
    () => {
        Matcher::Any
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::builder()
        .rule(rule!(allow any => 1))
        .rule(dbg!(rule!(allow
            {principal: "alice",
            action: "read",
            resource: "doc",
            } => 2)))
        .build()?;

    let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
    println!("{:?}", decision);
    Ok(())
}