use gate0::{Matcher, Policy, ReasonCode, Request, Rule, Target};


macro_rules! policy_builder {
    [ use $builder:ident; $($t1:tt $t2:tt $t3:tt $t4:tt $t5:tt;)+ ] => {
        {
            $(
                $builder = $builder.rule( rule!($t1 $t2 $t3 $t4 $t5) );
            )+
            $builder
        }
    };
    [ $($t1:tt $t2:tt $t3:tt $t4:tt $t5:tt;)+ ] => {
        {
            let mut builder = Policy::builder();
            $(
                builder = builder.rule( rule!($t1 $t2 $t3 $t4 $t5) );
            )+
            builder
        }
    };
}

macro_rules! rule {
    ($effect:ident $($t:tt)+) => {
        rule_inner!($effect, $($t)+)
    };
}

macro_rules! rule_inner {
    ($effect:ident, any => reason $rc:tt) => {
        Rule::$effect(Target::any(), reason_code!($rc))
    };
    ($effect:ident, ($p:tt $a:tt $r:tt) => reason $rc:literal) => {
        Rule::$effect(
            Target {
                principal: principal!(principal: $p,),
                action: action!(action: $a,),
                resource: resource!(resource: $r,),
            },
            reason_code!($rc),
        )
    };
    ($effect:ident, {$($a:tt: $b:tt)*} => reason $rc:literal) => {
        Rule::$effect(
            Target {
                principal: principal!($($a: $b,)*),
                action: action!($($a: $b,)*),
                resource: resource!($($a: $b,)*),
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

macro_rules! principal {
    (principal: any, $($a2:tt: $b2:tt,)*) => {
        Matcher::Any
    };
    (principal: $principal:literal, $($a2:tt: $b2:tt,)*) => {
        Matcher::Exact($principal)
    };
    (principal: [$($principal:literal),*], $($a2:tt: $b2:tt,)*) => {
        Matcher::OneOf(&[$($principal),*])
    };
    ($a1:tt: $b1:tt, $($a2:tt: $b2:tt,)+) => {
        principal!( $($a2: $b2,)+ )
    };
    ($a1:tt: $b1:tt,) => {
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
    (action: [$($action:literal),*], $($a2:tt: $b2:tt,)*) => {
        Matcher::OneOf(&[$($action ),*])
    };
    ($a1:tt: $b1:tt, $($a2:tt: $b2:tt,)+) => {
        action!( $($a2: $b2,)+ )
    };
    ($a1:tt: $b1:tt,) => {
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
    (resource: [$($resource:literal),*], $($a2:tt: $b2:tt,)*) => {
        Matcher::OneOf(&[$($resource ),*])
    };
    ($a1:tt: $b1:tt, $($a2:tt: $b2:tt,)+) => {
        resource!( $($a2: $b2,)+ )
    };
    ($a1:tt: $b1:tt,) => {
        Matcher::Any
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = policy_builder![
        allow any => reason 1;
        allow ("alice" ["read"] any) => reason 2;
        deny
            {
                principal: ["bob", "eve"]
                action: ["delete", "update"]
                resource: any
            } => reason 3;
    ].build()?;

    // let mut builder = Policy::builder();
    // let policy = policy_builder![
    //     use builder;

    //     allow any => reason 1;
    //     allow
    //         {
    //             principal: "alice",
    //             action: "read",
    //             resource: "doc"
    //         } => reason 2;
    //     deny
    //         {
    //             principal: ["bob", "eve"],
    //             action: ["delete", "update"],
    //             resource: any
    //         } => reason 3;
    // ].build()?;

    println!("Policy: {:#?}", policy);

    let decision = policy.evaluate(&Request::new("alice", "read", "doc"))?;
    println!("{:?}", decision);
    Ok(())
}