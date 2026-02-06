#[macro_export]
macro_rules! ctx {
    ( $( $key:expr => $value:expr ),* $(,)? ) => {
        &{
            let context: [(&str, $crate::Value); _] = [
                $(
                    ($key, ::core::convert::Into::<$crate::Value>::into($value)),
                )*
            ];
            context
        }
    };
}