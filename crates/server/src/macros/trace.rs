#[macro_export]
macro_rules! trace {
    ($fmt:expr $(, $args:expr)*) => {
        #[cfg(debug_assertions)]
        #[cfg(feature = "tracing")]
        {
            tracing::trace!($fmt $(, $args)*);
        }
    };
}

#[macro_export]
macro_rules! debug {
    ($fmt:expr $(, $args:expr)*) => {
        #[cfg(debug_assertions)]
        #[cfg(feature = "tracing")]
        {
            tracing::debug!($fmt $(, $args)*);
        }
    };
}

#[macro_export]
macro_rules! info {
    ($fmt:expr $(, $args:expr)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::info!($fmt $(, $args)*);
        }
    };
}

#[macro_export]
macro_rules! warn {
    ($fmt:expr $(, $args:expr)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::warn!($fmt $(, $args)*);
        }
    };
}

#[macro_export]
macro_rules! error {
    ($fmt:expr $(, $args:expr)*) => {
        #[cfg(feature = "tracing")]
        {
            tracing::error!($fmt $(, $args)*);
        }
    };
}