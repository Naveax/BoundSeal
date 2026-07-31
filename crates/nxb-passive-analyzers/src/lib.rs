include!("part1.rs");
include!("part2.rs");
include!("part3.rs");
include!("part4.rs");
include!("part5.rs");
include!("part6.rs");
include!("part7.rs");
include!("capacity_tests.rs");

pub mod finding_store {
    use super::Finding;
    #[cfg(test)]
    use super::{Confidence, Severity};

    include!("store_part1.rs");
    include!("store_part2.rs");
    include!("store_part3.rs");
    include!("store_part4.rs");
    include!("store_tests.rs");
}

pub mod exact_dedup {
    include!("dedup_part1.rs");
    include!("dedup_part2.rs");
    include!("dedup_part3.rs");
    include!("dedup_tests.rs");
}

pub mod root_cause_correlation {
    use super::{Confidence, Finding, Severity};

    include!("correlation_part1.rs");
    include!("correlation_part2.rs");
    include!("correlation_part3.rs");
    include!("correlation_tests.rs");
}

pub mod coverage_saturation {
    include!("coverage_part1.rs");
    include!("coverage_part2.rs");
    include!("coverage_tests.rs");
}
