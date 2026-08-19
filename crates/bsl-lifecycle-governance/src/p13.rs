use std::collections::{BTreeMap, BTreeSet};

use bsl_platform_assurance::{FinalAssuranceCertificate, RoadmapClosureCertificate};
use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256,
    LifecycleAuditChain, LifecycleAuditEvent, LifecycleError, MAX_COMPONENTS, MAX_INVARIANTS,
    MAX_MAINTENANCE_DURATION_TICKS, MAX_MAINTENANCE_OPERATIONS,
};

include!("p13_part1.rs");
include!("p13_part2.rs");
include!("p13_part3.rs");
include!("p13_part4.rs");
include!("p13_part5.rs");
include!("p13_part6.rs");
include!("p13_part7.rs");
