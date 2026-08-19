use std::collections::{BTreeMap, BTreeSet};

use bsl_lifecycle_governance::LifecycleClosureCertificate;
use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256,
    PostClosureAuditChain, PostClosureAuditEvent, PostClosureError, MAX_COMPONENTS,
    MAX_CUTOVER_TICKS, MAX_TRANSFER_OBJECTS, MAX_TRANSFER_TOTAL_BYTES,
};

include!("p16_part1.rs");
include!("p16_part2.rs");
include!("p16_part3.rs");
include!("p16_part4.rs");
include!("p16_part5.rs");
include!("p16_part6.rs");
