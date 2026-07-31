use std::collections::{BTreeMap, BTreeSet};

use nxb_lifecycle_governance::LifecycleClosureCertificate;
use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_hash_map, validate_identifier, validate_sha256, EvolutionAuditChain,
    EvolutionAuditEvent, EvolutionError, MAX_CANARY_SAMPLES, MAX_COMPONENTS, MAX_STEPS,
};

include!("p16_part1.rs");
include!("p16_part2.rs");
include!("p16_part3.rs");
include!("p16_part4.rs");
include!("p16_part5.rs");
include!("p16_part6.rs");
