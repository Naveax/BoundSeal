use std::collections::{BTreeMap, BTreeSet};

use nxb_platform_assurance::{FinalAssuranceCertificate, RoadmapClosureCertificate};
use serde::{Deserialize, Serialize};

use crate::{
    hash_serializable, validate_identifier, validate_sha256, ContinuityCertificate,
    LifecycleAuditChain, LifecycleAuditEvent, LifecycleError, MaintenanceReleaseCertificate,
    MAX_EVIDENCE_SAMPLES, MAX_VERIFIERS,
};

include!("p15_part1.rs");
include!("p15_part2.rs");
include!("p15_part3.rs");
include!("p15_part4.rs");
include!("p15_part5.rs");
include!("p15_part6.rs");
include!("p15_part7.rs");
include!("p15_part8.rs");
include!("p15_part9.rs");
