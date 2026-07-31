impl AssuranceCoverageMatrix{pub fn mandatory_count(&self)->usize{self.requirements.values().filter(|r|r.mandatory).count()}}
