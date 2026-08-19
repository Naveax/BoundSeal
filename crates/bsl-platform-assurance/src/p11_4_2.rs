impl OperatorControlPlane {
    fn transition(
        &mut self,
        command: OperatorCommand,
        now: u64,
        reason: &str,
    ) -> Result<OperatorControlState, AssuranceError> {
        match (self.state, command) {
            (OperatorControlState::Running, OperatorCommand::Pause) => {
                Ok(OperatorControlState::Paused)
            }
            (OperatorControlState::Paused, OperatorCommand::Resume) => {
                Ok(OperatorControlState::Running)
            }
            (
                OperatorControlState::Running | OperatorControlState::Paused,
                OperatorCommand::Cancel,
            ) => {
                let i = IncidentRecord::new(
                    IncidentClass::OperatorCancellation,
                    self.next_sequence,
                    reason.into(),
                    now,
                )?;
                self.incidents.insert(i.incident_id.clone(), i);
                Ok(OperatorControlState::Cancelling)
            }
            (OperatorControlState::Cancelling, OperatorCommand::Cancel) => {
                Ok(OperatorControlState::Cancelled)
            }
            (
                OperatorControlState::Running
                | OperatorControlState::Paused
                | OperatorControlState::Cancelling,
                OperatorCommand::EmergencyStop,
            ) => {
                let i = IncidentRecord::new(
                    IncidentClass::EmergencyStop,
                    self.next_sequence,
                    reason.into(),
                    now,
                )?;
                self.incidents.insert(i.incident_id.clone(), i);
                Ok(OperatorControlState::EmergencyStopped)
            }
            (
                OperatorControlState::Cancelled | OperatorControlState::EmergencyStopped,
                OperatorCommand::AcknowledgeIncident,
            ) => {
                let i = self
                    .incidents
                    .values_mut()
                    .find(|i| i.is_open())
                    .ok_or_else(|| AssuranceError::InvalidTransition("no open incident".into()))?;
                i.acknowledge(now)?;
                Ok(self.state)
            }
            (
                OperatorControlState::Cancelled | OperatorControlState::EmergencyStopped,
                OperatorCommand::SealRun,
            ) if self.incidents.values().all(|i| !i.is_open()) => Ok(OperatorControlState::Sealed),
            _ => Err(AssuranceError::InvalidTransition(
                "operator command state transition".into(),
            )),
        }
    }
    pub fn state(&self) -> OperatorControlState {
        self.state
    }
    pub fn incidents(&self) -> &BTreeMap<String, IncidentRecord> {
        &self.incidents
    }
    pub fn audit(&self) -> &AssuranceAuditChain {
        &self.audit
    }
}
