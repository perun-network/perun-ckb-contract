use crate::perun::{Action, Applyable};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {}

impl Applyable for State {
    fn apply(self, action: &Action<Self>) -> Self {
        match action {
            Action::Open(_) => self,
            Action::Fund(_) => self,
            Action::Abort(_) => self,
            Action::Send(_) => self,
            Action::Close(_) => self,
            Action::ForceClose(_) => self,
        }
    }
}
