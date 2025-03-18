/// Action is a generic channel action, that occurred in the channel. It is
/// parameterized by the type of the channel state.
pub enum Action<S>
where
    S: Applyable,
{
    Open(S),
    Fund(S),
    Abort(S),
    Send(S),
    Close(S),
    ForceClose(S),
}

/// Applyable allows to apply an action containing the same state type to its
/// current state.
pub trait Applyable
where
    Self: Clone,
{
    fn apply(self, action: &Action<Self>) -> Self;
}
