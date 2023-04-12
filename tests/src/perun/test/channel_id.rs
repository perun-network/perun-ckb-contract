use rand::Rng;

#[derive(Clone, Copy)]
pub struct ChannelId(u32);

impl ChannelId {
    pub fn new() -> Self {
        ChannelId(0)
    }

    pub fn new_random() -> Self {
        ChannelId(rand::thread_rng().gen())
    }
}
