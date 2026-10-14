//! GIFs, for a frontend that must never see a provider URL.
//!
//! Searching and previews are [`crate::gifs::Gifs`]'s, shared out of the session so they
//! can run without the session lock. Sending is the attachment path: the chosen GIF's bytes
//! are fetched through the relay and then sealed, uploaded and sent exactly as a photo
//! would be, so recipients fetch ciphertext from the instance and nothing from the provider.

use std::sync::Arc;

use super::{MessageView, Session, SessionError};
use crate::gifs::Gifs;

impl Session {
    /// GIF search for this session. Made on first use; cheap to call again.
    pub fn gifs(&mut self) -> Result<Arc<Gifs>, SessionError> {
        if let Some(g) = &self.gifs {
            return Ok(Arc::clone(g));
        }
        let g = Arc::new(Gifs::new(self.client.clone())?);
        self.gifs = Some(Arc::clone(&g));
        Ok(g)
    }

    /// Fetch a GIF from the last searches and send it to the open room as an encrypted
    /// attachment, in one call. The desktop shell runs the same steps with the lock
    /// released around the network parts.
    pub fn send_gif(&mut self, id: &str) -> Result<MessageView, SessionError> {
        let file = self.gifs()?.fetch_for_sending(id)?;
        self.send_file(&file.name, file.mime, &file.bytes)
    }
}
