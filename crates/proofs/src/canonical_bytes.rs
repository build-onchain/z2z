use corez::io::{self, Write};
/// Checks a canonical round-trip without allocating/copying a second full body.
pub(crate) struct CanonicalBytes<'a> {
    pub(crate) remaining: &'a [u8],
}

impl Write for CanonicalBytes<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.remaining.starts_with(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "noncanonical body",
            ));
        }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
