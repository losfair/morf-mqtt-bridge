use futures::Future;
use monoio::buf::IoBufMut;

pub struct OffsetIoBufMut<T> {
  inner: T,
  offset: usize,
}

impl<T> OffsetIoBufMut<T> {
  pub fn into_inner(self) -> T {
    self.inner
  }
}

impl<T: AsRef<[u8]>> OffsetIoBufMut<T> {
  pub fn new(inner: T, offset: usize) -> Self {
    assert!(offset <= inner.as_ref().len());
    Self { inner, offset }
  }
}

unsafe impl<T: IoBufMut> IoBufMut for OffsetIoBufMut<T> {
  fn write_ptr(&mut self) -> *mut u8 {
    unsafe { self.inner.write_ptr().offset(self.offset as isize) }
  }

  fn bytes_total(&mut self) -> usize {
    self.inner.bytes_total() - self.offset
  }

  unsafe fn set_init(&mut self, pos: usize) {
    self.inner.set_init(
      self
        .offset
        .checked_add(pos)
        .expect("OffsetIoBufMut::set_init: overflow"),
    );
  }
}

pub fn enforce_future_type<T: Future<Output = anyhow::Result<()>>>(input: T) -> T {
  input
}
