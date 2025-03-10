use core::ops::Index;

use zero::{read, read_array, read_str, read_strs_to_null, Pod, StrReaderIterator};

use crate::Buffer;

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct SliceBuffer<'s> {
    pub inner: &'s [u8],
}

impl<'s> Buffer for SliceBuffer<'s> {
    type Error = SliceError;

    type Ref<'a, T: Copy + 'a>
        = &'a T
    where
        Self: 'a;

    type Slice<'a, T: Copy + 'a>
        = SliceWrapper<'a, T>
    where
        Self: 'a;

    type String<'a>
        = &'a str
    where
        Self: 'a;

    type Strings<'a>
        = StrReaderIterator<'a>
    where
        Self: 'a;

    fn empty() -> Self {
        Self { inner: &[] }
    }

    fn offset(self, offset: usize) -> Self {
        Self {
            inner: &self.inner[offset..],
        }
    }

    fn truncate(self, size: usize) -> Self {
        Self {
            inner: &self.inner[..size],
        }
    }

    fn read<'a, T: Pod + Copy>(self) -> Result<Self::Ref<'a, T>, Self::Error>
    where
        Self: 'a,
    {
        if self.inner.len() >= size_of::<T>() {
            Ok(read(self.inner))
        } else {
            Err(SliceError::TooSmall)
        }
    }

    fn read_array<'a, T: Pod + Copy>(self) -> Result<Self::Slice<'a, T>, Self::Error>
    where
        Self: 'a,
    {
        if self.inner.len() % size_of::<T>() == 0 {
            Ok(SliceWrapper {
                inner: read_array(self.inner),
            })
        } else {
            Err(SliceError::TooSmall)
        }
    }

    fn read_str<'a>(self) -> Result<Self::String<'a>, Self::Error>
    where
        Self: 'a,
    {
        Ok(read_str(self.inner))
    }

    fn read_strs_to_null<'a>(self) -> Self::Strings<'a>
    where
        Self: 'a,
    {
        read_strs_to_null(self.inner)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SliceError {
    TooSmall,
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct SliceWrapper<'a, T> {
    inner: &'a [T],
}

impl<'a, T: Copy> Index<usize> for SliceWrapper<'a, T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.inner[index]
    }
}
