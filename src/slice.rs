use core::{
    convert::Infallible,
    ops::{Index, Range},
};

use zero::{Pod, StrReaderIterator};

use crate::Buffer;

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct SliceBuffer<'s> {
    pub inner: &'s [u8],
}

impl<'s> Buffer for SliceBuffer<'s> {
    type Error = Infallible;

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
        todo!()
    }

    fn offset(self, offset: usize) -> Self {
        todo!()
    }

    fn truncate(self, size: usize) -> Self {
        todo!()
    }

    fn read<'a, T: Pod + Copy>(self) -> Result<Self::Ref<'a, T>, Self::Error>
    where
        Self: 'a,
    {
        todo!()
    }

    fn read_array<'a, T: Pod + Copy>(self) -> Result<Self::Slice<'a, T>, Self::Error>
    where
        Self: 'a,
    {
        todo!()
    }

    fn read_str<'a>(self) -> Result<Self::String<'a>, Self::Error>
    where
        Self: 'a,
    {
        todo!()
    }

    fn read_strs_to_null<'a>(self) -> Self::Strings<'a>
    where
        Self: 'a,
    {
        todo!()
    }
}

impl<'s> Index<usize> for SliceBuffer<'s> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.inner[index]
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct SliceWrapper<'a, T> {
    inner: &'a [T],
}

impl<'a, T> Index<usize> for SliceWrapper<'a, T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        todo!()
    }
}
