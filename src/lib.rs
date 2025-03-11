#![no_std]
#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![warn(variant_size_differences)]

// TODO move to a module
macro_rules! check {
    ($e:expr) => {
        if !$e {
            return Err("");
        }
    };
    ($e:expr, $msg: expr) => {
        if !$e {
            return Err($msg);
        }
    };
}

#[cfg(feature = "compression")]
extern crate flate2;
#[cfg(feature = "compression")]
extern crate std;

pub mod dynamic;
pub mod hash;
pub mod header;
pub mod program;
pub mod sections;
pub mod slice;
pub mod symbol_table;

use core::ops::Deref;

use header::Header;
use program::{ProgramHeader, ProgramIter};
use sections::{SectionHeader, SectionIter};
use zero::Pod;

#[derive(Debug)]
pub enum ParseError<T> {
    Io(T),
    Message(&'static str),
}

pub trait Buffer: Copy {
    type Error;

    type Ref<'a, T: Copy + 'a>: Copy + Deref<Target = T> + 'a
    where
        Self: 'a;

    type Array<'a, T: Copy + 'a>: Array<'a, T, Error = Self::Error>
    where
        Self: 'a;

    type String<'a>: Copy + Deref<Target = str> + 'a
    where
        Self: 'a;

    type Strings<'a>: Iterator<Item = Self::String<'a>> + 'a
    where
        Self: 'a;

    fn empty() -> Self;

    fn offset(self, offset: usize) -> Self;

    fn truncate(self, size: usize) -> Self;

    fn read<'a, T: Pod + Copy>(self) -> Result<Self::Ref<'a, T>, Self::Error>
    where
        Self: 'a;

    fn read_array<'a, T: Pod + Copy>(self) -> Result<Self::Array<'a, T>, Self::Error>
    where
        Self: 'a;

    fn read_str<'a>(self) -> Result<Self::String<'a>, Self::Error>
    where
        Self: 'a;

    fn read_strs_to_null<'a>(self) -> Self::Strings<'a>
    where
        Self: 'a;
}

pub trait Array<'a, T: Copy + 'a>: Copy + 'a {
    type Error;

    fn read_at(&self, index: usize) -> Result<T, <Self as Array<'a, T>>::Error>;
}

pub type P32 = u32;
pub type P64 = u64;

#[derive(Debug)]
pub struct ElfFile<'a, B: Buffer + 'a> {
    pub input: B,
    pub header: Header<'a, B>,
}

impl<'a, B: Buffer + 'a> ElfFile<'a, B> {
    pub fn new(input: B) -> Result<Self, ParseError<B::Error>> {
        header::parse_header(input).map(|header| ElfFile { input, header })
    }

    pub fn section_header(&self, index: u16) -> Result<SectionHeader<'a, B>, ParseError<B::Error>> {
        sections::parse_section_header(self.input, self.header, index)
    }

    pub fn section_iter(&self) -> impl Iterator<Item = SectionHeader<'a, B>> + '_ {
        SectionIter {
            file: self,
            next_index: 0,
        }
    }

    pub fn program_header(&self, index: u16) -> Result<ProgramHeader<'a, B>, ParseError<B::Error>> {
        program::parse_program_header(self.input, self.header, index)
    }

    pub fn program_iter(&self) -> impl Iterator<Item = ProgramHeader<'a, B>> + '_ {
        ProgramIter {
            file: self,
            next_index: 0,
        }
    }

    pub fn get_shstr(&self, index: u32) -> Result<B::String<'_>, ParseError<B::Error>> {
        self.get_shstr_table().and_then(|shstr_table| {
            shstr_table
                .offset(index as usize)
                .read_str()
                .map_err(ParseError::Io)
        })
    }

    pub fn get_string(&'a self, index: u32) -> Result<B::String<'a>, ParseError<B::Error>> {
        let header = self
            .find_section_by_name(".strtab")
            .ok_or(ParseError::Message("no .strtab section"))?;
        if header.get_type().map_err(ParseError::Message)? != sections::ShType::StrTab {
            return Err(ParseError::Message("expected .strtab to be StrTab"));
        }
        header
            .raw_data(self)
            .offset(index as usize)
            .read_str()
            .map_err(ParseError::Io)
    }

    pub fn get_dyn_string(&'a self, index: u32) -> Result<B::String<'a>, ParseError<B::Error>> {
        let header = self
            .find_section_by_name(".dynstr")
            .ok_or(ParseError::Message("no .dynstr section"))?;
        header
            .raw_data(self)
            .offset(index as usize)
            .read_str()
            .map_err(ParseError::Io)
    }

    // This is really, stupidly slow. Not sure how to fix that, perhaps keeping
    // a HashTable mapping names to section header indices?
    pub fn find_section_by_name(&'a self, name: &'a str) -> Option<SectionHeader<'a, B>> {
        for sect in self.section_iter() {
            if let Ok(sect_name) = sect.get_name(self) {
                if &*sect_name == name {
                    return Some(sect);
                }
            }
        }

        None
    }

    fn get_shstr_table(&self) -> Result<B, ParseError<B::Error>> {
        // TODO cache this?
        let header = self.section_header(self.header.pt2.sh_str_index());
        header.and_then(|h| {
            let offset = h.offset() as usize;
            // if self.input.len() < offset {
            //     return Err("File is shorter than section offset");
            // }
            Ok(self.input.offset(offset))
        })
    }
}

/// A trait for things that are common ELF conventions but not part of the ELF
/// specification.
pub trait Extensions<'a, B: Buffer + 'a> {
    /// Parse and return the value of the .note.gnu.build-id section, if it
    /// exists and is well-formed.
    fn get_gnu_buildid(&'a self) -> Option<B>;

    /// Parse and return the value of the .gnu_debuglink section, if it
    /// exists and is well-formed.
    fn get_gnu_debuglink(&'a self) -> Option<(B::String<'a>, u32)>;

    /// Parse and return the value of the .gnu_debugaltlink section, if it
    /// exists and is well-formed.
    fn get_gnu_debugaltlink(&'a self) -> Option<(B::String<'a>, B)>;
}

impl<'a, B: Buffer + 'a> Extensions<'a, B> for ElfFile<'a, B> {
    fn get_gnu_buildid(&'a self) -> Option<B> {
        self.find_section_by_name(".note.gnu.build-id")
            .and_then(|header| header.get_data(self).ok())
            .and_then(|data| match data {
                // Handle Note32 if it's ever implemented!
                sections::SectionData::Note64(header, data) => Some((header, data)),
                _ => None,
            })
            .and_then(|(header, data)| {
                // Check for NT_GNU_BUILD_ID
                if header.type_() != 0x3 {
                    return None;
                }

                if &*header.name(data).ok()? != "GNU" {
                    return None;
                }

                Some(header.desc(data))
            })
    }

    fn get_gnu_debuglink(&'a self) -> Option<(B::String<'a>, u32)> {
        self.find_section_by_name(".gnu_debuglink")
            .and_then(|header| {
                let data = header.raw_data(self);
                let file = data.read_str().ok()?;
                // Round up to the nearest multiple of 4.
                let checksum_pos = ((file.len() + 4) / 4) * 4;
                let checksum: u32 = *data.offset(checksum_pos).read().ok()?;
                Some((file, checksum))
            })
    }

    fn get_gnu_debugaltlink(&'a self) -> Option<(B::String<'a>, B)> {
        self.find_section_by_name(".gnu_debugaltlink")
            .map(|header| header.raw_data(self))
            .and_then(|data| {
                let file = data.read_str().ok()?;
                // The rest of the data is a SHA1 checksum of the debuginfo, no alignment
                let checksum_pos = file.len() + 1;
                Some((file, data.offset(checksum_pos)))
            })
    }
}

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod test {
    use std::prelude::v1::*;

    use crate::slice::SliceBuffer;

    use super::*;
    use header::{HeaderPt1, HeaderPt2_};

    fn mk_elf_header(class: u8) -> Vec<u8> {
        let header_size = size_of::<HeaderPt1>()
            + match class {
                1 => size_of::<HeaderPt2_<P32>>(),
                2 => size_of::<HeaderPt2_<P64>>(),
                _ => 0,
            };
        let mut header = vec![0x7f, 'E' as u8, 'L' as u8, 'F' as u8];
        let data = 1u8;
        let version = 1u8;
        header.extend_from_slice(&[class, data, version]);
        header.resize(header_size, 0);
        header
    }

    #[test]
    fn interpret_class() {
        assert!(ElfFile::new(SliceBuffer {
            inner: &mk_elf_header(0)
        })
        .is_err());
        assert!(ElfFile::new(SliceBuffer {
            inner: &mk_elf_header(1)
        })
        .is_ok());
        assert!(ElfFile::new(SliceBuffer {
            inner: &mk_elf_header(2)
        })
        .is_ok());
        assert!(ElfFile::new(SliceBuffer {
            inner: &mk_elf_header(42u8)
        })
        .is_err());
    }
}
