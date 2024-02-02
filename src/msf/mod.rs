// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt;
use std::ops::Deref;

use scroll::{ctx::TryFromCtx, Endian, Pread};

use crate::common::*;
use crate::source::*;

mod page_list;
use self::page_list::PageList;

type PageNumber = u32;

#[derive(Debug, Copy, Clone)]
struct Header {
    page_size: usize,
    maximum_valid_page_number: PageNumber,
}

impl Header {
    fn pages_needed_to_store(&self, bytes: usize) -> usize {
        (bytes + (self.page_size - 1)) / self.page_size
    }

    fn validate_page_number(&self, page_number: u32) -> Result<PageNumber> {
        if page_number == 0 || page_number > self.maximum_valid_page_number {
            Err(Error::PageReferenceOutOfRange(page_number))
        } else {
            Ok(page_number as PageNumber)
        }
    }
}

/// Represents a stream table at various stages of access
#[doc(hidden)]
#[derive(Debug)]
enum StreamTable<'s> {
    /// The MSF header gives us the size of the table in bytes, and the list of pages (usually one)
    /// where we can find the list of pages that contain the stream table.
    HeaderOnly {
        size_in_bytes: usize,
        stream_table_location_location: PageList,
    },

    /// Given the HeaderOnly information, we can do an initial read to get the actual location of
    /// the stream table as a PageList.
    TableFound { stream_table_location: PageList },

    // Given the table location, we can access the stream table itself
    Available {
        stream_table_view: Box<dyn SourceView<'s>>,
    },
}

fn view<'s>(source: &mut dyn Source<'s>, page_list: &PageList) -> Result<Box<dyn SourceView<'s>>> {
    // view it
    let view = source.view(page_list.source_slices())?;

    // double check our Source
    // if the Source didn't return the requested bits, that's an implementation bug, so
    // assert instead of returning an error
    assert_eq!(view.as_slice().len(), page_list.len());

    // done
    Ok(view)
}

mod big;
mod small;

/// Represents a single Stream within the multi-stream file.
#[derive(Debug)]
pub struct Stream<'s> {
    source_view: Box<dyn SourceView<'s>>,
}

impl<'s> Stream<'s> {
    #[inline]
    pub(crate) fn parse_buffer(&self) -> ParseBuffer<'_> {
        let slice = self.source_view.as_slice();
        ParseBuffer::from(slice)
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.source_view.as_slice()
    }
}

impl Deref for Stream<'_> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// Provides access to a "multi-stream file", which is the container format used by PDBs.
pub trait Msf<'s, S>: fmt::Debug {
    /// Accesses a stream by stream number, optionally restricted by a byte limit.
    fn get(&mut self, stream_number: u32, limit: Option<usize>) -> Result<Stream<'s>>;
}

fn header_matches<const N: usize>(actual: &[u8], expected: &[u8; N]) -> bool {
    actual.len() >= expected.len() && &actual[0..expected.len()] == expected
}

pub fn open_msf<'s, S: Source<'s> + 's>(mut source: S) -> Result<Box<dyn Msf<'s, S> + 's>> {
    // map the header
    let mut header_location = PageList::new(4096);
    header_location.push(0);
    let header_view = match view(&mut source, &header_location) {
        Ok(view) => view,
        Err(e) => match e {
            Error::IoError(x) => {
                if x.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(Error::UnrecognizedFileFormat);
                } else {
                    return Err(Error::IoError(x));
                }
            }
            _ => return Err(e),
        },
    };

    // see if it's a BigMSF
    if header_matches(header_view.as_slice(), big::MAGIC) {
        // claimed!
        let bigmsf = big::BigMSF::new(source, header_view)?;
        return Ok(Box::new(bigmsf));
    }


    // see if it's a SmallMSF
    if header_matches(header_view.as_slice(), small::MAGIC) {
        // claimed!
        let smallmsf = small::SmallMSF::new(source, header_view)?;
        return Ok(Box::new(smallmsf));
    }

    Err(Error::UnrecognizedFileFormat)
}

#[cfg(test)]
mod tests {
    mod header {
        use crate::common::Error;
        use crate::msf::open_msf;
        use crate::msf::Header;

        #[test]
        fn test_pages_needed_to_store() {
            let h = Header {
                page_size: 4096,
                maximum_valid_page_number: 15,
            };
            assert_eq!(h.pages_needed_to_store(0), 0);
            assert_eq!(h.pages_needed_to_store(1), 1);
            assert_eq!(h.pages_needed_to_store(1024), 1);
            assert_eq!(h.pages_needed_to_store(2048), 1);
            assert_eq!(h.pages_needed_to_store(4095), 1);
            assert_eq!(h.pages_needed_to_store(4096), 1);
            assert_eq!(h.pages_needed_to_store(4097), 2);
        }

        #[test]
        fn test_validate_page_number() {
            let h = Header {
                page_size: 4096,
                maximum_valid_page_number: 15,
            };
            assert!(matches!(
                h.validate_page_number(0),
                Err(Error::PageReferenceOutOfRange(0))
            ));
            assert!(matches!(h.validate_page_number(1), Ok(1)));
            assert!(matches!(h.validate_page_number(2), Ok(2)));
            assert!(matches!(h.validate_page_number(14), Ok(14)));
            assert!(matches!(h.validate_page_number(15), Ok(15)));
            assert!(matches!(
                h.validate_page_number(16),
                Err(Error::PageReferenceOutOfRange(16))
            ));
            assert!(matches!(
                h.validate_page_number(17),
                Err(Error::PageReferenceOutOfRange(17))
            ));
        }

        #[test]
        fn test_small_file_unrecognized_file_format() {
            let small_file = std::io::Cursor::new(b"\x7FELF");

            match open_msf(small_file) {
                Ok(_) => panic!("4 byte file should not parse as msf"),
                Err(e) => match e {
                    Error::UnrecognizedFileFormat => (),
                    _ => panic!("4 byte file should parse as unrecognized file format"),
                },
            };
        }
    }
}
