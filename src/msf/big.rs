use super::*;

pub const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

/// The PDB header as stored on disk.
///
/// See the Microsoft code for reference: <https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/msf/msf.cpp#L946>
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RawHeader {
    magic: [u8; 32],
    page_size: u32,
    free_page_map: u32,
    pages_used: u32,
    directory_size: u32,
    _reserved: u32,
}

impl<'t> TryFromCtx<'t, Endian> for RawHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            magic: {
                let mut tmp = [0; 32];
                this.gread_inout_with(&mut offset, &mut tmp, le)?;
                tmp
            },
            page_size: this.gread_with(&mut offset, le)?,
            free_page_map: this.gread_with(&mut offset, le)?,
            pages_used: this.gread_with(&mut offset, le)?,
            directory_size: this.gread_with(&mut offset, le)?,
            _reserved: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

#[derive(Debug)]
pub struct BigMSF<'s, S> {
    header: Header,
    source: S,
    stream_table: StreamTable<'s>,
}

impl<'s, S: Source<'s>> BigMSF<'s, S> {
    fn read_page_list(hdr: &Header, size: usize, buf: &mut ParseBuffer) -> Result<PageList> {
        let pages = hdr.pages_needed_to_store(size);

        let mut page_list = PageList::new(hdr.page_size);
        for _ in 0..pages {
            let n = buf.parse_u32()?;
            page_list.push(hdr.validate_page_number(n as u32)?);
        }
        page_list.truncate(size);

        Ok(page_list)
    }

    pub fn new(source: S, header_view: Box<dyn SourceView<'_>>) -> Result<BigMSF<'s, S>> {
        let mut buf = ParseBuffer::from(header_view.as_slice());
        let header: RawHeader = buf.parse()?;

        if &header.magic != MAGIC {
            return Err(Error::UnrecognizedFileFormat);
        }

        if !header.page_size.is_power_of_two()
            || header.page_size < 0x100
            || header.page_size > (128 * 0x10000)
        {
            return Err(Error::InvalidPageSize(header.page_size));
        }

        let header_object = Header {
            page_size: header.page_size as usize,
            maximum_valid_page_number: header.pages_used,
        };

        // calculate how many pages are needed to store the stream table
        let size_of_stream_table_in_pages =
            header_object.pages_needed_to_store(header.directory_size as usize);

        let stream_table_page_list_page_list =
            Self::read_page_list(&header_object, size_of_stream_table_in_pages * 4, &mut buf)?;

        Ok(BigMSF {
            header: header_object,
            source,
            stream_table: StreamTable::HeaderOnly {
                size_in_bytes: header.directory_size as usize,
                stream_table_location_location: stream_table_page_list_page_list,
            },
        })
    }

    fn find_stream_table(&mut self) -> Result<()> {
        let mut new_stream_table: Option<StreamTable<'_>> = None;

        if let StreamTable::HeaderOnly {
            size_in_bytes,
            ref stream_table_location_location,
        } = self.stream_table
        {
            // the header indicated we need to read size_in_pages page numbers from the
            // specified PageList.

            // ask to view the location location
            let location_location = view(&mut self.source, stream_table_location_location)?;

            // build a PageList
            let mut page_list = PageList::new(self.header.page_size);
            let mut buf = ParseBuffer::from(location_location.as_slice());
            while !buf.is_empty() {
                let n = buf.parse_u32()?;
                page_list.push(self.header.validate_page_number(n)?);
            }

            page_list.truncate(size_in_bytes);

            // remember what we learned
            new_stream_table = Some(StreamTable::TableFound {
                stream_table_location: page_list,
            });
        }

        if let Some(st) = new_stream_table {
            self.stream_table = st;
        }

        Ok(())
    }

    fn make_stream_table_available(&mut self) -> Result<()> {
        // do the initial read if we must
        if let StreamTable::HeaderOnly { .. } = self.stream_table {
            self.find_stream_table()?;
        }

        // do we need to map the stream table itself?
        let mut new_stream_table = None;
        if let StreamTable::TableFound {
            ref stream_table_location,
        } = self.stream_table
        {
            // ask the source to view it
            let stream_table_view = view(&mut self.source, stream_table_location)?;
            new_stream_table = Some(StreamTable::Available { stream_table_view });
        }

        if let Some(st) = new_stream_table {
            self.stream_table = st;
        }

        // stream table is available
        assert!(matches!(self.stream_table, StreamTable::Available { .. }));

        Ok(())
    }

    fn look_up_stream(&mut self, stream_number: u32) -> Result<PageList> {
        // ensure the stream table is available
        self.make_stream_table_available()?;

        let header = self.header;

        // declare the things we're going to find
        let bytes_in_stream: u32;
        let page_list: PageList;

        if let StreamTable::Available {
            ref stream_table_view,
        } = self.stream_table
        {
            let stream_table_slice = stream_table_view.as_slice();
            let mut stream_table = ParseBuffer::from(stream_table_slice);

            // the stream table is structured as:
            // stream_count
            // 0..stream_count: size of stream in bytes (0xffffffff indicating "stream does not exist")
            // stream 0: PageNumber
            // stream 1: PageNumber, PageNumber
            // stream 2: PageNumber, PageNumber, PageNumber, PageNumber, PageNumber
            // stream 3: PageNumber, PageNumber, PageNumber, PageNumber
            // (number of pages determined by number of bytes)

            let stream_count = stream_table.parse_u32()?;

            // check if we've already outworn our welcome
            if stream_number >= stream_count {
                return Err(Error::StreamNotFound(stream_number));
            }

            // we now have {stream_count} u32s describing the length of each stream

            // walk over the streams before the requested stream
            // we need to pay attention to how big each one is, since their page numbers come
            // before our page numbers in the stream table
            let mut page_numbers_to_skip: usize = 0;
            for _ in 0..stream_number {
                let bytes = stream_table.parse_u32()?;
                if bytes == u32::max_value() {
                    // stream is not present, ergo nothing to skip
                } else {
                    page_numbers_to_skip += header.pages_needed_to_store(bytes as usize);
                }
            }

            // read our stream's size
            bytes_in_stream = stream_table.parse_u32()?;
            if bytes_in_stream == u32::max_value() {
                return Err(Error::StreamNotFound(stream_number));
            }
            let pages_in_stream = header.pages_needed_to_store(bytes_in_stream as usize);

            // skip the remaining streams' byte counts
            let _ = stream_table.take((stream_count - stream_number - 1) as usize * 4)?;

            // skip the preceding streams' page numbers
            let _ = stream_table.take((page_numbers_to_skip as usize) * 4)?;

            // we're now at the list of pages for our stream
            // accumulate them into a PageList
            let mut list = PageList::new(header.page_size);
            for _ in 0..pages_in_stream {
                let page_number = stream_table.parse_u32()?;
                list.push(self.header.validate_page_number(page_number)?);
            }

            // truncate to the size of the stream
            list.truncate(bytes_in_stream as usize);

            page_list = list;
        } else {
            unreachable!();
        }

        // done!
        Ok(page_list)
    }
}

impl<'s, S: Source<'s>> Msf<'s, S> for BigMSF<'s, S> {
    fn get(&mut self, stream_number: u32, limit: Option<usize>) -> Result<Stream<'s>> {
        // look up the stream
        let mut page_list = self.look_up_stream(stream_number)?;

        // apply any limits we have
        if let Some(limit) = limit {
            page_list.truncate(limit);
        }

        // now that we know where this stream lives, we can view it
        let view = view(&mut self.source, &page_list)?;

        // pack it into a Stream
        let stream = Stream { source_view: view };

        Ok(stream)
    }
}
