use super::*;

pub const MAGIC: &[u8; 44] = b"Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47\0\0";

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RawHeader {
    magic: [u8; 44],
    page_size: u32,
    start_page: u16,
    pages_used: u16,
    directory_size: u32,
    _reserved: u32,
}

impl<'t> TryFromCtx<'t, Endian> for RawHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            magic: {
                let mut tmp = [0; 44];
                this.gread_inout_with(&mut offset, &mut tmp, le)?;
                tmp
            },
            page_size: this.gread_with(&mut offset, le)?,
            start_page: this.gread_with(&mut offset, le)?,
            pages_used: this.gread_with(&mut offset, le)?,
            directory_size: this.gread_with(&mut offset, le)?,
            _reserved: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

#[derive(Debug)]
pub struct SmallMSF<'s, S> {
    header: Header,
    source: S,
    stream_table: StreamTable<'s>,
}

impl<'s, S: Source<'s>> SmallMSF<'s, S> {
    fn read_page_list(hdr: &Header, size: usize, buf: &mut ParseBuffer) -> Result<PageList> {
        let pages = hdr.pages_needed_to_store(size);

        let mut page_list = PageList::new(hdr.page_size);
        for _ in 0..pages {
            let n = buf.parse_u16()?;
            page_list.push(hdr.validate_page_number(n as u32)?);
        }
        page_list.truncate(size);

        Ok(page_list)
    }

    pub fn new(source: S, header_view: Box<dyn SourceView<'_>>) -> Result<SmallMSF<'s, S>> {
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
            maximum_valid_page_number: header.pages_used as u32,
        };

        let stream_table_location =
            Self::read_page_list(&header_object, header.directory_size as usize, &mut buf)?;

        Ok(Self {
            header: header_object,
            source,
            stream_table: StreamTable::TableFound {
                stream_table_location,
            },
        })
    }

    fn make_stream_table_available(&mut self) -> Result<()> {
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

            let stream_count = stream_table.parse_u16()? as u32;
            let _reserved = stream_table.parse_u16()?;

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
                let _reserved = stream_table.parse_u32()?;
                if bytes == u32::max_value() {
                    // stream is not present, ergo nothing to skip
                } else {
                    page_numbers_to_skip += header.pages_needed_to_store(bytes as usize);
                }
            }

            // read our stream's size
            bytes_in_stream = stream_table.parse_u32()?;
            let _reserved = stream_table.parse_u32()?;
            if bytes_in_stream == u32::max_value() {
                return Err(Error::StreamNotFound(stream_number));
            }

            // skip the remaining streams' byte counts
            let _ = stream_table.take((stream_count - stream_number - 1) as usize * 8)?;

            // skip the preceding streams' page numbers
            let _ = stream_table.take((page_numbers_to_skip as usize) * 2)?;

            page_list =
                Self::read_page_list(&self.header, bytes_in_stream as usize, &mut stream_table)?;
        } else {
            unreachable!();
        }

        // done!
        Ok(page_list)
    }
}

impl<'s, S: Source<'s>> Msf<'s, S> for SmallMSF<'s, S> {
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
