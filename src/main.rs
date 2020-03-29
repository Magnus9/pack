extern crate libc;
extern crate utime;
extern crate flate2;

use std::fs::{File, read_dir, create_dir};
use std::io::prelude::*;
use std::path::Path;
use std::env;
use std::io::{self, SeekFrom, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::time::UNIX_EPOCH;

use getopts::Options;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use flate2::Compression;
use flate2::write::{DeflateEncoder, DeflateDecoder};

const MAGIC_NUM:      &'static [u8] = &[0x50, 0x41, 0x43, 0x4b];
const SIZE_OF_HDR:    usize         = 28;
const HEADERS_OFFSET: u64           = 12;
const FTYPE_FILE:     u16           = 1 << 9;
const FTYPE_DIR:      u16           = 1 << 10;
const COMPRESS:       u16           = 1 << 11;
const PERM_BITS:      u16           = 0x1ff;

struct Pack {
    headers:   Vec<Fheader>,
    fname:     String,
    d_offset:  u64,
    matches:   getopts::Matches
}

impl Pack {
    pub fn new(fname: String, matches: getopts::Matches) -> Pack {
        Pack {
            headers:   Vec::new(),
            d_offset:  HEADERS_OFFSET,
            fname,
            matches
        }
    }

    fn cleanup(&mut self, error: io::Error)
    {
        eprintln!("{}", error);
        if self.matches.opt_present("p") {
            let fname = Path::new(&self.fname).file_name()
                .unwrap()
                .to_str()
                .unwrap();
            let path  = format!("{}.pack", fname);
            if Path::new(&path).exists() {
                std::fs::remove_dir(path).unwrap();
            }
        } else if self.matches.opt_present("u") {
            let header = self.headers.get(0);
            if let Some(hdr) = header {
                if Path::new(&hdr.apath).exists() {
                    std::fs::remove_dir(&hdr.apath).unwrap();
                }
            }
        }
    }

    fn run(&mut self, program: &String, opts: getopts::Options)
    {
        let retval = if self.matches.opt_present("p") {
            self.pack()
        } else if self.matches.opt_present("u") {
            self.unpack()
        } else if self.matches.opt_present("l") {
            self.list()
        } else {
            print_usage(program, opts);
            return;
        };
        if let Err(e) = retval {
            self.cleanup(e);
        }
    }

    fn compress(buf: &mut [u8]) -> io::Result<Vec<u8>>
    {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&buf)?;
        encoder.finish()
    }

    fn pack(&mut self) -> io::Result<()>
    {
        self.read_node();
        let fname = format!("{}.pack", Path::new(&self.fname)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap());
        let mut archive = File::create(&fname)?;
        archive.write_all(MAGIC_NUM)?;
        archive.write_u64::<NativeEndian>(self.d_offset)?;

        archive.seek(SeekFrom::Start(self.d_offset))?;
        for header in &mut self.headers {
            let mut file = File::open(&header.fpath)?;
            if (header.flags & FTYPE_FILE) > 0 {
                let mut buf = vec![0; header.fsize as usize];
                file.read(&mut buf)?;
                if self.matches.opt_present("c") {
                    buf = Pack::compress(&mut buf)?;
                    // Update the header.fsize to the compressed dlen.
                    header.fsize = buf.len() as u64;
                }
                archive.write_all(&buf)?;
            }
        }
        archive.seek(SeekFrom::Start(HEADERS_OFFSET))?;
        for header in &mut self.headers {
            header.write(&mut archive)?;
        }
        Ok(())
    }

    fn decompress(&self, buf: &[u8]) -> io::Result<Vec<u8>>
    {
        let mut decoder = DeflateDecoder::new(Vec::new());
        decoder.write_all(buf)?;
        decoder.finish()
    }

    fn unpack(&mut self) -> io::Result<()>
    {
        let mut archive = self.open_archive()?; 
        let mut offset  = HEADERS_OFFSET;
        while offset < self.d_offset {
            let header = Fheader::new_from_archive(&mut archive)?;
            if (header.flags & FTYPE_DIR) > 0 {
                create_dir(&header.apath)?;
            }
            offset += (SIZE_OF_HDR + header.apath_len as usize) as u64;
            self.headers.push(header);
        }
        for header in self.headers.iter() {
            if (header.flags & FTYPE_FILE) > 0 {
                let mut buf = vec![0; header.fsize as usize];
                archive.read(&mut buf)?;
                if self.matches.opt_present("c") {
                    buf = self.decompress(&mut buf)?;
                }
                if self.matches.opt_present("v") {
                    println!("{}", header.apath);
                }
                let mut file = File::create(&header.apath)?;

                file.write_all(&mut buf)?;
                // Set the access and modified times.
                utime::set_file_times(&header.apath, header.modified,
                                      header.modified)?;
                // Set permissions on the file.
                let mut perm = file.metadata()
                    .unwrap()
                    .permissions();
                perm.set_mode((header.flags & PERM_BITS) as u32);
                file.set_permissions(perm)?;
            }
        }
        Ok(())
    }

    // List the contents of the archive on the terminal.
    fn list(&mut self) -> io::Result<()>
    {
        let mut archive = self.open_archive()?; 
        let mut offset  = HEADERS_OFFSET;
        while offset < self.d_offset {
            let header = Fheader::new_from_archive(&mut archive)?;
            println!("{}", header);
            // Increment the offset into the next header.
            offset += (SIZE_OF_HDR + header.apath_len as usize) as u64;
        }
        Ok(())
    }

    /*
     * Try to open the file and verify if the file
     * is an archive. This will increase the cursor
     * to the header section.
     */
    fn open_archive(&mut self) -> io::Result<File>
    {
        let mut archive = match File::open(&self.fname) {
            Ok(f)  => f,
            Err(e) => return Err(e)
        };
        // Check for the magic number.
        let mut magic = [0; 4];
        archive.read(&mut magic)?;
        let magic = match std::str::from_utf8(&magic) {
            Ok(s)  => s,
            Err(_) => {
                return Err(io::Error::new(ErrorKind::Other,
                           "not a pack archive"));
            }
        };
        if magic != "PACK" {
            return Err(io::Error::new(ErrorKind::Other,
                       "not a pack archive"));
        }
        // Save the location to the data segment.
        self.d_offset = archive.read_u64::<NativeEndian>()?;
        Ok(archive)
    }

    fn recurse_node(&mut self, node: &Path, index: usize)
    {
        for entry in read_dir(node).unwrap() {
            let path       = entry.unwrap().path();
            let mut header = Fheader::new_from_file(self, &path, index);
            if path.is_dir() {
                header.flags |= FTYPE_DIR;
                self.recurse_node(&path, index);
            } else if path.is_file() {
                header.flags |= FTYPE_FILE;
            } else {
                continue;
            }
            self.headers.push(header);
        }
    }

    fn read_node(&mut self)
    {
        let fname = self.fname.clone();
        let path  = Path::new(&fname);
        let lname = path.file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let index = fname.find(&lname).unwrap();
        /*
         * Read the root node into a header. If it is a
         * directory, recurse, otherwise add the leaf file node.
         */
        let mut header = Fheader::new_from_file(self, &path, index);
        if path.is_dir() {
            header.flags |= FTYPE_DIR;
            self.headers.push(header);
            self.recurse_node(&path, index);
        } else if path.is_file() {
            header.flags |= FTYPE_FILE;
            self.headers.push(header);
        }
        self.headers.sort();
    }
}

#[derive(Default, Debug, Ord, Eq, PartialEq, PartialOrd)]
struct Fheader {
    apath_len: u16,
    fsize:     u64,
    modified:  u64,
    // Holds the read, write, exec and filetype bits.
    flags:     u16,
    // Not in use, reserved.
    offset:    u64,
    // File path. Not used in the binary. Only used to open
    // the files when packing.
    fpath:     String,
    // Archive path. The actual path in the binary.
    apath:     String
}

impl std::fmt::Display for Fheader
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(f, "{} ({})", self.apath, calc_byteunits(self.fsize as f64))
    }
}

impl Fheader {
    fn new_from_archive(archive: &mut File) -> io::Result<Fheader>
    {
        let mut header: Fheader = Default::default();
        header.apath_len = archive.read_u16::<NativeEndian>()?;
        header.fsize     = archive.read_u64::<NativeEndian>()?;
        header.modified  = archive.read_u64::<NativeEndian>()?;
        header.flags     = archive.read_u16::<NativeEndian>()?;
        header.offset    = archive.read_u64::<NativeEndian>()?;
        let mut buf      = vec![0; header.apath_len as usize];
        archive.read(&mut buf)?;
        header.apath = match std::str::from_utf8(&buf) {
            Ok(s)  => String::from(s),
            Err(_) => {
                return Err(io::Error::new(ErrorKind::Other,
                           "Malformed header"));
            } 
        };
        Ok(header)
    }

    fn new_from_file(pack: &mut Pack, path: &Path, index: usize) -> Fheader
    {
        let metadata = path.metadata().unwrap();
        let mut header: Fheader = Default::default();
        header.fpath     = String::from(path.to_str().unwrap());
        header.apath     = String::from(&header.fpath[index..]);
        header.apath_len = header.apath.len() as u16;
        header.fsize     = metadata.len();
        header.modified  = metadata.modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        header.flags = metadata.permissions().mode() as u16;
        if pack.matches.opt_present("c") {
            header.flags |= COMPRESS;
        }
        // Increment the data segment offset.
        pack.d_offset += (header.apath_len + SIZE_OF_HDR as u16) as u64;

        header
    }

    fn write(&mut self, archive: &mut File) -> io::Result<()>
    {
        archive.write_u16::<NativeEndian>(self.apath_len)?;
        archive.write_u64::<NativeEndian>(self.fsize)?;
        archive.write_u64::<NativeEndian>(self.modified)?;
        archive.write_u16::<NativeEndian>(self.flags)?;
        archive.write_u64::<NativeEndian>(self.offset)?;
        archive.write_all(self.apath.as_bytes())
    }
}

fn calc_byteunits(fsize: f64) -> String
{
    let mut num = fsize / 1024.0 / 1024.0 / 1024.0 / 1024.0;
    if num >= 1.0 {
        return format!("{:.2}TB", num);
    }
    num = fsize / 1024.0 / 1024.0 / 1024.0;
    if num >= 1.0 {
        return format!("{:.2}GB", num);
    }
    num = fsize / 1024.0 / 1024.0;
    if num >= 1.0 {
        return format!("{:.2}MB", num);
    }
    num = fsize / 1024.0;
    format!("{:.2}KB", num)
}

fn print_usage(program: &String, opts: Options)
{
    let brief = format!("Usage: {} [options] FILE", program);
    print!("{}", opts.usage(&brief));
}

fn create_opts() -> getopts::Options
{
    let mut opts = Options::new();
    opts.optflag("p", "pack", "Create archive");
    opts.optflag("u", "unpack", "Unpack archive");
    opts.optflag("l", "list", "List archive");
    opts.optflag("c", "compression", "Compress/Decompress with DEFLATE");
    opts.optflag("v", "verbose", "Show verbose output");
    opts.optflag("h", "help", "Show help");
    opts
}

fn main()
{
    let args: Vec<String> = env::args().collect();
    let program  = &args[0];
    let opts     = create_opts();
    let matches  = match opts.parse(&args[1..]) {
        Ok(m)  => m,
        Err(e) => panic!(e.to_string())
    };
    let fname = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(program, opts);
        return;
    };
    if matches.opt_present("h") {
        print_usage(program, opts);
        return;
    }
    let mut pack = Pack::new(fname, matches);
    pack.run(program, opts);
}
