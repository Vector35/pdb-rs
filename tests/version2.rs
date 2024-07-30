use std::fs::File;

use fallible_iterator::FallibleIterator;

fn setup<F>(func: F)
where
    F: FnOnce(&mut pdb::PDB<File>),
{
    let file = if let Ok(filename) = std::env::var("PDB_FILE") {
        std::fs::File::open(filename)
    } else {
        unimplemented!("Set a file via the PDB_FILE environment variable");
    }
    
    .expect("opening file");

    let mut pdb = pdb::PDB::open(file).expect("opening pdb");
    func(&mut pdb);
}

#[test]
fn version2_parse() {
    setup(|pdb| {
        let pdb_info = pdb.pdb_information().unwrap();
        dbg!(&pdb_info);
        /*let stream_names = pdb_info.stream_names().unwrap();
        for name in stream_names.into_iter() {
            dbg!(&name);
        
        }*/

        let sym = pdb.global_symbols().unwrap();
        let mut iter = sym.iter();
        while let Ok(Some(symbol)) = iter.next() {
            println!("{:?}", symbol.parse());
        }

        let tpes = pdb.type_information().unwrap();
        let mut iter = tpes.iter();
        while let Ok(Some(typ)) = iter.next() {
            println!("{:?}", typ.parse());
        }
    });

}