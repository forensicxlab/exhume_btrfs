use clap::*;
use clap_num::maybe_hex;
use exhume_body::{Body, BodySlice};
use exhume_btrfs::BtrfsFS;
use exhume_btrfs::key::FS_TREE_OBJECTID;
use log::{debug, error, info};
use serde_json::{Value, json};
use std::fs::File;
use std::io::Write;

fn main() {
    let matches = Command::new("exhume_btrfs")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Exhume artifacts from a Btrfs partition (read-only).")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true)
                .help("The path to the body to exhume."),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false)
                .help("The format of the file: 'auto' (default), 'raw', 'ewf', 'vmdk', 'qcow2', 'vhdx'..."),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The Btrfs partition starts at address (decimal or hex)."),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(true)
                .help("The size of the Btrfs partition in sectors (decimal or hex)."),
        )
        .arg(
            Arg::new("subvol")
                .long("subvol")
                .value_parser(maybe_hex::<u64>)
                .default_value("5")
                .help("Subvolume (tree) id that --inode refers to (default 5, the top level)."),
        )
        .arg(
            Arg::new("inode")
                .short('i')
                .long("inode")
                .value_parser(maybe_hex::<u64>)
                .help("Display the metadata about a specific inode number (>=256) of --subvol."),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .value_parser(value_parser!(String))
                .conflicts_with("inode")
                .help("Resolve an absolute path from the top-level subvolume instead of --inode."),
        )
        .arg(
            Arg::new("dir_entry")
                .short('d')
                .long("dir_entry")
                .action(ArgAction::SetTrue)
                .help("If the selected inode is a directory, list its entries."),
        )
        .arg(
            Arg::new("extents")
                .short('e')
                .long("extents")
                .action(ArgAction::SetTrue)
                .help("List the file extents of the selected inode."),
        )
        .arg(
            Arg::new("xattrs")
                .short('x')
                .long("xattrs")
                .action(ArgAction::SetTrue)
                .help("List the extended attributes of the selected inode."),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .action(ArgAction::SetTrue)
                .help("Dump the content of the selected inode to 'inode_<subvol>_<N>.bin'."),
        )
        .arg(
            Arg::new("superblock")
                .long("superblock")
                .action(ArgAction::SetTrue)
                .help("Display the superblock information."),
        )
        .arg(
            Arg::new("subvolumes")
                .long("subvolumes")
                .action(ArgAction::SetTrue)
                .help("List subvolumes and snapshots."),
        )
        .arg(
            Arg::new("chunks")
                .long("chunks")
                .action(ArgAction::SetTrue)
                .help("List the chunk (logical to physical) mapping."),
        )
        .arg(
            Arg::new("tolerate_bad_checksums")
                .long("tolerate-bad-checksums")
                .action(ArgAction::SetTrue)
                .help("Keep reading metadata blocks whose checksum does not match (salvage mode, logged)."),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output structures in JSON format."),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Set the log verbosity level"),
        )
        .get_matches();

    let log_level_str = matches.get_one::<String>("log_level").unwrap();
    let level_filter = match log_level_str.as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    let file_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let offset = *matches.get_one::<u64>("offset").unwrap();
    let size = *matches.get_one::<u64>("size").unwrap();
    let subvol = *matches
        .get_one::<u64>("subvol")
        .unwrap_or(&FS_TREE_OBJECTID);
    let inode_num = matches.get_one::<u64>("inode").copied();
    let path = matches.get_one::<String>("path").cloned();
    let json_output = matches.get_flag("json");

    let body = Body::new(file_path.to_owned(), format);
    debug!("Created Body from '{}'", file_path);
    let partition_size = size * body.get_sector_size() as u64;
    let slice = match BodySlice::new(&body, offset, partition_size) {
        Ok(s) => s,
        Err(e) => {
            error!("Could not create the partition slice: {e}");
            std::process::exit(1);
        }
    };
    let mut fs = match BtrfsFS::open(slice, matches.get_flag("tolerate_bad_checksums")) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Could not open the Btrfs filesystem: {e}");
            std::process::exit(1);
        }
    };

    if matches.get_flag("superblock") {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&fs.superblock.to_json()).unwrap()
            );
        } else {
            println!("{}", fs.superblock);
        }
    }

    if matches.get_flag("subvolumes") {
        if json_output {
            let arr: Vec<Value> = fs.subvolumes().iter().map(|s| s.to_json()).collect();
            println!("{}", serde_json::to_string_pretty(&json!(arr)).unwrap());
        } else {
            for s in fs.subvolumes() {
                println!(
                    "[{}] {:<10} {}{}{} uuid={} parent_uuid={} created={}",
                    s.id,
                    s.kind_name(),
                    s.path,
                    if s.readonly { " (ro)" } else { "" },
                    if s.is_default { " (default)" } else { "" },
                    s.uuid,
                    s.parent_uuid,
                    s.otime_h
                );
            }
        }
    }

    if matches.get_flag("chunks") {
        if json_output {
            let arr: Vec<Value> = fs.chunks().chunks().map(|c| c.to_json()).collect();
            println!("{}", serde_json::to_string_pretty(&json!(arr)).unwrap());
        } else {
            for c in fs.chunks().chunks() {
                let stripes: Vec<String> = c
                    .stripes
                    .iter()
                    .map(|s| format!("{}:{}", s.devid, s.offset))
                    .collect();
                println!(
                    "logical {:>14} length {:>12} {:<16} {:<7} stripes {}",
                    c.logical,
                    c.length,
                    c.kind_name(),
                    c.profile_name(),
                    stripes.join(" ")
                );
            }
        }
    }

    let inode = match (inode_num, path) {
        (Some(n), _) => match fs.get_inode(subvol, n) {
            Ok(i) => Some(i),
            Err(e) => {
                error!("Could not fetch inode {n} of subvolume {subvol}: {e}");
                std::process::exit(1);
            }
        },
        (None, Some(p)) => match fs.resolve_path(&p) {
            Ok(i) => Some(i),
            Err(e) => {
                error!("Could not resolve path {p:?}: {e}");
                std::process::exit(1);
            }
        },
        (None, None) => None,
    };

    let Some(inode) = inode else {
        return;
    };

    if matches.get_flag("dir_entry") {
        match fs.list_dir(&inode) {
            Ok(entries) => {
                if json_output {
                    let arr: Vec<Value> = entries.iter().map(|e| e.to_json()).collect();
                    println!("{}", serde_json::to_string_pretty(&json!(arr)).unwrap());
                } else {
                    info!(
                        "Directory listing for inode {} of subvolume {}:",
                        inode.ino, inode.tree_id
                    );
                    for e in entries {
                        println!("{e}");
                    }
                }
            }
            Err(e) => error!("Could not list the directory: {e}"),
        }
    } else if matches.get_flag("extents") {
        match fs.extents(&inode) {
            Ok(extents) => {
                if json_output {
                    let arr: Vec<Value> = extents.iter().map(|e| e.to_json()).collect();
                    println!("{}", serde_json::to_string_pretty(&json!(arr)).unwrap());
                } else {
                    for e in extents {
                        println!("{}", serde_json::to_string(&e.to_json()).unwrap());
                    }
                }
            }
            Err(e) => error!("Could not list the extents: {e}"),
        }
    } else if matches.get_flag("xattrs") {
        match fs.xattrs(&inode) {
            Ok(xattrs) => {
                if json_output {
                    let arr: Vec<Value> = xattrs.iter().map(|x| x.to_json()).collect();
                    println!("{}", serde_json::to_string_pretty(&json!(arr)).unwrap());
                } else {
                    for x in xattrs {
                        println!("{} = {:?}", x.name, String::from_utf8_lossy(&x.value));
                    }
                }
            }
            Err(e) => error!("Could not list the extended attributes: {e}"),
        }
    } else if json_output {
        let mut value = inode.to_json();
        if let Value::Object(map) = &mut value {
            if let Ok(p) = fs.inode_path(inode.tree_id, inode.ino) {
                map.insert("path".into(), json!(p));
            }
            if inode.is_symlink()
                && let Ok(target) = fs.read_symlink(&inode)
            {
                map.insert("symlink_target".into(), json!(target));
            }
        }
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        println!("{inode}");
        if let Ok(p) = fs.inode_path(inode.tree_id, inode.ino) {
            println!("Path: {p}");
        }
        if inode.is_symlink()
            && let Ok(target) = fs.read_symlink(&inode)
        {
            println!("Symlink target: {target}");
        }
    }

    if matches.get_flag("dump") {
        match fs.read_inode(&inode) {
            Ok(data) => {
                let filename = format!("inode_{}_{}.bin", inode.tree_id, inode.ino);
                match File::create(&filename).and_then(|mut f| f.write_all(&data)) {
                    Ok(()) => info!("Dumped {} bytes to {filename}", data.len()),
                    Err(e) => error!("Could not write {filename}: {e}"),
                }
            }
            Err(e) => error!("Could not read the inode content: {e}"),
        }
    }
}
