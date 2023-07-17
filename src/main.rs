use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write, BufWriter};
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;
use rayon::prelude::*;
use fnv::FnvHashMap;
use once_cell::sync::Lazy;
use crossbeam::channel;

pub struct FileCompare {
    database: FnvHashMap<String, String>,
    risk_files: FnvHashMap<String, String>,
}

impl FileCompare {
    pub fn new(database_path: &str) -> io::Result<FileCompare> {
        let mut file_compare = FileCompare {
            database: FnvHashMap::default(),
            risk_files: FnvHashMap::default(),
        };
        file_compare.read_signatures(database_path)?;
        Ok(file_compare)
    }

    fn read_signatures(&mut self, path: &str) -> io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() == 2 {
                self.database.insert(parts[0].to_string(), parts[1].to_string());
            }
        }
        Ok(())
    }

    pub fn compare(&mut self, path: &str) -> io::Result<()> {
        let file_bytes = fs::read(path)?;
        for (name, signature) in &self.database {
            let signature_bytes = hex::decode(signature).expect("Invalid hex in signature");
            if file_bytes.starts_with(&signature_bytes) {
                self.risk_files.insert(path.to_owned(), name.to_owned());
                break;
            }
        }
        Ok(())
    }

    pub fn get_database(&self) -> &FnvHashMap<String, String> {
        &self.database
    }

    pub fn get_risk_files(&self) -> &FnvHashMap<String, String> {
        &self.risk_files
    }

    pub fn log_risk_files(&self, directory: &str) -> io::Result<()> {
        let log_file = format!("{}/logs/risk_files.log", directory);
        let file = File::create(&log_file)?;
        let mut writer = BufWriter::new(file);
        for (path, name) in &self.risk_files {
            writeln!(writer, "Risky file: {} - Signature: {}", path, name)?;
        }
        Ok(())
    }
}

pub struct RecFileSearch {
    directory: Arc<str>,
    found_files: Arc<Mutex<Vec<Arc<str>>>>,
    found_dirs: Arc<Mutex<Vec<Arc<str>>>>,
    tester: Arc<Mutex<FileCompare>>,
}

impl RecFileSearch {
    pub fn new(directory: String, tester: FileCompare) -> RecFileSearch {
        RecFileSearch {
            directory: Arc::from(directory),
            found_files: Arc::new(Mutex::new(Vec::new())),
            found_dirs: Arc::new(Mutex::new(Vec::new())),
            tester: Arc::new(Mutex::new(tester)),
        }
    }

    pub fn start(&mut self) -> io::Result<Duration> {
        let start_time = Instant::now();
        let directory = Arc::clone(&self.directory);
        let found_files = Arc::clone(&self.found_files);
        let found_dirs = Arc::clone(&self.found_dirs);
        let tester = Arc::clone(&self.tester);
        WalkDir::new(&*directory).into_iter().par_bridge().for_each(move |entry| {
            let entry = entry.expect("Failed to read directory entry");
            if entry.file_type().is_dir() {
                let dir_path: Arc<str> = Arc::from(entry.path().to_string_lossy().into_owned());
                found_dirs.lock().unwrap().push(dir_path.clone());
                let dir_start_time = Instant::now();
                // Process directory contents recursively if needed
                // ...
                let dir_elapsed = dir_start_time.elapsed();
                write_to_log(&directory, &format!("Directory: {} - Time: {:?}", dir_path, dir_elapsed)).unwrap();
            } else if entry.file_type().is_file() {
                let file_path: Arc<str> = Arc::from(entry.path().to_string_lossy().into_owned());
                found_files.lock().unwrap().push(file_path.clone());
                let file_start_time = Instant::now();
                tester.lock().unwrap().compare(&file_path).unwrap();
                let file_elapsed = file_start_time.elapsed();
                write_to_log(&directory, &format!("File: {} - Time: {:?}", file_path, file_elapsed)).unwrap();
            }
        });
        let elapsed = start_time.elapsed();
        write_to_log(&self.directory, &format!("Total runtime: {:?}", elapsed))?;
        Ok(elapsed)
    }

    pub fn get_files(&self) -> &Arc<Mutex<Vec<Arc<str>>>> {
        &self.found_files
    }

    pub fn get_dirs(&self) -> &Arc<Mutex<Vec<Arc<str>>>> {
        &self.found_dirs
    }

    pub fn set_dir(&mut self, path: Arc<str>) {
        self.directory = path;
    }
}

static LOG_CHANNEL: Lazy<(channel::Sender<String>, channel::Receiver<String>)> = Lazy::new(|| {
    let (sender, receiver) = channel::unbounded();
    (sender, receiver)
});

fn start_logging_thread(directory: Arc<str>) {
    let (log_sender, log_receiver) = &*LOG_CHANNEL;
    let log_file = format!("{}/logs/performance.log", &*directory);
    let file = File::create(&log_file).unwrap();
    let mut writer = BufWriter::new(file);
    std::thread::spawn(move || {
        while let Ok(message) = log_receiver.recv() {
            writeln!(writer, "{}", message).unwrap();
        }
    });
}

pub fn write_to_log(directory: &Arc<str>, message: &str) -> io::Result<()> {
    let (log_sender, _) = &*LOG_CHANNEL;
    log_sender.send(format!("{}: {}", directory, message)).unwrap();
    Ok(())
}

fn main() -> io::Result<()> {
    let search_path = String::from("/mnt/General_Data/Dev/Rust/AntiVirus/Test_env");
    let db_path = String::from("/mnt/General_Data/Dev/Rust/AntiVirus/Test_env/signatures.db");
    let comparer = FileCompare::new(&db_path)?;
    let mut secure_dir = RecFileSearch::new(search_path, comparer);
    start_logging_thread(Arc::clone(&secure_dir.directory));
    let total_runtime = secure_dir.start()?;
    println!("Total runtime: {:?}", total_runtime);
    secure_dir.tester.lock().unwrap().log_risk_files(&secure_dir.directory)?;
    Ok(())
}
