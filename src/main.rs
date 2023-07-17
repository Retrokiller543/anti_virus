use std::collections::HashMap;
use std::fs;
use std::io::Write;
use walkdir::WalkDir;

pub struct FileCompare {
    database: HashMap<String, String>,
    risk_files: HashMap<String, String>,
}

impl FileCompare {
    pub fn new(database_path: &str) -> FileCompare {
        let mut file_compare = FileCompare {
            database: HashMap::new(),
            risk_files: HashMap::new(),
        };
        file_compare.read_signatures(database_path);
        file_compare
    }

    fn read_signatures(&mut self, path: &str) {
        let data = fs::read_to_string(path)
            .expect("Unable to read file");
        for line in data.lines() {
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() == 2 {
                self.database.insert(parts[0].to_string(), parts[1].to_string());
            }
        }
    }

    pub fn compare(&mut self, path: &str) {
        let file_bytes = fs::read(path).expect("Unable to read file");
        for (name, signature) in &self.database {
            let signature_bytes = hex::decode(signature).expect("Invalid hex in signature");
            if file_bytes.starts_with(&signature_bytes) {
                self.risk_files.insert(path.to_string(), name.to_string());
                break;
            }
        }
    }

    pub fn get_database(&self) -> &HashMap<String, String> {
        &self.database
    }

    pub fn get_risk_files(&self) -> &HashMap<String, String> {
        &self.risk_files
    }

    pub fn write_to_log(&self, path: &str) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)  // This will create the file if it doesn't exist
            .open(path)
            .unwrap();
        for (file_path, virus_name) in &self.risk_files {
            writeln!(file, "{} - {}", file_path, virus_name).expect("Couldn't write to log file");
        }
    }
}

pub struct RecFileSearch {
    directory: String,
    found_files: Vec<String>,
    found_dirs: Vec<String>,
    tester: FileCompare,
}

impl RecFileSearch {
    pub fn new(directory: String, tester: FileCompare) -> RecFileSearch {
        RecFileSearch {
            directory,
            found_files: Vec::new(),
            found_dirs: Vec::new(),
            tester,
        }
    }

    pub fn start(&mut self) {
        for entry in WalkDir::new(&self.directory) {
            let entry = entry.expect("Failed to read directory entry");
            if entry.file_type().is_dir() {
                self.found_dirs.push(entry.path().to_string_lossy().into_owned());
            } else if entry.file_type().is_file() {
                let path = entry.path().to_string_lossy().into_owned();
                self.found_files.push(path.clone());
                self.tester.compare(&path);
            }
        }
        let path = format!("{}/dv1667.log", self.directory);
        self.tester.write_to_log(&path);
    }

    pub fn get_files(&self) -> &Vec<String> {
        &self.found_files
    }

    pub fn get_dirs(&self) -> &Vec<String> {
        &self.found_dirs
    }

    pub fn set_dir(&mut self, path: String) {
        self.directory = path;
    }
}

fn main() {
    let search_path = String::from("/mnt/General_Data/Dev/Rust/AntiVirus/Test_env/TestDir");
    let db_path = String::from("/mnt/General_Data/Dev/Rust/AntiVirus/Test_env/signatures.db");
    let comparer = FileCompare::new(&db_path);
    let mut secure_dir = RecFileSearch::new(search_path, comparer);
    secure_dir.start();
}
