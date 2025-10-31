#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, ErrorKind};
use std::fs::{File, create_dir_all};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};
use chrono::Local;
use std::sync::atomic::{AtomicBool, Ordering};
use dirs;

/// Tipo personalizzato per gestione errori
type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Configurazione persistente dell'app
#[derive(Serialize, Deserialize, Clone)]
struct AppConfig {
    last_server_port: String,
    last_client_ip: String,
    last_client_port: String,
    encryption_enabled: bool,
    download_folder: String,
    auto_extract_zip: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let download_folder = get_app_data_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "LanBeam".to_string());

        Self {
            last_server_port: "8080".to_string(),
            last_client_ip: "".to_string(),
            last_client_port: "8080".to_string(),
            encryption_enabled: false,
            download_folder,
            auto_extract_zip: true,
        }
    }
}

/// File condiviso
#[derive(Clone)]
struct SharedFile {
    name: String,
    path: PathBuf,
    size: u64,
    encrypted: bool,
    is_archive: bool,
}

/// Stato del trasferimento
#[derive(Clone, PartialEq)]
enum TransferState {
    Queued,
    Transferring,
    Paused,
    Completed,
    Cancelled,
    Error(String),
    Extracting(f32), // Ora include il progresso dell'estrazione
}

/// Trasferimento
#[derive(Clone)]
struct Transfer {
    filename: String,
    size: u64,
    progress: f32,
    state: TransferState,
    cancel_flag: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
    start_time: std::time::Instant,
    is_archive: bool,
    extracted_files: Vec<String>,
    extract_progress: f32, // Progresso separato per l'estrazione
}

/// Modalità app
#[derive(PartialEq)]
enum AppMode {
    Share,
    Download,
}

impl Default for AppMode {
    fn default() -> Self { AppMode::Share }
}

/// App principale
struct FileTransferApp {
    mode: AppMode,
    config: AppConfig,

    // Server
    server_port: String,
    server_status: Arc<Mutex<String>>,
    server_running: Arc<AtomicBool>,
    server_password: String,
    server_encryption_enabled: bool,
    server_shared_files: Arc<Mutex<Vec<SharedFile>>>,
    server_transfers: Arc<Mutex<Vec<Transfer>>>,

    // Client
    client_ip: String,
    client_port: String,
    client_password: String,
    client_encryption_enabled: bool,
    client_available_files: Arc<Mutex<Vec<SharedFile>>>,
    client_status: String,
    client_transfers: Arc<Mutex<Vec<Transfer>>>,
    client_queue: Arc<Mutex<VecDeque<String>>>,

    received_files: Arc<Mutex<Vec<String>>>,
    errors: Arc<Mutex<Vec<String>>>,
    auto_extract_zip: bool,
}

impl Default for FileTransferApp {
    fn default() -> Self {
        let config = Self::load_config().unwrap_or_default();
        
        Self {
            mode: AppMode::Share,
            config: config.clone(),

            server_port: config.last_server_port,
            server_status: Arc::new(Mutex::new("Server fermo".to_string())),
            server_running: Arc::new(AtomicBool::new(false)),
            server_password: String::new(),
            server_encryption_enabled: config.encryption_enabled,
            server_shared_files: Arc::new(Mutex::new(Vec::new())),
            server_transfers: Arc::new(Mutex::new(Vec::new())),

            client_ip: config.last_client_ip,
            client_port: config.last_client_port,
            client_password: String::new(),
            client_encryption_enabled: config.encryption_enabled,
            client_available_files: Arc::new(Mutex::new(Vec::new())),
            client_status: String::new(),
            client_transfers: Arc::new(Mutex::new(Vec::new())),
            client_queue: Arc::new(Mutex::new(VecDeque::new())),

            received_files: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            auto_extract_zip: config.auto_extract_zip,
        }
    }
}

// --- Costanti e helper functions ---
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);
const BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Estensioni supportate per archivi
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "rar", "7z", "tar", "gz", "bz2"];

/// Ottiene la directory dell'applicazione (stessa per downloads, config e log)
fn get_app_data_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|mut path| {
        path.push("LanBeam");
        path
    })
}

/// Log eventi
fn log_event(message: &str) {
    println!("{}", message);
    if let Some(app_dir) = get_app_data_dir() {
        let log_file = app_dir.join("lanbeam.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file) 
        {
            let _ = writeln!(file, "{}: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), message);
        }
    }
}

/// Gestione errori IO
fn handle_io_error(e: std::io::Error, context: &str) -> std::io::Error {
    let error_msg = format!("Errore IO in {}: {}", context, e);
    log_event(&error_msg);
    std::io::Error::new(e.kind(), error_msg)
}

/// Scrittura su socket con gestione errori non-bloccanti
fn write_all_with_retry(stream: &mut TcpStream, data: &[u8], cancel_flag: &AtomicBool) -> std::io::Result<()> {
    let mut total_written = 0;
    
    while total_written < data.len() {
        if cancel_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(ErrorKind::Interrupted, "Operazione annullata"));
        }
        
        match stream.write(&data[total_written..]) {
            Ok(0) => {
                return Err(std::io::Error::new(ErrorKind::WriteZero, "Scrittura di 0 byte"));
            }
            Ok(n) => {
                total_written += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    
    Ok(())
}

/// Lettura da socket con gestione errori non-bloccanti
fn read_exact_with_retry(stream: &mut TcpStream, buf: &mut [u8], cancel_flag: &AtomicBool) -> std::io::Result<()> {
    let mut total_read = 0;
    
    while total_read < buf.len() {
        if cancel_flag.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(ErrorKind::Interrupted, "Operazione annullata"));
        }
        
        match stream.read(&mut buf[total_read..]) {
            Ok(0) => {
                return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "Connessione chiusa"));
            }
            Ok(n) => {
                total_read += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    
    Ok(())
}

/// Icona per stato trasferimento
fn state_icon(state: &TransferState) -> &'static str {
    match state {
        TransferState::Queued => "⏳",
        TransferState::Transferring => "📤",
        TransferState::Paused => "⏸️",
        TransferState::Completed => "✅",
        TransferState::Cancelled => "❌",
        TransferState::Error(_) => "⚠️",
        TransferState::Extracting(_) => "📦",
    }
}

/// Abbrevia nome file
fn abbreviate_filename(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        let half = (max_len - 3) / 2;
        format!("{}...{}", &name[..half], &name[name.len()-half..])
    }
}

/// Formatta dimensione file
fn format_file_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let size_f64 = size as f64;

    if size_f64 < KB {
        format!("{} B", size)
    } else if size_f64 < MB {
        format!("{:.2} KB", size_f64 / KB)
    } else if size_f64 < GB {
        format!("{:.2} MB", size_f64 / MB)
    } else {
        format!("{:.2} GB", size_f64 / GB)
    }
}

/// Calcola velocità trasferimento
fn format_transfer_speed(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;

    if bytes_per_sec < KB {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < MB {
        format!("{:.1} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.1} MB/s", bytes_per_sec / MB)
    }
}

/// Controlla dimensione file
fn check_file_size(size: u64) -> Result<(), String> {
    if size > MAX_FILE_SIZE {
        Err(format!("File troppo grande (max {} GB)", MAX_FILE_SIZE / 1024 / 1024 / 1024))
    } else {
        Ok(())
    }
}

/// Verifica se un file è un archivio
fn is_archive_file(filename: &str) -> bool {
    if let Some(ext) = Path::new(filename).extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        ARCHIVE_EXTENSIONS.iter().any(|&archive_ext| archive_ext == ext_str)
    } else {
        false
    }
}

/// Estrai archivio ZIP con progresso
fn extract_zip_file_with_progress(
    zip_path: &Path, 
    extract_to: &Path, 
    progress_callback: impl Fn(f32) -> bool
) -> AppResult<Vec<String>> {
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    
    let total_files = archive.len();
    let mut extracted_files = Vec::new();
    let mut processed_files = 0;
    
    for i in 0..total_files {
        let mut file = archive.by_index(i)?;
        let outpath = extract_to.join(file.mangled_name());
        
        if file.name().ends_with('/') {
            create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
            extracted_files.push(outpath.to_string_lossy().into_owned());
        }
        
        processed_files += 1;
        let progress = (processed_files as f32 / total_files as f32) * 100.0;
        
        // Chiama il callback e controlla se continuare
        if !progress_callback(progress) {
            return Err(std::io::Error::new(ErrorKind::Interrupted, "Estrazione annullata").into());
        }
    }
    
    Ok(extracted_files)
}

/// Crittografia
fn encrypt_data(data: &[u8], password: &str) -> AppResult<Vec<u8>> {
    if password.is_empty() {
        return Ok(data.to_vec());
    }
    
    let key = derive_key(password);
    Ok(xor_encrypt_decrypt(data, &key))
}

fn decrypt_data(data: &[u8], password: &str) -> AppResult<Vec<u8>> {
    if password.is_empty() {
        return Ok(data.to_vec());
    }
    
    let key = derive_key(password);
    Ok(xor_encrypt_decrypt(data, &key))
}

fn derive_key(password: &str) -> String {
    format!("{:x}", md5::compute(password.as_bytes()))
}

fn xor_encrypt_decrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return data.to_vec();
    }

    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}

/// Connessione con timeout
fn connect_with_timeout(addr: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    TcpStream::connect_timeout(&addr.parse().unwrap(), timeout)
}

/// Ottiene IP locale
fn get_local_ip() -> Result<String, std::io::Error> {
    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    if udp_socket.connect("8.8.8.8:80").is_err() {
        return Ok("nessuna rete".to_string());
    }
    let ip = udp_socket.local_addr()?.ip().to_string();
    if ip == "0.0.0.0" || ip == "::" {
        Ok("nessuna rete".to_string())
    } else {
        Ok(ip)
    }
}

/// Raccoglie file ricorsivamente
fn collect_files_recursive(base: &Path, current: &Path, out: &mut Vec<(String, PathBuf, u64)>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files_recursive(base, &path, out)?;
        } else if metadata.is_file() {
            if let Err(e) = check_file_size(metadata.len()) {
                log_event(&format!("File saltato {}: {}", path.display(), e));
                continue;
            }
            
            let rel = path.strip_prefix(base)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| path.file_name().unwrap().to_string_lossy().into_owned());
            out.push((rel, path.clone(), metadata.len()));
        }
    }
    Ok(())
}

// --- Implementazione App ---
impl FileTransferApp {
    fn load_config() -> AppResult<AppConfig> {
        if let Some(app_dir) = get_app_data_dir() {
            let config_file = app_dir.join("lanbeam_config.json");
            if let Ok(content) = std::fs::read_to_string(config_file) {
                return Ok(serde_json::from_str(&content)?);
            }
        }
        Ok(AppConfig::default())
    }

    fn save_config(&self) {
        let config = AppConfig {
            last_server_port: self.server_port.clone(),
            last_client_ip: self.client_ip.clone(),
            last_client_port: self.client_port.clone(),
            encryption_enabled: self.server_encryption_enabled,
            download_folder: self.config.download_folder.clone(),
            auto_extract_zip: self.auto_extract_zip,
        };
        
        if let Some(app_dir) = get_app_data_dir() {
            let config_file = app_dir.join("lanbeam_config.json");
            if let Ok(content) = serde_json::to_string_pretty(&config) {
                let _ = std::fs::write(config_file, content);
            }
        }
    }

    fn add_error(&self, error: String) {
        log_event(&error);
        self.errors.lock().unwrap().push(error);
    }

    fn show_errors(&self, ctx: &egui::Context) {
        let mut errors = self.errors.lock().unwrap();
        if !errors.is_empty() {
            egui::Window::new("Errori")
                .collapsible(true)
                .resizable(true)
                .default_width(400.0)
                .show(ctx, |ui| {
                    for error in errors.iter() {
                        ui.label(error);
                    }
                    ui.separator();
                    if ui.button("Pulisci Errori").clicked() {
                        errors.clear();
                    }
                });
        }
    }

    fn add_file_to_share(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Err(e) = check_file_size(metadata.len()) {
                    self.add_error(e);
                    return;
                }
                
                let filename = path.file_name().unwrap().to_str().unwrap().to_string();
                let is_archive = is_archive_file(&filename);
                
                let file = SharedFile {
                    name: filename,
                    path: path.clone(),
                    size: metadata.len(),
                    encrypted: self.server_encryption_enabled,
                    is_archive,
                };
                self.server_shared_files.lock().unwrap().push(file);
                log_event(&format!("File aggiunto: {} {}", path.display(), if is_archive { "(archivio)" } else { "" }));
            }
        }
    }

    fn add_folder_to_share(&mut self) {
        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
            let base = folder.clone();
            let mut collected = Vec::new();
            if let Err(e) = collect_files_recursive(&base, &base, &mut collected) {
                self.add_error(format!("Errore lettura cartella: {}", e));
                return;
            }
            
            let encrypted = self.server_encryption_enabled;
            let mut list = self.server_shared_files.lock().unwrap();
            for (rel_name, abs_path, size) in collected {
                let rel_name = rel_name.replace("\\", "/");
                let is_archive = is_archive_file(&rel_name);
                
                list.push(SharedFile {
                    name: rel_name,
                    path: abs_path,
                    size,
                    encrypted,
                    is_archive,
                });
            }
            log_event(&format!("Cartella aggiunta: {} ({} file)", folder.display(), list.len()));
        }
    }

    fn start_server(&mut self) {
        let port = self.server_port.parse::<u16>().unwrap_or(8080);
        let status = Arc::clone(&self.server_status);
        let running = Arc::clone(&self.server_running);
        let shared_files = Arc::clone(&self.server_shared_files);
        let transfers = Arc::clone(&self.server_transfers);
        let password = if self.server_encryption_enabled {
            Some(self.server_password.clone())
        } else { None };

        running.store(true, Ordering::SeqCst);
        *status.lock().unwrap() = format!(
            "Server in ascolto sulla porta {} {}",
            port,
            if password.is_some() { "🔒" } else { "" }
        );

        thread::spawn(move || {
            if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{}", port)) {
                listener.set_nonblocking(true).unwrap();
                
                while running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            log_event(&format!("Nuova connessione da {}", addr));
                            
                            let status_clone = Arc::clone(&status);
                            let files_clone = Arc::clone(&shared_files);
                            let transfers_clone = Arc::clone(&transfers);
                            let pwd = password.clone();

                            thread::spawn(move || {
                                if let Err(e) = handle_client(stream, status_clone, files_clone, transfers_clone, pwd) {
                                    log_event(&format!("Errore gestione client: {}", e));
                                }
                            });
                        },
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(100));
                        },
                        Err(e) => {
                            log_event(&format!("Errore accettazione connessione: {}", e));
                        }
                    }
                }
            } else {
                *status.lock().unwrap() = format!("Impossibile avviare il server sulla porta {}", port);
            }
        });
        
        log_event(&format!("Server avviato sulla porta {}", port));
    }

    fn stop_server(&mut self) {
        let mut transfers = self.server_transfers.lock().unwrap();
        for transfer in transfers.iter_mut() {
            if transfer.state == TransferState::Transferring || matches!(transfer.state, TransferState::Extracting(_)) || transfer.state == TransferState::Paused {
                transfer.cancel_flag.store(true, Ordering::SeqCst);
                transfer.state = TransferState::Cancelled;
            }
        }
        drop(transfers);

        self.server_running.store(false, Ordering::SeqCst);
        *self.server_status.lock().unwrap() = "Server fermato".to_string();
        log_event("Server fermato");
    }

    fn request_file_list(&mut self) {
        let ip = self.client_ip.clone();
        let port = self.client_port.clone();
        let available = Arc::clone(&self.client_available_files);
        let error_handler = Arc::clone(&self.errors);

        self.client_status = "Richiesta lista file...".to_string();

        thread::spawn(move || {
            match connect_with_timeout(&format!("{}:{}", ip, port), TRANSFER_TIMEOUT) {
                Ok(mut stream) => {
                    if let Err(e) = stream.set_nonblocking(false) {
                        error_handler.lock().unwrap().push(format!("Errore configurazione socket: {}", e));
                        return;
                    }
                    
                    match get_file_list(&mut stream) {
                        Ok(files) => {
                            *available.lock().unwrap() = files;
                        },
                        Err(e) => {
                            error_handler.lock().unwrap().push(format!("Errore recupero lista: {}", e));
                        }
                    }
                },
                Err(e) => {
                    error_handler.lock().unwrap().push(format!("Connessione fallita: {}", e));
                }
            }
        });
    }

    fn download_file(&mut self, filename: String) {
        if self.client_encryption_enabled && self.client_password.is_empty() {
            self.client_status = "Errore: inserisci una password".to_string();
            return;
        }

        let mut file_path = PathBuf::from(&self.config.download_folder).join(&filename);
		file_path.push("downloads");
        if file_path.exists() {
            self.client_status = format!("File {} già presente", filename);
            return;
        }

        self.client_queue.lock().unwrap().push_back(filename.clone());

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let pause_flag = Arc::new(AtomicBool::new(false));

        let is_archive = is_archive_file(&filename);
        let size = self.client_available_files.lock().unwrap()
            .iter()
            .find(|f| f.name == filename)
            .map(|f| f.size)
            .unwrap_or(0);

        let transfer = Transfer {
            filename: filename.clone(),
            size,
            progress: 0.0,
            state: TransferState::Queued,
            cancel_flag: Arc::clone(&cancel_flag),
            pause_flag: Arc::clone(&pause_flag),
            start_time: std::time::Instant::now(),
            is_archive,
            extracted_files: Vec::new(),
            extract_progress: 0.0,
        };

        self.client_transfers.lock().unwrap().push(transfer);

        let active_count = self.client_transfers.lock().unwrap()
            .iter()
            .filter(|t| t.state == TransferState::Transferring)
            .count();

        if active_count == 0 {
            self.process_download_queue();
        }
        
        log_event(&format!("File aggiunto alla coda: {} {}", filename, if is_archive { "(archivio)" } else { "" }));
    }

    fn process_download_queue(&mut self) {
        let queue = Arc::clone(&self.client_queue);
        let transfers = Arc::clone(&self.client_transfers);
        let received = Arc::clone(&self.received_files);
        let errors = Arc::clone(&self.errors);
        let ip = self.client_ip.clone();
        let port = self.client_port.clone();
        let download_folder = self.config.download_folder.clone();
        let password = if self.client_encryption_enabled {
            Some(self.client_password.clone())
        } else { None };
        let auto_extract = self.auto_extract_zip;

        thread::spawn(move || {
            loop {
                let next_file = queue.lock().unwrap().pop_front();

                if let Some(filename) = next_file {
                    let transfer_idx = {
                        let mut transfers_lock = transfers.lock().unwrap();
                        if let Some(idx) = transfers_lock.iter().position(|t| t.filename == filename && t.state == TransferState::Queued) {
                            if let Some(t) = transfers_lock.get_mut(idx) {
                                t.state = TransferState::Transferring;
                            }
                            Some(idx)
                        } else {
                            None
                        }
                    };

                    if let Some(idx) = transfer_idx {
                        match download_file_from_server(
                            &ip,
                            &port,
                            &filename,
                            password.clone(),
                            Arc::clone(&transfers),
                            idx,
                            &download_folder,
                            auto_extract,
                        ) {
                            Ok(extracted_files) => {
                                received.lock().unwrap().push(filename.clone());
                                if let Some(t) = transfers.lock().unwrap().get_mut(idx) {
                                    if !t.cancel_flag.load(Ordering::SeqCst) {
                                        t.state = TransferState::Completed;
                                        t.progress = 100.0;
                                        t.extracted_files = extracted_files;
                                        t.extract_progress = 100.0;
                                    }
                                }
                                log_event(&format!("Download completato: {}", filename));
                            },
                            Err(e) => {
                                if let Some(t) = transfers.lock().unwrap().get_mut(idx) {
                                    if !t.cancel_flag.load(Ordering::SeqCst) {
                                        t.state = TransferState::Error(e.to_string());
                                    }
                                }
                                errors.lock().unwrap().push(format!("Errore download {}: {}", filename, e));
                            }
                        }
                    }

                    thread::sleep(Duration::from_millis(500));
                } else {
                    break;
                }
            }
        });
    }

    fn download_all_files(&mut self) {
        let files = self.client_available_files.lock().unwrap().clone();
        for f in files {
            self.download_file(f.name);
        }
    }

    fn cancel_transfer(&mut self, idx: usize, is_server: bool) {
        let transfers = if is_server {
            &self.server_transfers
        } else {
            &self.client_transfers
        };

        if let Some(transfer) = transfers.lock().unwrap().get_mut(idx) {
            if !is_server && transfer.state == TransferState::Queued {
                let mut queue = self.client_queue.lock().unwrap();
                if let Some(pos) = queue.iter().position(|f| f == &transfer.filename) {
                    queue.remove(pos);
                }
            }

            transfer.cancel_flag.store(true, Ordering::SeqCst);
        }
    }

    fn pause_transfer(&mut self, idx: usize, is_server: bool) {
        let transfers = if is_server {
            &self.server_transfers
        } else {
            &self.client_transfers
        };

        if let Some(transfer) = transfers.lock().unwrap().get_mut(idx) {
            if transfer.state == TransferState::Transferring {
                transfer.pause_flag.store(true, Ordering::SeqCst);
                transfer.state = TransferState::Paused;
            }
        }
    }

    fn resume_transfer(&mut self, idx: usize, is_server: bool) {
        let transfers = if is_server {
            &self.server_transfers
        } else {
            &self.client_transfers
        };

        if let Some(transfer) = transfers.lock().unwrap().get_mut(idx) {
            if transfer.state == TransferState::Paused {
                transfer.pause_flag.store(false, Ordering::SeqCst);
                transfer.state = TransferState::Transferring;
            }
        }
    }

    fn clear_completed_transfers(&mut self, is_server: bool) {
        let transfers = if is_server {
            &self.server_transfers
        } else {
            &self.client_transfers
        };

        transfers.lock().unwrap().retain(|t| {
            !matches!(t.state, TransferState::Completed | TransferState::Cancelled | TransferState::Error(_))
        });
    }

    fn calculate_speed(&self, transfer: &Transfer) -> String {
        let elapsed = transfer.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let transferred = (transfer.progress / 100.0) * transfer.size as f32;
            format_transfer_speed(transferred as f64 / elapsed)
        } else {
            "Calcolo...".to_string()
        }
    }

    fn open_download_folder(&self) {
        let mut path = PathBuf::from(&self.config.download_folder);
		path.push("downloads");
        
        // Se il percorso non esiste, prova a crearlo
        if !path.exists() {
            if let Err(e) = create_dir_all(&path) {
                self.add_error(format!("Impossibile creare la cartella: {}", e));
                return;
            }
        }
        
        if let Err(e) = open::that(&path) {
            self.add_error(format!("Impossibile aprire la cartella: {}", e));
        }
    }
}

// --- Gestione client/server ---
fn handle_client(
    mut stream: TcpStream,
    status: Arc<Mutex<String>>,
    shared_files: Arc<Mutex<Vec<SharedFile>>>,
    transfers: Arc<Mutex<Vec<Transfer>>>,
    password: Option<String>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr()?;
    *status.lock().unwrap() = format!("Connessione da {}...", peer);

    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut cmd_buf = [0u8; 4];
    read_exact_with_retry(&mut stream, &mut cmd_buf, &AtomicBool::new(false))?;
    let cmd = String::from_utf8_lossy(&cmd_buf);

    if cmd == "LIST" {
        let files = shared_files.lock().unwrap();
        
        let count_bytes = (files.len() as u32).to_be_bytes();
        write_all_with_retry(&mut stream, &count_bytes, &AtomicBool::new(false))?;
        
        for f in files.iter() {
            let name_bytes = f.name.as_bytes();
            
            let name_len_bytes = (name_bytes.len() as u32).to_be_bytes();
            write_all_with_retry(&mut stream, &name_len_bytes, &AtomicBool::new(false))?;
            
            write_all_with_retry(&mut stream, name_bytes, &AtomicBool::new(false))?;
            
            let size_bytes = f.size.to_be_bytes();
            write_all_with_retry(&mut stream, &size_bytes, &AtomicBool::new(false))?;
            
            let encrypted_flag = if f.encrypted {1} else {0};
            let archive_flag = if f.is_archive {1} else {0};
            write_all_with_retry(&mut stream, &[encrypted_flag, archive_flag], &AtomicBool::new(false))?;
        }
        
        stream.flush()?;
        *status.lock().unwrap() = format!("Inviata lista a {}", peer);
        return Ok(());
    }

    if cmd == "DOWN" {
        let mut len_buf = [0u8; 4];
        read_exact_with_retry(&mut stream, &mut len_buf, &AtomicBool::new(false))?;
        let name_len = u32::from_be_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        read_exact_with_retry(&mut stream, &mut name_buf, &AtomicBool::new(false))?;
        let requested = String::from_utf8_lossy(&name_buf).to_string();

        let files = shared_files.lock().unwrap();
        let file_info = match files.iter().find(|f| f.name == requested) {
            Some(f) => f.clone(),
            None => {
                write_all_with_retry(&mut stream, b"NOTFOUND", &AtomicBool::new(false))?;
                return Ok(());
            }
        };
        drop(files);

        if file_info.encrypted && password.is_none() {
            write_all_with_retry(&mut stream, b"NEEDPASS", &AtomicBool::new(false))?;
            return Ok(());
        }

        write_all_with_retry(&mut stream, b"OK______", &AtomicBool::new(false))?;

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let pause_flag = Arc::new(AtomicBool::new(false));

        let transfer = Transfer {
            filename: requested.clone(),
            size: file_info.size,
            progress: 0.0,
            state: TransferState::Transferring,
            cancel_flag: Arc::clone(&cancel_flag),
            pause_flag: Arc::clone(&pause_flag),
            start_time: std::time::Instant::now(),
            is_archive: file_info.is_archive,
            extracted_files: Vec::new(),
            extract_progress: 0.0,
        };

        transfers.lock().unwrap().push(transfer.clone());
        let transfer_idx = transfers.lock().unwrap().len() - 1;

        let mut source_file = File::open(&file_info.path)?;
        
        let size_bytes = file_info.size.to_be_bytes();
        write_all_with_retry(&mut stream, &size_bytes, &cancel_flag)?;
        stream.flush()?;

        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut sent: u64 = 0;

        log_event(&format!("Invio file iniziato: {} ({} bytes) a {}", requested, file_info.size, peer));

        while sent < file_info.size {
            if cancel_flag.load(Ordering::SeqCst) {
                break;
            }

            while pause_flag.load(Ordering::SeqCst) {
                if cancel_flag.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            let remaining = file_info.size - sent;
            let to_send = std::cmp::min(buffer.len() as u64, remaining) as usize;

            let bytes_read = match source_file.read(&mut buffer[..to_send]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    log_event(&format!("Errore lettura file: {}", e));
                    break;
                }
            };

            if bytes_read == 0 {
                break;
            }

            let data = if let Some(ref pwd) = password {
                encrypt_data(&buffer[..bytes_read], pwd).unwrap_or_else(|_| buffer[..bytes_read].to_vec())
            } else {
                buffer[..bytes_read].to_vec()
            };

            if let Err(e) = write_all_with_retry(&mut stream, &data, &cancel_flag) {
                log_event(&format!("Errore invio dati: {}", e));
                break;
            }
            
            sent += bytes_read as u64;

            if let Some(t) = transfers.lock().unwrap().get_mut(transfer_idx) {
                t.progress = (sent as f64 / file_info.size as f64 * 100.0) as f32;
                
                let progress_percent = (sent * 100) / file_info.size;
                if progress_percent % 10 == 0 && progress_percent > 0 {
                    let last_logged = (t.progress as u64 / 10) * 10;
                    if progress_percent > last_logged {
                        log_event(&format!("Progresso {}: {}/{} bytes ({:.1}%)", 
                            requested, sent, file_info.size, t.progress));
                    }
                }
            }

            thread::sleep(Duration::from_millis(1));
        }

        stream.flush()?;

        if let Some(t) = transfers.lock().unwrap().get_mut(transfer_idx) {
            if cancel_flag.load(Ordering::SeqCst) {
                t.state = TransferState::Cancelled;
            } else if sent == file_info.size {
                t.state = TransferState::Completed;
                t.progress = 100.0;
                log_event(&format!("File inviato completato: {} ({} bytes)", requested, sent));
            } else {
                t.state = TransferState::Error("Trasferimento incompleto".to_string());
                log_event(&format!("File inviato incompleto: {} ({}/{} bytes)", requested, sent, file_info.size));
            }
        }

        *status.lock().unwrap() = format!("Inviato {} a {} ({}/{})", requested, peer, sent, file_info.size);
    }

    Ok(())
}

fn get_file_list(stream: &mut TcpStream) -> std::io::Result<Vec<SharedFile>> {
    write_all_with_retry(stream, b"LIST", &AtomicBool::new(false))?;
    stream.flush()?;

    let mut len_buf = [0u8; 4];
    read_exact_with_retry(stream, &mut len_buf, &AtomicBool::new(false))?;
    let count = u32::from_be_bytes(len_buf);

    let mut files = Vec::new();
    for _ in 0..count {
        read_exact_with_retry(stream, &mut len_buf, &AtomicBool::new(false))?;
        let name_len = u32::from_be_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        read_exact_with_retry(stream, &mut name_buf, &AtomicBool::new(false))?;
        let name = String::from_utf8_lossy(&name_buf).to_string();

        let mut size_buf = [0u8; 8];
        read_exact_with_retry(stream, &mut size_buf, &AtomicBool::new(false))?;
        let size = u64::from_be_bytes(size_buf);

        let mut flags = [0u8; 2];
        read_exact_with_retry(stream, &mut flags, &AtomicBool::new(false))?;
        let encrypted = flags[0] == 1;
        let is_archive = flags[1] == 1;

        files.push(SharedFile { name, path: PathBuf::new(), size, encrypted, is_archive });
    }

    Ok(files)
}

fn download_file_from_server(
    ip: &str,
    port: &str,
    filename: &str,
    password: Option<String>,
    transfers: Arc<Mutex<Vec<Transfer>>>,
    transfer_idx: usize,
    download_folder: &str,
    auto_extract: bool,
) -> std::io::Result<Vec<String>> {
    let mut stream = connect_with_timeout(&format!("{}:{}", ip, port), TRANSFER_TIMEOUT)?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(TRANSFER_TIMEOUT))?;
    stream.set_write_timeout(Some(TRANSFER_TIMEOUT))?;

    write_all_with_retry(&mut stream, b"DOWN", &AtomicBool::new(false))?;
    let name_bytes = filename.as_bytes();
    let name_len_bytes = (name_bytes.len() as u32).to_be_bytes();
    write_all_with_retry(&mut stream, &name_len_bytes, &AtomicBool::new(false))?;
    write_all_with_retry(&mut stream, name_bytes, &AtomicBool::new(false))?;
    stream.flush()?;

    let mut status_buf = [0u8; 8];
    read_exact_with_retry(&mut stream, &mut status_buf, &AtomicBool::new(false))?;
    let status_str = String::from_utf8_lossy(&status_buf);
    
    if status_str.starts_with("NOTFOUND") {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "File non trovato"));
    }
    if status_str.starts_with("NEEDPASS") {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Password richiesta"));
    }

    let mut size_buf = [0u8; 8];
    read_exact_with_retry(&mut stream, &mut size_buf, &AtomicBool::new(false))?;
    let total_size = u64::from_be_bytes(size_buf);

    let mut file_path = PathBuf::from(download_folder);
	file_path.push("downloads");
    let rel = Path::new(filename);
    for component in rel.components() {
        file_path.push(component.as_os_str());
    }

    if let Some(parent) = file_path.parent() {
        create_dir_all(parent)?;
    }
    let mut out_file = File::create(&file_path)?;

    let (cancel_flag, pause_flag) = {
        let transfers_lock = transfers.lock().unwrap();
        if let Some(t) = transfers_lock.get(transfer_idx) {
            (Arc::clone(&t.cancel_flag), Arc::clone(&t.pause_flag))
        } else {
            return Ok(Vec::new());
        }
    };

    let mut received: u64 = 0;
    let mut buffer = vec![0u8; BUFFER_SIZE];

    log_event(&format!("Download iniziato: {} ({} bytes)", filename, total_size));

    while received < total_size {
        if cancel_flag.load(Ordering::SeqCst) {
            drop(out_file);
            let _ = std::fs::remove_file(&file_path);
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Download annullato"));
        }

        while pause_flag.load(Ordering::SeqCst) {
            if cancel_flag.load(Ordering::SeqCst) {
                drop(out_file);
                let _ = std::fs::remove_file(&file_path);
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Download annullato"));
            }
            thread::sleep(Duration::from_millis(100));
        }

        let remaining = total_size - received;
        let to_read = std::cmp::min(buffer.len() as u64, remaining) as usize;

        let bytes_read = match stream.read(&mut buffer[..to_read]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => return Err(handle_io_error(e, "lettura da socket")),
        };

        if bytes_read == 0 {
            break;
        }

        let data = if let Some(ref pwd) = password {
            decrypt_data(&buffer[..bytes_read], pwd).unwrap_or_else(|_| buffer[..bytes_read].to_vec())
        } else {
            buffer[..bytes_read].to_vec()
        };

        out_file.write_all(&data)
            .map_err(|e| handle_io_error(e, "scrittura su file"))?;
        
        received += bytes_read as u64;

        if let Some(t) = transfers.lock().unwrap().get_mut(transfer_idx) {
            t.progress = (received as f64 / total_size as f64 * 100.0) as f32;
            
            let progress_percent = (received * 100) / total_size;
            if progress_percent % 10 == 0 && progress_percent > 0 {
                let last_logged = (t.progress as u64 / 10) * 10;
                if progress_percent > last_logged {
                    log_event(&format!("Progresso {}: {}/{} bytes ({:.1}%)", 
                        filename, received, total_size, t.progress));
                }
            }
        }

        thread::sleep(Duration::from_millis(1));
    }

    out_file.sync_all()?;

    if received != total_size {
        let error_msg = format!("File incompleto: ricevuti {}/{} bytes", received, total_size);
        log_event(&error_msg);
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error_msg));
    }

    let mut extracted_files = Vec::new();

    // Estrazione automatica degli archivi ZIP con progresso
    if auto_extract && filename.to_lowercase().ends_with(".zip") {
        {
            let mut transfers_lock = transfers.lock().unwrap();
            if let Some(t) = transfers_lock.get_mut(transfer_idx) {
                t.state = TransferState::Extracting(0.0);
                t.extract_progress = 0.0;
            }
        }

        log_event(&format!("Estrazione archivio: {}", filename));
        
        let extract_dir = file_path.with_extension("");
        
        // Estrai con callback di progresso
        let cancel_flag_clone = Arc::clone(&cancel_flag);
        let transfers_clone = Arc::clone(&transfers);
        let idx = transfer_idx;
        
        match extract_zip_file_with_progress(&file_path, &extract_dir, |progress| {
            // Controlla cancellazione
            if cancel_flag_clone.load(Ordering::SeqCst) {
                return false;
            }
            
            // Aggiorna il progresso nell'interfaccia
            if let Some(t) = transfers_clone.lock().unwrap().get_mut(idx) {
                t.state = TransferState::Extracting(progress);
                t.extract_progress = progress;
            }
            
            true
        }) {
            Ok(files) => {
                extracted_files = files;
                log_event(&format!("Archivio estratto: {} file creati", extracted_files.len()));
            },
            Err(e) => {
                log_event(&format!("Errore estrazione archivio: {}", e));
                if cancel_flag.load(Ordering::SeqCst) {
                    return Err(std::io::Error::new(ErrorKind::Interrupted, "Estrazione annullata"));
                }
            }
        }
    }

    log_event(&format!("Download completato: {} ({} bytes)", filename, received));
    Ok(extracted_files)
}

// --- GUI ---
impl eframe::App for FileTransferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.show_errors(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode, AppMode::Share, "📤 Condividi");
                ui.selectable_value(&mut self.mode, AppMode::Download, "📥 Scarica");
            });

            ui.separator();
            ui.add_space(10.0);

            match self.mode {
                AppMode::Share => {
                    if let Ok(local_ip) = get_local_ip() {
                        ui.label(format!("Il tuo IP: {}", local_ip));
                    }

                    ui.horizontal(|ui| {
                        ui.label("Porta:");
                        ui.text_edit_singleline(&mut self.server_port);
                    });

                    ui.add_space(10.0);
                    ui.checkbox(&mut self.server_encryption_enabled, "Crittografia");

                    if self.server_encryption_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            ui.add(egui::TextEdit::singleline(&mut self.server_password).password(true));
                        });
                    }

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Aggiungi File").clicked() {
                            self.add_file_to_share();
                        }
                        if ui.button("Aggiungi Cartella").clicked() {
                            self.add_folder_to_share();
                        }
                    });

                    ui.add_space(10.0);
                    ui.separator();
                    ui.heading("File Condivisi:");

                    egui::ScrollArea::vertical()
                        .id_source("shared_files_scroll")
                        .max_height(120.0)
                        .show(ui, |ui| {
                        let mut to_remove = None;
                        let files = self.server_shared_files.lock().unwrap();
                        if files.is_empty() {
                            ui.label("Nessun file condiviso");
                        } else {
                            for (i, file) in files.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.label(format!(
                                        "{} {} {} ({})",
                                        if file.is_archive { "📦" } else { "📄" },
                                        abbreviate_filename(&file.name, 25),
                                        if file.encrypted { "🔒" } else { "" },
                                        format_file_size(file.size)
                                    )).on_hover_text(&file.name);
                                    if ui.small_button("❌").clicked() {
                                        to_remove = Some(i);
                                    }
                                });
                            }
                        }
                        drop(files);
                        if let Some(i) = to_remove { 
                            self.server_shared_files.lock().unwrap().remove(i); 
                        }
                    });

                    ui.add_space(10.0);
                    ui.separator();

                    let is_running = self.server_running.load(Ordering::SeqCst);
                    ui.horizontal(|ui| {
                        if !is_running {
                            let has_files = !self.server_shared_files.lock().unwrap().is_empty();
                            let can_start = has_files && (!self.server_encryption_enabled || !self.server_password.is_empty());
                            if ui.add_enabled(can_start, egui::Button::new("Avvia Server")).clicked() {
                                self.start_server();
                            }
                            if !has_files { 
                                ui.label("Aggiungi almeno un file"); 
                            }
                        } else {
                            if ui.button("Ferma Server").clicked() {
                                self.stop_server();
                            }
                        }
                    });

                    ui.add_space(10.0);
                    ui.label(format!("Stato: {}", self.server_status.lock().unwrap()));

                    ui.add_space(10.0);
                    ui.separator();
                    ui.heading("Trasferimenti Attivi:");

                    let mut actions = Vec::new();
                    egui::ScrollArea::vertical()
                        .id_source("server_transfers_scroll")
                        .max_height(150.0)
                        .show(ui, |ui| {
                            let transfers = self.server_transfers.lock().unwrap();
                            if transfers.is_empty() {
                                ui.label("Nessun trasferimento attivo");
                            } else {
                                for (idx, transfer) in transfers.iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("{} {} {}",
                                            state_icon(&transfer.state),
                                            if transfer.is_archive { "📦" } else { "📄" },
                                            abbreviate_filename(&transfer.filename, 20)
                                        )).on_hover_text(&transfer.filename);

                                        match &transfer.state {
                                            TransferState::Transferring => {
                                                ui.add(egui::ProgressBar::new(transfer.progress / 100.0)
                                                    .text(format!("{:.1}% - {}", transfer.progress, self.calculate_speed(transfer))));
                                                if ui.small_button("⏸").clicked() {
                                                    actions.push(("pause", idx));
                                                }
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                            TransferState::Paused => {
                                                ui.label("⏸ In pausa");
                                                if ui.small_button("▶").clicked() {
                                                    actions.push(("resume", idx));
                                                }
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                            TransferState::Completed => {
                                                ui.label("✓ Completato");
                                            },
                                            TransferState::Cancelled => {
                                                ui.label("❌ Annullato");
                                            },
                                            TransferState::Error(e) => {
                                                ui.label(format!("⚠ {}", abbreviate_filename(e, 30)));
                                            },
                                            TransferState::Queued => {
                                                ui.label("⏳ In coda");
                                            },
                                            TransferState::Extracting(progress) => {
                                                ui.add(egui::ProgressBar::new(*progress / 100.0)
                                                    .text(format!("Estrazione: {:.1}%", progress)));
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                        }
                                    });
                                }
                            }
                        });

                    for (action, idx) in actions {
                        match action {
                            "pause" => self.pause_transfer(idx, true),
                            "resume" => self.resume_transfer(idx, true),
                            "cancel" => self.cancel_transfer(idx, true),
                            _ => {}
                        }
                    }

                    if ui.button("Pulisci Completati").clicked() {
                        self.clear_completed_transfers(true);
                    }
                }

                AppMode::Download => {
                    ui.horizontal(|ui| {
                        ui.label("IP: ");
                        ui.text_edit_singleline(&mut self.client_ip);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Porta: ");
                        ui.text_edit_singleline(&mut self.client_port);
                    });

                    ui.add_space(10.0);
                    ui.checkbox(&mut self.client_encryption_enabled, "Crittografia");
                    if self.client_encryption_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            ui.add(egui::TextEdit::singleline(&mut self.client_password).password(true));
                        });
                    }

                    ui.add_space(10.0);
                    ui.checkbox(&mut self.auto_extract_zip, "Estrai automaticamente archivi ZIP");

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔍 Cerca File").clicked() {
                            self.request_file_list();
                        }
                        if ui.button("Scarica Tutti").clicked() {
                            self.download_all_files();
                        }
                        if ui.button("📁 Cartella Download").clicked() {
                            self.open_download_folder();
                        }
                    });

                    ui.add_space(10.0);
                    ui.separator();
                    ui.heading("File Disponibili:");

                    let files_to_download: Vec<String> = {
                        let files = self.client_available_files.lock().unwrap();
                        let mut to_download = Vec::new();

                        egui::ScrollArea::vertical()
                            .id_source("available_files_scroll")
                            .max_height(120.0)
                            .show(ui, |ui| {
                                if files.is_empty() {
                                    ui.label("Nessun file disponibile. Connettiti a un server.");
                                } else {
                                    for file in files.iter() {
                                        ui.horizontal(|ui| {
                                            ui.label(format!(
                                                "{} {} {} ({})",
                                                if file.is_archive { "📦" } else { "📄" },
                                                abbreviate_filename(&file.name, 20),
                                                if file.encrypted { "🔒" } else { "" },
                                                format_file_size(file.size)
                                            )).on_hover_text(&file.name);
                                            if ui.button("Scarica").clicked() {
                                                to_download.push(file.name.clone());
                                            }
                                        });
                                    }
                                }
                            });
                        to_download
                    };

                    for filename in files_to_download {
                        self.download_file(filename);
                    }

                    ui.add_space(10.0);
                    ui.separator();
                    ui.heading("Download:");

                    let mut actions = Vec::new();
                    egui::ScrollArea::vertical()
                        .id_source("client_transfers_scroll")
                        .max_height(150.0)
                        .show(ui, |ui| {
                            let transfers = self.client_transfers.lock().unwrap();
                            if transfers.is_empty() {
                                ui.label("Nessun download attivo");
                            } else {
                                for (idx, transfer) in transfers.iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("{} {} {}",
                                            state_icon(&transfer.state),
                                            if transfer.is_archive { "📦" } else { "📄" },
                                            abbreviate_filename(&transfer.filename, 20)
                                        )).on_hover_text(&transfer.filename);

                                        match &transfer.state {
                                            TransferState::Queued => {
                                                ui.label(format!("⏳ In coda ({})", format_file_size(transfer.size)));
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                            TransferState::Transferring => {
                                                ui.add(egui::ProgressBar::new(transfer.progress / 100.0)
                                                    .desired_width(100.0)
                                                    .text(format!("{:.1}% - {}", transfer.progress, self.calculate_speed(transfer))));
                                                if ui.small_button("⏸").clicked() {
                                                    actions.push(("pause", idx));
                                                }
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                            TransferState::Paused => {
                                                ui.label("⏸ In pausa");
                                                if ui.small_button("▶").clicked() {
                                                    actions.push(("resume", idx));
                                                }
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                            TransferState::Completed => {
                                                ui.label("✓ Completato");
                                                if transfer.is_archive && !transfer.extracted_files.is_empty() {
                                                    ui.label(format!(" ({} file estratti)", transfer.extracted_files.len()));
                                                }
                                            },
                                            TransferState::Cancelled => {
                                                ui.label("❌ Annullato");
                                            },
                                            TransferState::Error(_) => {
                                                ui.label("⚠ Errore");
                                            },
                                            TransferState::Extracting(progress) => {
                                                ui.add(egui::ProgressBar::new(*progress / 100.0)
                                                    .desired_width(100.0)
                                                    .text(format!("Estrazione: {:.1}%", progress)));
                                                if ui.small_button("❌").clicked() {
                                                    actions.push(("cancel", idx));
                                                }
                                            },
                                        }
                                    });

                                    if transfer.state == TransferState::Completed && transfer.is_archive && !transfer.extracted_files.is_empty() {
                                        ui.indent("extracted_files", |ui| {
                                            for extracted in &transfer.extracted_files {
                                                ui.label(format!("   📄 {}", abbreviate_filename(extracted, 25)));
                                            }
                                        });
                                    }
                                }
                            }
                        });

                    for (action, idx) in actions {
                        match action {
                            "pause" => self.pause_transfer(idx, false),
                            "resume" => self.resume_transfer(idx, false),
                            "cancel" => self.cancel_transfer(idx, false),
                            _ => {}
                        }
                    }

                    if ui.button("Pulisci Completati").clicked() {
                        self.clear_completed_transfers(false);
                    }

                    ui.add_space(10.0);
                    ui.separator();
                    ui.heading("File Scaricati:");
                    egui::ScrollArea::vertical()
                        .id_source("downloaded_files_scroll")
                        .max_height(80.0)
                        .show(ui, |ui| {
                            let received = self.received_files.lock().unwrap();
                            if received.is_empty() {
                                ui.label("Nessun file scaricato ancora");
                            } else {
                                for file in received.iter() {
                                    ui.label(format!("✓ {}", abbreviate_filename(file, 30)))
                                        .on_hover_text(file);
                                }
                            }
                        });
                }
            }
        });

        if ctx.input(|i| i.viewport().close_requested()) {
            self.save_config();
        }

        ctx.request_repaint();
    }
}

fn main() -> Result<(), eframe::Error> {
    // Crea le directory necessarie all'avvio
    if let Some(app_dir) = get_app_data_dir() {
        let _ = create_dir_all(&app_dir);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 500.0])
            .with_title("LanBeam - Trasferimento File LAN"),
        ..Default::default()
    };

    eframe::run_native(
        "LanBeam",
        options,
        Box::new(|_cc| Box::new(FileTransferApp::default())),
    )
}