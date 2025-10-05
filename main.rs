use eframe::egui;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::fs::{File, create_dir_all};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::collections::VecDeque;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 700.0])
            .with_title("LanBeam"),
        ..Default::default()
    };
    
    eframe::run_native(
        "LanBeam",
        options,
        Box::new(|_cc| Ok(Box::new(FileTransferApp::default()))),
    )
}

#[derive(Clone)]
struct SharedFile {
    name: String,
    path: PathBuf,
    size: u64,
    encrypted: bool,
}

#[derive(Clone, PartialEq)]
enum TransferState {
    Queued,
    Transferring,
    Paused,
    Completed,
    Cancelled,
    Error(String),
}

#[derive(Clone)]
struct Transfer {
    filename: String,
    size: u64,
    progress: f32,
    state: TransferState,
    cancel_flag: Arc<Mutex<bool>>,
    pause_flag: Arc<Mutex<bool>>,
}

#[derive(Default)]
struct FileTransferApp {
    mode: AppMode,
    
    // Server
    server_port: String,
    server_status: Arc<Mutex<String>>,
    server_running: Arc<Mutex<bool>>,
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
}

#[derive(PartialEq, Default)]
enum AppMode {
    #[default]
    Share,
    Download,
}

// --- Helper functions ---
fn abbreviate_filename(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        let half = (max_len - 3) / 2;
        format!("{}...{}", &name[..half], &name[name.len()-half..])
    }
}

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

// XOR encryption/decryption
fn xor_encrypt_decrypt(data: &[u8], password: &str) -> Vec<u8> {
    let key_bytes = password.as_bytes();
    if key_bytes.is_empty() {
        return data.to_vec();
    }
    
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}

// --- Implementation ---
impl FileTransferApp {
    fn add_file_to_share(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            if let Ok(metadata) = std::fs::metadata(&path) {
                let file = SharedFile {
                    name: path.file_name().unwrap().to_str().unwrap().to_string(),
                    path: path.clone(),
                    size: metadata.len(),
                    encrypted: self.server_encryption_enabled,
                };
                self.server_shared_files.lock().unwrap().push(file);
            }
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

        *running.lock().unwrap() = true;
        *status.lock().unwrap() = format!(
            "Server in ascolto sulla porta {} {}",
            port,
            if password.is_some() { "🔒" } else { "" }
        );

        thread::spawn(move || {
            if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{}", port)) {
                for stream in listener.incoming() {
                    if !*running.lock().unwrap() { break; }

                    if let Ok(stream) = stream {
                        let status_clone = Arc::clone(&status);
                        let files_clone = Arc::clone(&shared_files);
                        let transfers_clone = Arc::clone(&transfers);
                        let pwd = password.clone();

                        thread::spawn(move || {
                            if let Err(e) = handle_client(stream, status_clone, files_clone, transfers_clone, pwd) {
                                eprintln!("Errore nella gestione del client: {}", e);
                            }
                        });
                    }
                }
            } else {
                *status.lock().unwrap() = format!("Impossibile avviare il server sulla porta {}", port);
            }
        });
    }

    fn stop_server(&mut self) {
        // Cancella tutti i trasferimenti attivi
        let mut transfers = self.server_transfers.lock().unwrap();
        for transfer in transfers.iter_mut() {
            if transfer.state == TransferState::Transferring || transfer.state == TransferState::Paused {
                *transfer.cancel_flag.lock().unwrap() = true;
                transfer.state = TransferState::Cancelled;
            }
        }
        drop(transfers);
        
        *self.server_running.lock().unwrap() = false;
        *self.server_status.lock().unwrap() = "Server fermato".to_string();
    }

    fn request_file_list(&mut self) {
        let ip = self.client_ip.clone();
        let port = self.client_port.clone();
        let available = Arc::clone(&self.client_available_files);

        self.client_status = "Richiesta lista file...".to_string();

        thread::spawn(move || {
            match get_file_list(&ip, &port) {
                Ok(files) => {
                    *available.lock().unwrap() = files;
                },
                Err(e) => eprintln!("Errore nel recupero lista: {}", e),
            }
        });
    }

    fn download_file(&mut self, filename: String) {
        if self.client_encryption_enabled && self.client_password.is_empty() {
            self.client_status = "Errore: inserisci una password".to_string();
            return;
        }

        // Controlla se il file esiste già
        let file_path = PathBuf::from("downloads").join(&filename);
        if file_path.exists() {
            self.client_status = format!("File {} già presente", filename);
            return;
        }

        // Aggiungi alla coda
        self.client_queue.lock().unwrap().push_back(filename.clone());
        
        // Crea trasferimento in coda
        let cancel_flag = Arc::new(Mutex::new(false));
        let pause_flag = Arc::new(Mutex::new(false));
        
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
        };
        
        self.client_transfers.lock().unwrap().push(transfer);
        
        // Avvia il worker se non ci sono già trasferimenti attivi
        let active_count = self.client_transfers.lock().unwrap()
            .iter()
            .filter(|t| t.state == TransferState::Transferring)
            .count();
        
        if active_count == 0 {
            self.process_download_queue();
        }
    }

    fn process_download_queue(&mut self) {
        let queue = Arc::clone(&self.client_queue);
        let transfers = Arc::clone(&self.client_transfers);
        let received = Arc::clone(&self.received_files);
        let ip = self.client_ip.clone();
        let port = self.client_port.clone();
        let password = if self.client_encryption_enabled {
            Some(self.client_password.clone())
        } else { None };

        thread::spawn(move || {
            loop {
                let next_file = queue.lock().unwrap().pop_front();
                
                if let Some(filename) = next_file {
                    // Trova l'indice del trasferimento in coda
                    let transfer_idx = {
                        let mut transfers_lock = transfers.lock().unwrap();
                        if let Some(idx) = transfers_lock.iter().position(|t| t.filename == filename && t.state == TransferState::Queued) {
                            // Cambia stato da Queued a Transferring
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
                        ) {
                            Ok(_) => {
                                received.lock().unwrap().push(filename.clone());
                                if let Some(t) = transfers.lock().unwrap().get_mut(idx) {
                                    if !*t.cancel_flag.lock().unwrap() {
                                        t.state = TransferState::Completed;
                                        t.progress = 100.0;
                                    }
                                }
                            },
                            Err(e) => {
                                if let Some(t) = transfers.lock().unwrap().get_mut(idx) {
                                    if !*t.cancel_flag.lock().unwrap() {
                                        t.state = TransferState::Error(e.to_string());
                                    }
                                }
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
            // Se è in coda, rimuovilo anche dalla coda
            if !is_server && transfer.state == TransferState::Queued {
                let mut queue = self.client_queue.lock().unwrap();
                if let Some(pos) = queue.iter().position(|f| f == &transfer.filename) {
                    queue.remove(pos);
                }
            }
            
            *transfer.cancel_flag.lock().unwrap() = true;
            transfer.state = TransferState::Cancelled;
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
                *transfer.pause_flag.lock().unwrap() = true;
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
                *transfer.pause_flag.lock().unwrap() = false;
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
}

// --- GUI ---
impl eframe::App for FileTransferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                        ui.label(format!("IP: {}", local_ip));
                    }

                    ui.horizontal(|ui| {
                        ui.label("Porta:");
                        ui.text_edit_singleline(&mut self.server_port);
                    });
                    if self.server_port.is_empty() { self.server_port = "8080".to_string(); }

                    ui.add_space(10.0);
                    ui.checkbox(&mut self.server_encryption_enabled, "Crittografia");

                    if self.server_encryption_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            ui.add(egui::TextEdit::singleline(&mut self.server_password).password(true));
                        });
                    }

                    ui.add_space(10.0);

                    if ui.button("Aggiungi File").clicked() {
                        self.add_file_to_share();
                    }

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
                                        "📄 {} {} ({})",
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
                        if let Some(i) = to_remove { self.server_shared_files.lock().unwrap().remove(i); }
                    });

                    ui.add_space(10.0);
                    ui.separator();

                    let is_running = *self.server_running.lock().unwrap();
                    ui.horizontal(|ui| {
                        if !is_running {
                            let has_files = !self.server_shared_files.lock().unwrap().is_empty();
                            let can_start = has_files && (!self.server_encryption_enabled || !self.server_password.is_empty());
                            if ui.add_enabled(can_start, egui::Button::new("Avvia Server")).clicked() {
                                self.start_server();
                            }
                            if !has_files { ui.label("Aggiungi almeno un file"); }
                        } else {
                            if ui.button("Ferma Server").clicked() {
                                self.stop_server();
                            }
                        }
                    });

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
                                        ui.label(abbreviate_filename(&transfer.filename, 20))
                                            .on_hover_text(&transfer.filename);
                                        
                                        match &transfer.state {
                                            TransferState::Transferring => {
                                                ui.add(egui::ProgressBar::new(transfer.progress / 100.0)
                                                    .text(format!("{:.1}%", transfer.progress)));
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
                                                ui.label(format!("⚠ {}", e));
                                            },
                                            TransferState::Queued => {
                                                ui.label("⏳ In coda");
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
                    if self.client_port.is_empty() { self.client_port = "8080".to_string(); }

                    ui.add_space(10.0);
                    ui.checkbox(&mut self.client_encryption_enabled, "Crittografia");
                    if self.client_encryption_enabled {
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            ui.add(egui::TextEdit::singleline(&mut self.client_password).password(true));
                        });
                    }

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔍 Cerca File").clicked() {
                            self.request_file_list();
                        }
                        if ui.button("Scarica Tutti").clicked() {
                            self.download_all_files();
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
                                                "📄 {} {} ({})",
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
                                        ui.label(abbreviate_filename(&transfer.filename, 20))
                                            .on_hover_text(&transfer.filename);
                                        
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
                                                    .text(format!("{:.1}%", transfer.progress)));
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
                                            TransferState::Error(_) => {
                                                ui.label("⚠ Errore");
                                            },
                                        }
                                    });
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

        ctx.request_repaint();
    }
}

// --- Server/client functions ---
fn handle_client(
    mut stream: TcpStream,
    status: Arc<Mutex<String>>,
    shared_files: Arc<Mutex<Vec<SharedFile>>>,
    transfers: Arc<Mutex<Vec<Transfer>>>,
    password: Option<String>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr()?;
    *status.lock().unwrap() = format!("Connessione da {}...", peer);

    let mut cmd_buf = [0u8; 4];
    stream.read_exact(&mut cmd_buf)?;
    let cmd = String::from_utf8_lossy(&cmd_buf);

    if cmd == "LIST" {
        let files = shared_files.lock().unwrap();
        stream.write_all(&(files.len() as u32).to_be_bytes())?;
        for f in files.iter() {
            let name_bytes = f.name.as_bytes();
            stream.write_all(&(name_bytes.len() as u32).to_be_bytes())?;
            stream.write_all(name_bytes)?;
            stream.write_all(&f.size.to_be_bytes())?;
            stream.write_all(&[if f.encrypted {1} else {0}])?;
        }
        stream.flush()?;
        *status.lock().unwrap() = format!("Inviata lista a {}", peer);
        return Ok(());
    }

    if cmd == "DOWN" {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let name_len = u32::from_be_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        stream.read_exact(&mut name_buf)?;
        let requested = String::from_utf8_lossy(&name_buf).to_string();

        let files = shared_files.lock().unwrap();
        let file_info = match files.iter().find(|f| f.name == requested) {
            Some(f) => f.clone(),
            None => {
                stream.write_all(b"NOTFOUND")?;
                return Ok(());
            }
        };
        drop(files);

        if file_info.encrypted && password.is_none() {
            stream.write_all(b"NEEDPASS")?;
            return Ok(());
        }

        stream.write_all(b"OK______")?;

        // Crea il trasferimento
        let cancel_flag = Arc::new(Mutex::new(false));
        let pause_flag = Arc::new(Mutex::new(false));
        
        let transfer = Transfer {
            filename: requested.clone(),
            size: file_info.size,
            progress: 0.0,
            state: TransferState::Transferring,
            cancel_flag: Arc::clone(&cancel_flag),
            pause_flag: Arc::clone(&pause_flag),
        };
        
        transfers.lock().unwrap().push(transfer.clone());
        let transfer_idx = transfers.lock().unwrap().len() - 1;

        let mut source_file = File::open(&file_info.path)?;
        stream.write_all(&file_info.size.to_be_bytes())?;

        let mut buffer = vec![0u8; 8192];
        let mut sent = 0u64;

        loop {
            // Controlla cancellazione
            if *cancel_flag.lock().unwrap() {
                break;
            }

            // Controlla pausa
            while *pause_flag.lock().unwrap() {
                if *cancel_flag.lock().unwrap() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            let n = source_file.read(&mut buffer)?;
            if n == 0 { break; }
            
            let data = if let Some(ref pwd) = password {
                xor_encrypt_decrypt(&buffer[..n], pwd)
            } else {
                buffer[..n].to_vec()
            };
            
            stream.write_all(&data)?;
            sent += n as u64;
            
            if let Some(t) = transfers.lock().unwrap().get_mut(transfer_idx) {
                t.progress = (sent as f64 / file_info.size as f64 * 100.0) as f32;
            }
        }

        stream.flush()?;
        
        if let Some(t) = transfers.lock().unwrap().get_mut(transfer_idx) {
            if *cancel_flag.lock().unwrap() {
                t.state = TransferState::Cancelled;
            } else {
                t.state = TransferState::Completed;
                t.progress = 100.0;
            }
        }
        
        *status.lock().unwrap() = format!("Inviato {} a {}", requested, peer);
    }

    Ok(())
}

fn get_file_list(ip: &str, port: &str) -> std::io::Result<Vec<SharedFile>> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port))?;
    stream.write_all(b"LIST")?;
    stream.flush()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let count = u32::from_be_bytes(len_buf);

    let mut files = Vec::new();
    for _ in 0..count {
        stream.read_exact(&mut len_buf)?;
        let name_len = u32::from_be_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        stream.read_exact(&mut name_buf)?;
        let name = String::from_utf8_lossy(&name_buf).to_string();

        let mut size_buf = [0u8; 8];
        stream.read_exact(&mut size_buf)?;
        let size = u64::from_be_bytes(size_buf);

        let mut flag = [0u8;1];
        stream.read_exact(&mut flag)?;
        let encrypted = flag[0] == 1;

        files.push(SharedFile { name, path: PathBuf::new(), size, encrypted });
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
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port))?;
    stream.write_all(b"DOWN")?;
    let name_bytes = filename.as_bytes();
    stream.write_all(&(name_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(name_bytes)?;
    stream.flush()?;

    let mut status_buf = [0u8;8];
    stream.read_exact(&mut status_buf)?;
    let status_str = String::from_utf8_lossy(&status_buf);
    if status_str == "NOTFOUND" { 
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "File non trovato")); 
    }
    if status_str == "NEEDPASS" { 
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Password richiesta")); 
    }

    let mut size_buf = [0u8;8];
    stream.read_exact(&mut size_buf)?;
    let size = u64::from_be_bytes(size_buf);

    let mut file_path = PathBuf::from("downloads");
    create_dir_all(&file_path)?;
    file_path.push(filename);
    let mut out_file = File::create(&file_path)?;

    let cancel_flag = if let Some(t) = transfers.lock().unwrap().get(transfer_idx) {
        Arc::clone(&t.cancel_flag)
    } else {
        return Ok(());
    };

    let pause_flag = if let Some(t) = transfers.lock().unwrap().get(transfer_idx) {
        Arc::clone(&t.pause_flag)
    } else {
        return Ok(());
    };

    let mut received = 0u64;
    let mut buffer = vec![0u8; 8192];
    
    while received < size {
        // Controlla cancellazione
        if *cancel_flag.lock().unwrap() {
            drop(out_file);
            let _ = std::fs::remove_file(&file_path);
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Download annullato"));
        }

        // Controlla pausa
        while *pause_flag.lock().unwrap() {
            if *cancel_flag.lock().unwrap() {
                drop(out_file);
                let _ = std::fs::remove_file(&file_path);
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Download annullato"));
            }
            thread::sleep(Duration::from_millis(100));
        }

        let n = stream.read(&mut buffer)?;
        if n == 0 { break; }
        
        let data = if let Some(ref pwd) = password {
            xor_encrypt_decrypt(&buffer[..n], pwd)
        } else {
            buffer[..n].to_vec()
        };
        
        out_file.write_all(&data)?;
        received += n as u64;
        
        if let Some(t) = transfers.lock().unwrap().get_mut(transfer_idx) {
            t.progress = (received as f64 / size as f64 * 100.0) as f32;
        }
    }

    Ok(())
}

fn get_local_ip() -> Result<String, std::io::Error> {
    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    udp_socket.connect("8.8.8.8:80")?;
    Ok(udp_socket.local_addr()?.ip().to_string())
}
