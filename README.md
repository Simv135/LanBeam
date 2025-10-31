# LanBeam - Trasferimento File LAN

**LanBeam** è un'applicazione desktop per il trasferimento di file tramite rete LAN con interfaccia grafica moderna e funzionalità avanzate.

[download pre-release](https://github.com/Simv135/LanBeam/releases)

## ✨ Caratteristiche Principali

### 🚀 Funzionalità Core
- **Condivisione File**: Trasforma il tuo PC in un server per condividere file e cartelle
- **Download Multipli**: Scarica file da altri dispositivi sulla rete
- **Interfaccia Intuitiva**: GUI moderna e responsive con egui/eframe
- **Multi-piattaforma**: Compatibile con Windows, macOS e Linux

### 🔒 Sicurezza
- **Crittografia Opzionale**: Proteggi i trasferimenti con password
- **Autenticazione**: Controllo degli accessi per file crittografati
- **Gestione Errori**: Sistema di logging e notifiche errori

### 📊 Gestione Avanzata
- **Code di Download**: Download multipli con gestione delle priorità
- **Pausa/Riprendi**: Controllo completo sui trasferimenti
- **Progresso in Tempo Reale**: Monitoraggio dettagliato con velocità di trasferimento
- **Estrazione Automatica**: Decompressione automatica degli archivi ZIP

### 🗂️ Organizzazione File
- **Gestione Cartelle**: Supporto per condivisione ricorsiva di cartelle
- **Download Folder**: Directory dedicata per i file scaricati
- **Separazione Archivi**: Riconoscimento automatico dei file compressi

## 📖 Guida all'Uso

### Modalità Condivisione (Share) 📤

1. **Configurazione Server**
   - Inserisci la porta desiderata (default: 8080)
   - Abilita la crittografia se necessario
   - Imposta una password per i file crittografati

2. **Aggiunta File**
   - Clicca "Aggiungi File" per selezionare singoli file
   - Clicca "Aggiungi Cartella" per condividere intere directory
   - I file vengono mostrati nella lista con dimensioni e tipo

3. **Avvio Server**
   - Clicca "Avvia Server" per iniziare la condivisione
   - Condividi il tuo IP e porta con altri dispositivi
   - Monitora i trasferimenti attivi in tempo reale

### Modalità Download (Download) 📥

1. **Connessione al Server**
   - Inserisci IP e porta del server remoto
   - Abilita crittografia se richiesto dal server
   - Inserisci la password corretta

2. **Ricerca File**
   - Clicca "Cerca File" per ottenere la lista dei file disponibili
   - I file vengono mostrati con dimensioni e stato crittografia

3. **Download**
   - Clicca "Scarica" su singoli file o "Scarica Tutti"
   - I download vengono accodati automaticamente
   - Monitora il progresso con velocità di trasferimento

## 🎛️ Comandi Trasferimento

### Controlli Disponibili
- **▶️ Riprendi**: Continua un trasferimento in pausa
- **⏸️ Pausa**: Metti in pausa un trasferimento attivo
- **❌ Annulla**: Interrompi definitivamente un trasferimento
- **🧹 Pulisci**: Rimuovi i trasferimenti completati

### Stati Trasferimento
- **⏳ In Coda**: In attesa di essere processato
- **📤 Trasferendo**: Download/upload in corso
- **⏸️ In Pausa**: Trasferimento sospeso temporaneamente
- **📦 Estraendo**: Estrazione archivio in corso
- **✅ Completato**: Operazione terminata con successo
- **❌ Annullato**: Operazione interrotta dall'utente
- **⚠️ Errore**: Si è verificato un errore

## ⚙️ Configurazione

### File di Configurazione
L'app salva automaticamente le impostazioni in:
- **Windows**: `%APPDATA%\Local\LanBeam\lanbeam_config.json`
- **Linux**: `~/.local/share/LanBeam/lanbeam_config.json`
- **macOS**: `~/Library/Application Support/LanBeam/lanbeam_config.json`

### Impostazioni Persistenti
- Ultime porte utilizzate
- Preferenze crittografia
- Cartella download predefinita
- Impostazione estrazione automatica ZIP

## 🔧 Risoluzione Problemi

### Problemi Comuni

**Connessione Rifiutata**
- Verifica che il firewall permetta connessioni sulla porta specificata
- Controlla che il server sia attivo e in ascolto
- Verifica che IP e porta siano corretti

**Download Incompleto**
- Controlla lo spazio su disco disponibile
- Verifica la stabilità della connessione di rete
- Assicurati di avere i permessi di scrittura

**File Non Trovati**
- Sul server: verifica che i file siano ancora presenti nel percorso originale
- Sul client: controlla che il nome del file non contenga caratteri speciali

### Log e Debug
I log dell'applicazione sono salvati in `lanbeam.log` nella cartella dati dell'app. Controlla questo file per diagnosticare problemi complessi.

## 📋 Requisiti di Sistema

- **Sistema Operativo**: Windows 10+, macOS 10.15+, o Linux moderno
- **Memoria RAM**: 100MB minimo, 512MB raccomandato
- **Spazio Disco**: 50MB per l'applicazione + spazio per i file trasferiti
- **Rete**: Connessione LAN funzionante, TCP/IP abilitato

## 🚀 Limitazioni Note

- **Dimensione Massima File**: 10GB per file
- **Connessioni Simultanee**: Gestione base, non ottimizzata per centinaia di connessioni
- **Reti Complesse**: Potrebbero esserci problemi su reti con NAT complessi

## 🔒 Considerazioni Sicurezza

- La crittografia usa XOR con chiave MD5 (base, non per dati sensibili)
- Non esporre il server su internet senza firewall appropriato
- Le password vengono memorizzate in memoria durante la sessione

## 📄 Licenza

Distribuito sotto licenza MIT. Vedere `LICENSE` per dettagli.

**Nota**: Questo software è progettato per uso in reti locali trusted. Utilizzare appropriati strumenti di sicurezza per reti pubbliche o non affidabili.
