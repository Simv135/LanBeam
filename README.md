# LanBeam - LAN File Transfer

**LanBeam** is a desktop application for transferring files via a Local Area Network (LAN), featuring a modern graphical interface and advanced functionalities.

[Download Pre-release](https://github.com/Simv135/LanBeam/releases)

## ✨ Key Features

### 🚀 Core Functionality
*   **File Sharing**: Turn your PC into a server to share files and folders.
*   **Multiple Downloads**: Download files from other devices on the network.
*   **Intuitive Interface**: Modern and responsive GUI built with egui/eframe.
*   **Cross-Platform**: Compatible with Windows, macOS, and Linux.

### 🔒 Security
*   **Optional Encryption**: Protect transfers with a password.
*   **Authentication**: Access control for encrypted files.
*   **Error Handling**: Logging system and error notifications.

### 📊 Advanced Management
*   **Download Queue**: Multiple downloads with priority management.
*   **Pause/Resume**: Full control over active transfers.
*   **Real-Time Progress**: Detailed monitoring with transfer speed.
*   **Auto-Extraction**: Automatic decompression of ZIP archives.

### 🗂️ File Organization
*   **Folder Management**: Support for recursive folder sharing.
*   **Download Folder**: Dedicated directory for downloaded files.
*   **Archive Separation**: Automatic recognition of compressed files.

## 📖 User Guide

### Share Mode 📤

1.  **Server Setup**
    *   Enter the desired port (default: 8080).
    *   Enable encryption if necessary.
    *   Set a password for encrypted files.

2.  **Adding Files**
    *   Click "Add File" to select individual files.
    *   Click "Add Folder" to share entire directories.
    *   Files are displayed in a list with size and type.

3.  **Starting the Server**
    *   Click "Start Server" to begin sharing.
    *   Share your IP address and port with other devices.
    *   Monitor active transfers in real-time.

### Download Mode 📥

1.  **Connecting to a Server**
    *   Enter the remote server's IP address and port.
    *   Enable encryption if required by the server.
    *   Enter the correct password.

2.  **Browsing Files**
    *   Click "Search Files" to retrieve the list of available files.
    *   Files are displayed with size and encryption status.

3.  **Downloading**
    *   Click "Download" on individual files or use "Download All".
    *   Downloads are automatically queued.
    *   Monitor progress and transfer speed.

## 🎛️ Transfer Controls

### Available Controls
*   **▶️ Resume**: Continue a paused transfer.
*   **⏸️ Pause**: Temporarily suspend an active transfer.
*   **❌ Cancel**: Permanently stop a transfer.
*   **🧹 Clear**: Remove completed transfers from the list.

### Transfer Status
*   **⏳ Queued**: Waiting to be processed.
*   **📤 Transferring**: Download/upload in progress.
*   **⏸️ Paused**: Transfer is temporarily suspended.
*   **📦 Extracting**: Archive extraction in progress.
*   **✅ Completed**: Operation finished successfully.
*   **❌ Cancelled**: Operation stopped by the user.
*   **⚠️ Error**: An error occurred.

## ⚙️ Configuration

### Configuration File
The app automatically saves settings to:
*   **Windows**: `%APPDATA%\Local\LanBeam\lanbeam_config.json`
*   **Linux**: `~/.local/share/LanBeam/lanbeam_config.json`
*   **macOS**: `~/Library/Application Support/LanBeam/lanbeam_config.json`

### Persistent Settings
*   Last used ports.
*   Encryption preferences.
*   Default download folder.
*   Automatic ZIP extraction setting.

## 🔧 Troubleshooting

### Common Issues

**Connection Refused**
*   Verify the firewall allows connections on the specified port.
*   Check that the server is active and listening.
*   Ensure the IP address and port are correct.

**Incomplete Download**
*   Check available disk space.
*   Verify network connection stability.
*   Ensure you have write permissions.

**File Not Found**
*   **On the server**: Verify the files still exist in their original location.
*   **On the client**: Check that the filename does not contain special characters.

### Logs and Debug
Application logs are saved to `lanbeam.log` in the app's data folder. Check this file to diagnose complex issues.

## 📋 System Requirements

*   **Operating System**: Windows 10+, macOS 10.15+, or modern Linux.
*   **RAM**: 100MB minimum, 512MB recommended.
*   **Disk Space**: 50MB for the application + space for transferred files.
*   **Network**: Functional LAN connection, TCP/IP enabled.

## 🚀 Known Limitations

*   **Maximum File Size**: 10GB per file.
*   **Simultaneous Connections**: Basic management, not optimized for hundreds of connections.
*   **Complex Networks**: Issues may arise on networks with complex NAT configurations.

## 🔒 Security Considerations

*   Encryption uses XOR with an MD5 key (basic, not for sensitive data).
*   Do not expose the server to the internet without an appropriate firewall.
*   Passwords are stored in memory during the session.

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.

**Note**: This software is designed for use on trusted local networks. Use appropriate security tools for public or untrusted networks.
