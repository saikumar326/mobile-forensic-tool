import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
from tkinter import ttk
from PIL import Image, ImageTk, UnidentifiedImageError
from PIL.ExifTags import TAGS, GPSTAGS
from datetime import datetime
import imagehash
from stegano import lsb
import hashlib
import json
import sqlite3
from scapy.all import rdpcap
import tempfile
from PIL import ImageChops, ImageEnhance
import threading
import zipfile
import xml.etree.ElementTree as ET
import bcrypt
from tkinter import filedialog, messagebox, ttk
import cv2  # For video playback
import threading 


# Database setup (outside the class)
def initialize_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# Password hashing and verification (outside the class)
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)


# Registration Window
class RegistrationWindow:
    def __init__(self):
        self.window = tk.Toplevel()
        self.window.title("Register")
        self.window.geometry("400x250")

        # Username
        self.label_username = tk.Label(self.window, text="Username:")
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(self.window)
        self.entry_username.pack(pady=5)

        # Password
        self.label_password = tk.Label(self.window, text="Password:")
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(self.window, show="*")
        self.entry_password.pack(pady=5)

        # Confirm Password
        self.label_confirm_password = tk.Label(self.window, text="Confirm Password:")
        self.label_confirm_password.pack(pady=5)
        self.entry_confirm_password = tk.Entry(self.window, show="*")
        self.entry_confirm_password.pack(pady=5)

        # Register Button
        self.button_register = tk.Button(self.window, text="Register", command=self.register)
        self.button_register.pack(pady=10)

    def register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        confirm_password = self.entry_confirm_password.get()

        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),  # Call the standalone function
            )
            conn.commit()
            messagebox.showinfo("Success", "Registration successful! You can now log in.")
            self.window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")
        finally:
            conn.close()


# Login Window
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("400x250")

        # Username
        self.label_username = tk.Label(root, text="Username:")
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(root)
        self.entry_username.pack(pady=5)

        # Password
        self.label_password = tk.Label(root, text="Password:")
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(root, show="*")
        self.entry_password.pack(pady=5)

        # Login Button
        self.button_login = tk.Button(root, text="Login", command=self.authenticate)
        self.button_login.pack(pady=10)

        # Register Button
        self.button_register = tk.Button(root, text="Register", command=self.open_registration)
        self.button_register.pack(pady=5)

        # Forgot Password Button
        self.button_forgot_password = tk.Button(root, text="Forgot Password", command=self.open_password_recovery)
        self.button_forgot_password.pack(pady=5)

    def authenticate(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and verify_password(password, result[0]):  # Call the standalone function
            self.root.destroy()
            self.launch_main_app(username)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def open_registration(self):
        RegistrationWindow()

    def open_password_recovery(self):
        PasswordRecoveryWindow()

    def launch_main_app(self, username):
        root = tk.Tk()
        app = AdvancedForensicTool(root, username)
        root.mainloop()

class AdvancedForensicTool:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"Advanced Digital Forensic Tool - Welcome, {username}")
        self.root.geometry("1200x800")
        self.device_id = None
        self.file_list = []
        self.is_running = False
        self.status_var = tk.StringVar()
        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface for the main application."""
        # Main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Workspace for multimedia files
        self.workspace_frame = ttk.Frame(self.main_frame)
        self.workspace_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left panel for file list
        self.left_panel = ttk.Frame(self.workspace_frame, width=200)
        self.left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # Right panel for displaying multimedia and metadata
        self.right_panel = ttk.Frame(self.workspace_frame)
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # File listbox
        self.file_listbox = tk.Listbox(self.left_panel, selectmode=tk.SINGLE)
        self.file_listbox.pack(fill=tk.BOTH, expand=True)
        self.file_listbox.bind("<<ListboxSelect>>", self.display_selected_file)

        # Metadata display
        self.metadata_text = tk.Text(self.right_panel, wrap=tk.WORD, height=10)
        self.metadata_text.pack(fill=tk.X, pady=5)

        # Image/Video display area with scrollbars
        self.canvas = tk.Canvas(self.right_panel, bg="black")
        self.canvas.pack(fill=tk.BOTH, expand=True)

        # Scrollbars for the canvas
        self.scroll_x = ttk.Scrollbar(self.right_panel, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.scroll_y = ttk.Scrollbar(self.right_panel, orient=tk.VERTICAL, command=self.canvas.yview)
        self.scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.configure(xscrollcommand=self.scroll_x.set, yscrollcommand=self.scroll_y.set)
        self.canvas.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # Status bar
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        """Set up the user interface for the main application."""
        # Apply a modern theme
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use the 'clam' theme for a modern look

        # Configure colors and fonts
        self.style.configure("TFrame", background="#2E3440")  # Dark background for frames
        self.style.configure("TLabel", background="#2E3440", foreground="#ECEFF4", font=("Helvetica", 12))  # Light text on dark background
        self.style.configure("TButton", font=("Helvetica", 12), padding=5, background="#4C566A", foreground="#ECEFF4")  # Custom button colors
        self.style.map("TButton", background=[("active", "#5E81AC")])  # Change button color on hover
        self.style.configure("TMenu", font=("Helvetica", 12), background="#4C566A", foreground="#ECEFF4")  # Menu colors
        self.style.configure("TEntry", font=("Helvetica", 12), background="#3B4252", foreground="#ECEFF4")  # Entry widget colors
        self.style.configure("TText", font=("Helvetica", 12), background="#3B4252", foreground="#ECEFF4")  # Text widget colors

        # Create a menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Create a "File" menu
        file_menu = tk.Menu(menubar, tearoff=0, background="#4C566A", foreground="#ECEFF4")
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Detect Device", command=self.detect_device)
        file_menu.add_command(label="List Files", command=self.list_files)
        file_menu.add_command(label="Extract File", command=self.extract_file)
        file_menu.add_command(label="Extract Photos", command=self.extract_photos)
        file_menu.add_command(label="Recover Deleted Files", command=self.recover_deleted_files)
        file_menu.add_command(label="Create ADB Backup", command=self.create_adb_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Clear Workspace", command=self.clear_workspace)
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Create a "Device Info" menu
        device_menu = tk.Menu(menubar, tearoff=0, background="#4C566A", foreground="#ECEFF4")
        menubar.add_cascade(label="Device Info", menu=device_menu)
        device_menu.add_command(label="Extract Device Information", command=self.extract_device_info)
        device_menu.add_command(label="Check Root Status", command=self.check_root_status)
        device_menu.add_command(label="Check Encryption Status", command=self.check_encryption_status)

        # Create a "Data Extraction" menu
        data_menu = tk.Menu(menubar, tearoff=0, background="#4C566A", foreground="#ECEFF4")
        menubar.add_cascade(label="Data Extraction", menu=data_menu)
        data_menu.add_command(label="Extract SMS/Calls", command=self.extract_sms_calls)
        data_menu.add_command(label="Analyze Browser History", command=self.extract_browser_history)
        data_menu.add_command(label="Track Location", command=self.track_location)
        data_menu.add_command(label="Extract Social Media Artifacts", command=self.extract_social_media)
        data_menu.add_command(label="Extract App Data", command=self.extract_app_data)
        data_menu.add_command(label="Extract Wi-Fi Networks", command=self.display_wifi_networks)
        data_menu.add_command(label="Extract Geolocation Data", command=self.get_geolocation_data)

        # Create a "Analysis" menu
        analysis_menu = tk.Menu(menubar, tearoff=0, background="#4C566A", foreground="#ECEFF4")
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Generate File Hash", command=self.generate_file_hash)
        analysis_menu.add_command(label="Extract File Metadata", command=self.extract_file_metadata)
        analysis_menu.add_command(label="Analyze Network Traffic", command=self.analyze_network_traffic)
        analysis_menu.add_command(label="Perform Data Carving", command=self.data_carving)
        analysis_menu.add_command(label="Timeline Analysis", command=self.timeline_analysis)
        analysis_menu.add_command(label="Keyword Search", command=self.keyword_search)
        analysis_menu.add_command(label="Image Analysis", command=self.image_analysis)
        analysis_menu.add_command(label="Analyze APK", command=self.analyze_apk)
        analysis_menu.add_command(label="Analyze App Permissions", command=self.analyze_app_permissions)
        analysis_menu.add_command(label="Scan for Malware", command=self.scan_for_malware)
        analysis_menu.add_command(label="Scan USB for Malware", command=self.scan_usb_for_malware)

        # Create a "Data Clearing" menu
        clear_menu = tk.Menu(menubar, tearoff=0, background="#4C566A", foreground="#ECEFF4")
        menubar.add_cascade(label="Data Clearing", menu=clear_menu)
        clear_menu.add_command(label="Clear App Data", command=self.clear_app_data)
        clear_menu.add_command(label="Clear Cache", command=self.clear_cache)
        clear_menu.add_command(label="Factory Reset", command=self.factory_reset)

        # Create a "Reporting" menu
        report_menu = tk.Menu(menubar, tearoff=0, background="#4C566A", foreground="#ECEFF4")
        menubar.add_cascade(label="Reporting", menu=report_menu)
        report_menu.add_command(label="Export Report", command=self.export_report)
        report_menu.add_command(label="Analyze Results", command=self.analyze_results)

        # Create a main frame for the content
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create a scrolled text widget for output
        self.text = scrolledtext.ScrolledText(self.main_frame, height=20, width=80, font=("Helvetica", 12), bg="#3B4252", fg="#ECEFF4")
        self.text.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create a frame for displaying images or other content
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add a status bar at the bottom
        self.status_var.set("Ready")  # Set the initial status
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, background="#4C566A", foreground="#ECEFF4")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    def display_image(self, image_path):
        """Display the selected image in its original quality."""
        try:
            img = Image.open(image_path)
            img_tk = ImageTk.PhotoImage(img)

            # Create a frame inside the canvas to hold the image
            self.image_frame = ttk.Frame(self.canvas)
            self.canvas.create_window((0, 0), window=self.image_frame, anchor="nw")

            # Display the image
            label = tk.Label(self.image_frame, image=img_tk)
            label.image = img_tk  # Keep a reference to avoid garbage collection
            label.pack()

            # Update scroll region to include the entire image
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        except Exception as e:
            self.metadata_text.insert(tk.END, f"Error displaying image: {e}\n")

    def display_video(self, video_path):
        """Display the selected video in its original quality."""
        try:
            # Create a thread to play the video
            threading.Thread(target=self.play_video, args=(video_path,), daemon=True).start()
        except Exception as e:
            self.metadata_text.insert(tk.END, f"Error displaying video: {e}\n")

    def play_video(self, video_path):
        """Play the selected video using OpenCV."""
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                self.metadata_text.insert(tk.END, "Error: Could not open video file.\n")
                return

            # Create a new window for video playback
            video_window = tk.Toplevel(self.root)
            video_window.title(f"Video: {os.path.basename(video_path)}")

            # Create a canvas for the video
            video_canvas = tk.Canvas(video_window, bg="black")
            video_canvas.pack(fill=tk.BOTH, expand=True)

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                # Convert the frame to RGB and display it
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(frame)
                img_tk = ImageTk.PhotoImage(img)

                video_canvas.create_image(0, 0, anchor="nw", image=img_tk)
                video_canvas.image = img_tk  # Keep a reference to avoid garbage collection

                # Update the video window
                video_window.update()

                # Control playback speed
                cv2.waitKey(25)

            cap.release()
            video_window.destroy()
        except Exception as e:
            self.metadata_text.insert(tk.END, f"Error playing video: {e}\n")

    def load_files(self, directory):
        """Load files from the specified directory into the file listbox."""
        self.current_directory = directory
        self.file_listbox.delete(0, tk.END)
        for file in os.listdir(directory):
            self.file_listbox.insert(tk.END, file)

    def extract_photos(self):
        """Extract photos from the device and load them into the workspace."""
        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return

        if not self.device_id:
            self.status_var.set("No device connected. Please detect a device first.")
            return

        photo_dirs = ["/sdcard/DCIM/", "/sdcard/Pictures/", "/sdcard/Download/"]
        for directory in photo_dirs:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", directory, save_dir],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self.status_var.set(f"Photos extracted to {save_dir}")
                self.load_files(save_dir)
            else:
                self.status_var.set(f"Failed to extract photos: {result.stderr}")
    def generate_file_hash(self):
        """Generate a hash for a selected file."""
        file_path = filedialog.askopenfilename(title="Select File to Generate Hash")
        if not file_path:
            return

        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                buf = f.read()
                hasher.update(buf)
            file_hash = hasher.hexdigest()
            self.text.insert(tk.END, f"SHA-256 Hash of {file_path}: {file_hash}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error generating file hash: {e}\n")

    def scan_usb_for_malware(self):
        """Scan a connected USB drive for malware."""
        self.text.insert(tk.END, "Scanning USB drive for malware...\n")

        # Step 1: Detect USB drives
        usb_drives = self.detect_usb_drives()
        if not usb_drives:
            self.text.insert(tk.END, "No USB drives detected.\n")
            return

        # Step 2: Prompt the user to select a USB drive
        selected_drive = self.select_usb_drive(usb_drives)
        if not selected_drive:
            self.text.insert(tk.END, "No USB drive selected. Operation aborted.\n")
            return

        # Step 3: Perform the malware scan
        self.perform_malware_scan(selected_drive)

    def detect_usb_drives(self):
        """Detect connected USB drives."""
        usb_drives = []

        try:
            # Use system commands to detect USB drives
            if os.name == 'nt':  # Windows
                result = subprocess.run(["wmic", "logicaldisk", "get", "name,description"], capture_output=True, text=True)
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if "Removable" in line:
                        drive = line.split()[0]
                        usb_drives.append(drive)
            else:  # Linux/Mac
                result = subprocess.run(["lsblk", "-o", "NAME,MOUNTPOINT"], capture_output=True, text=True)
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if "/media/" in line or "/mnt/" in line:
                        drive = line.split()[-1]
                        usb_drives.append(drive)

            if usb_drives:
                self.text.insert(tk.END, f"Detected USB drives: {', '.join(usb_drives)}\n")
            else:
                self.text.insert(tk.END, "No USB drives detected.\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error detecting USB drives: {e}\n")

        return usb_drives

    def select_usb_drive(self, usb_drives):
        """Prompt the user to select a USB drive."""
        selected_drive = None

        try:
            if len(usb_drives) == 1:
                selected_drive = usb_drives[0]
                self.text.insert(tk.END, f"Selected USB drive: {selected_drive}\n")
            else:
                self.text.insert(tk.END, "Multiple USB drives detected. Please select one:\n")
                for i, drive in enumerate(usb_drives):
                    self.text.insert(tk.END, f"{i + 1}. {drive}\n")
                choice = simpledialog.askinteger("Select USB Drive", "Enter the number of the USB drive to scan:")
                if choice and 1 <= choice <= len(usb_drives):
                    selected_drive = usb_drives[choice - 1]
                    self.text.insert(tk.END, f"Selected USB drive: {selected_drive}\n")
                else:
                    self.text.insert(tk.END, "Invalid selection. Operation aborted.\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error selecting USB drive: {e}\n")

        return selected_drive

    def scan_for_suspicious_files(self, drive_path):
        """Scan the USB drive for suspicious files."""
        suspicious_files = []

        try:
        # Search for files with suspicious extensions or names
            for root_dir, _, files in os.walk(drive_path):
                for file in files:
                    if file.lower().endswith(('.exe', '.bat', '.dll', '.vbs', '.scr', '.cmd')):
                        suspicious_files.append(os.path.join(root_dir, file))

        except Exception as e:
            self.text.insert(tk.END, f"Error scanning for suspicious files: {e}\n")

        return suspicious_files


    def perform_malware_scan(self, drive_path):
        """Perform a malware scan on the selected USB drive."""
        self.text.insert(tk.END, f"Scanning {drive_path} for malware...\n")

        try:
         # Step 1: Search for suspicious files
            suspicious_files = self.scan_for_suspicious_files(drive_path)  # Pass drive_path here
            if suspicious_files:
                self.text.insert(tk.END, "Suspicious files found:\n")
                for file in suspicious_files:
                    self.text.insert(tk.END, f"- {file}\n")
            else:
                self.text.insert(tk.END, "No suspicious files found.\n")

        # Step 2: Generate a summary
            summary = self.generate_malware_scan_summary(suspicious_files)
            self.text.insert(tk.END, "\nMalware Scan Summary:\n")
            self.text.insert(tk.END, summary)

            # Step 3: Display a message box with the results
            messagebox.showinfo("Malware Scan Results", summary)

        except Exception as e:
            self.text.insert(tk.END, f"Error during malware scan: {e}\n")

    def generate_malware_scan_summary(self, suspicious_files):
        """Generate a summary of the malware scan results."""
        summary = "USB Malware Scan Summary:\n\n"

        # Add suspicious files to the summary
        if suspicious_files:
            summary += "Suspicious Files Found:\n"
            for file in suspicious_files:
                summary += f"- {file}\n"
        else:
            summary += "No suspicious files found.\n"

        # Add recommendations
        if suspicious_files:
            summary += "\nRecommendations:\n"
            summary += "- Remove or quarantine suspicious files.\n"
            summary += "- Scan the USB drive with a trusted antivirus tool.\n"
        else:
            summary += "\nThe USB drive appears to be clean.\n"

        return summary

    def analyze_results(self):
        """Analyze the results of forensic operations and display a summary."""
        self.text.insert(tk.END, "\n=== Result Analysis ===\n")

        # Example: Analyze extracted files
        if self.file_list:
            self.text.insert(tk.END, f"Total files extracted: {len(self.file_list)}\n")
            self.text.insert(tk.END, "Files extracted:\n")
            for file in self.file_list:
                self.text.insert(tk.END, f"- {file}\n")
        else:
            self.text.insert(tk.END, "No files extracted.\n")

        # Example: Analyze malware scan results
        if "malware_scan_results" in self.analysis_results:
            self.text.insert(tk.END, "\nMalware Scan Results:\n")
            self.text.insert(tk.END, self.analysis_results["malware_scan_results"])
        else:
            self.text.insert(tk.END, "\nNo malware scan results available.\n")

        # Example: Analyze image metadata
        if "image_metadata" in self.analysis_results:
            self.text.insert(tk.END, "\nImage Metadata Analysis:\n")
            self.text.insert(tk.END, self.analysis_results["image_metadata"])
        else:
            self.text.insert(tk.END, "\nNo image metadata analyzed.\n")

        # Example: Provide recommendations
        self.text.insert(tk.END, "\nRecommendations:\n")
        if "malware_scan_results" in self.analysis_results and "suspicious_files" in self.analysis_results["malware_scan_results"]:
            self.text.insert(tk.END, "- Remove or quarantine suspicious files.\n")
            self.text.insert(tk.END, "- Install a trusted antivirus app for further scanning.\n")
        else:
            self.text.insert(tk.END, "- No suspicious files detected. Your device appears to be clean.\n")

        self.text.insert(tk.END, "\n=== End of Analysis ===\n")

    def clear_workspace(self):
        """Clear the workspace content (text widget and content frame)."""
        self.text.delete(1.0, tk.END)  # Clear the text widget
        for widget in self.content_frame.winfo_children():  # Clear the content frame
            widget.destroy()
        self.text.insert(tk.END, "Workspace cleared.\n")

    def extract_app_data(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return

        self.text.insert(tk.END, "Extracting app data...\n")

        try:
        # List all installed apps
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "list", "packages"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                self.text.insert(tk.END, f"Failed to list installed apps: {result.stderr}\n")
                return

            packages = result.stdout.strip().split("\n")
            packages = [pkg.replace("package:", "") for pkg in packages]

        # Extract data for each app
            for package in packages:
                self.text.insert(tk.END, f"Extracting data for {package}...\n")
                result = subprocess.run(
                    ["adb", "-s", self.device_id, "backup", "-f", os.path.join(save_dir, f"{package}.ab"), package],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    self.text.insert(tk.END, f"App data for {package} extracted to {save_dir}\n")
                else:
                    self.text.insert(tk.END, f"Failed to extract app data for {package}: {result.stderr}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error extracting app data: {e}\n")
    
    def display_wifi_networks(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        try:
        # Extract Wi-Fi configuration file from the device
            wifi_config_path = "/data/misc/wifi/WifiConfigStore.xml"
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "su", "-c", f"cat {wifi_config_path}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.text.insert(tk.END, f"Failed to extract Wi-Fi networks: {result.stderr}\n")
                return

        # Display the Wi-Fi networks
            self.text.insert(tk.END, "Wi-Fi Networks:\n")
            self.text.insert(tk.END, result.stdout + "\n")

        except subprocess.TimeoutExpired:
            self.text.insert(tk.END, "Wi-Fi network extraction timed out.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error extracting Wi-Fi networks: {e}\n")
    
    def check_encryption_status(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        try:
        # Check encryption status using adb
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "getprop", "ro.crypto.state"],
                capture_output=True,
                text=True,
                timeout=10
            )
            encryption_status = result.stdout.strip()
            if encryption_status == "encrypted":
                self.text.insert(tk.END, "Device is encrypted.\n")
            else:
                self.text.insert(tk.END, "Device is not encrypted.\n")
        except subprocess.TimeoutExpired:
            self.text.insert(tk.END, "Encryption check timed out.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error checking encryption status: {e}\n")

    def check_root_status(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "su", "-c", "echo root"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "root" in result.stdout:
                self.text.insert(tk.END, "Device is rooted.\n")
            else:
                self.text.insert(tk.END, "Device is not rooted.\n")
        except subprocess.TimeoutExpired:
            self.text.insert(tk.END, "Root check timed out. Assuming non-rooted device.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error checking root status: {e}\n")

    def detect_device(self):
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")
        if len(lines) > 1:
            self.device_id = lines[1].split("\t")[0]
            self.text.insert(tk.END, f"Connected Device: {self.device_id}\n")
            self.list_files()  # Automatically list files when device is detected
        else:
            self.text.insert(tk.END, "No device detected. Enable USB debugging.\n")
            self.device_id = None

    def list_files(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected.\n")
            return
        result = subprocess.run(["adb", "-s", self.device_id, "shell", "ls", "/sdcard"], capture_output=True, text=True)
        self.file_list = result.stdout.strip().split("\n")
        self.text.insert(tk.END, "Files & Folders in /sdcard:\n" + "\n".join(self.file_list) + "\n")

    def extract_file(self):
        file_to_extract = simpledialog.askstring("Input", "Enter filename to extract (/sdcard/)")
        if not file_to_extract or file_to_extract not in self.file_list:
            messagebox.showerror("Error", "Invalid file name.")
            return
        save_dir = filedialog.askdirectory(title="Select Save Location")
        result = subprocess.run(["adb", "-s", self.device_id, "pull", f"/sdcard/{file_to_extract}", save_dir], capture_output=True, text=True)
        if result.returncode == 0:
            self.text.insert(tk.END, f"File extracted to {save_dir}\n")
            self.display_file_contents(os.path.join(save_dir, file_to_extract))
        else:
            self.text.insert(tk.END, f"Failed to extract file: {result.stderr}\n")

    def extract_device_info(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        self.text.insert(tk.END, "Extracting device information...\n")

        try:
            # Get device manufacturer and model
            manufacturer = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "getprop", "ro.product.manufacturer"],
                capture_output=True, text=True
            ).stdout.strip()

            model = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "getprop", "ro.product.model"],
                capture_output=True, text=True
            ).stdout.strip()

            # Get Android version
            android_version = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True
            ).stdout.strip()

            # Get device serial number
            serial_number = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "getprop", "ro.serialno"],
                capture_output=True, text=True
            ).stdout.strip()

            # Display the extracted information
            self.text.insert(tk.END, f"Manufacturer: {manufacturer}\n")
            self.text.insert(tk.END, f"Model: {model}\n")
            self.text.insert(tk.END, f"Android Version: {android_version}\n")
            self.text.insert(tk.END, f"Serial Number: {serial_number}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error extracting device information: {e}\n")

    def display_file_contents(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                self.text.insert(tk.END, f"Contents of {file_path}:\n{content}\n")
        except UnicodeDecodeError:
            self.text.insert(tk.END, f"Cannot display binary file: {file_path}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error reading file: {e}\n")

    def extract_photos(self):
        """Extract photos from the device."""
        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            self.status_var.set("Operation aborted.")  # Update the status bar
            return

        if not self.device_id:
            self.status_var.set("No device ID provided. Operation aborted.")  # Update the status bar
            return

        photo_dirs = ["/sdcard/DCIM/", "/sdcard/Pictures/", "/sdcard/Download/"]

        log_filename = os.path.join(save_dir, f"extraction_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

        with open(log_filename, "w") as log_file:
            log_file.write(f"Extraction started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for directory in photo_dirs:
                result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "test", "-d", directory],
                    capture_output=True, text=True
                )

                if result.returncode != 0:
                    log_file.write(f"Directory {directory} does not exist on the device.\n")
                    self.text.insert(tk.END, f"Directory {directory} does not exist on the device.\n")
                    continue

                result = subprocess.run(
                    ["adb", "-s", self.device_id, "pull", directory, save_dir],
                    capture_output=True, text=True
                )

                if result.returncode == 0:
                    success_message = f"Photos from {directory} successfully saved in {save_dir}\n"
                    self.text.insert(tk.END, success_message)
                    log_file.write(success_message)
                    self.display_extracted_content(save_dir)
                else:
                    failure_message = f"Failed to extract photos from {directory}: {result.stderr}\n"
                    self.text.insert(tk.END, failure_message)
                    log_file.write(failure_message)

                if os.path.isdir(save_dir):
                    extracted_files = os.listdir(save_dir)
                    if not extracted_files:
                        log_file.write("Warning: No files extracted.\n")
                        self.text.insert(tk.END, "Warning: No photos found in this directory.\n")
                    else:
                        log_file.write(f"Extracted files: {extracted_files}\n")

            log_file.write(f"\nExtraction completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        self.text.insert(tk.END, f"Extraction log saved at {log_filename}\n")
        self.status_var.set("Photo extraction completed.")  # Update the status bar
    def display_extracted_content(self, directory):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        self.split_workspace()
        self.display_file_list(directory)
        self.display_content(directory)

    def split_workspace(self):
        self.paned_window = tk.PanedWindow(self.content_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        self.left_frame = tk.Frame(self.paned_window, width=200, bg="lightgray")
        self.paned_window.add(self.left_frame)

        self.right_frame = tk.Frame(self.paned_window, bg="white")
        self.paned_window.add(self.right_frame)

    def display_file_list(self, directory):
        self.file_listbox = tk.Listbox(self.left_frame, selectmode=tk.SINGLE)
        self.file_listbox.pack(fill=tk.BOTH, expand=True)

        for root_dir, _, files in os.walk(directory):
            for file in files:
                self.file_listbox.insert(tk.END, file)

        self.file_listbox.bind("<<ListboxSelect>>", lambda event: self.display_selected_file(directory))

    def display_content(self, directory):
        for widget in self.right_frame.winfo_children():
            widget.destroy()

        first_file = self.file_listbox.get(0)
        if first_file:
            self.display_selected_file(directory, first_file)

    def display_selected_file(self, directory, selected_file=None):
        if not selected_file:
            selected_file = self.file_listbox.get(self.file_listbox.curselection())

        file_path = os.path.join(directory, selected_file)

        for widget in self.right_frame.winfo_children():
            widget.destroy()

        if selected_file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            self.display_image(file_path)
        elif selected_file.lower().endswith(('.mp4', '.avi', '.mkv')):
            self.display_video(file_path)
        else:
            self.display_file_contents(file_path)

    def display_image(self, image_path):
        try:
            img = Image.open(image_path)
            img.thumbnail((400, 400))  # Resize the image to fit the frame
            img = ImageTk.PhotoImage(img)
            label = tk.Label(self.right_frame, image=img)
            label.image = img  # Keep a reference to avoid garbage collection
            label.pack(fill=tk.BOTH, expand=True)
        except Exception as e:
            self.text.insert(tk.END, f"Error displaying image {image_path}: {e}\n")

    def display_video(self, video_path):
        try:
            self.text.insert(tk.END, f"Video file selected: {video_path}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error displaying video {video_path}: {e}\n")

    def display_file_contents(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                text_widget = tk.Text(self.right_frame, wrap=tk.WORD)
                text_widget.insert(tk.END, content)
                text_widget.pack(fill=tk.BOTH, expand=True)
        except UnicodeDecodeError:
            self.text.insert(tk.END, f"Cannot display binary file: {file_path}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error reading file: {e}\n")

    def recover_deleted_files(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return

        self.text.insert(tk.END, "Recovering deleted files...\n")

        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "su", "-c", "echo root"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "root" in result.stdout:
                self.text.insert(tk.END, "Device is rooted. Using photorec for recovery.\n")
                self.recover_with_photorec(save_dir)
            else:
                self.text.insert(tk.END, "Device is not rooted. Using alternative recovery methods.\n")
                self.recover_without_root(save_dir)

        except subprocess.TimeoutExpired:
            self.text.insert(tk.END, "Root check timed out. Assuming non-rooted device.\n")
            self.recover_without_root(save_dir)
        except Exception as e:
            self.text.insert(tk.END, f"Error during recovery: {e}\n")

    def recover_with_photorec(self, save_dir):
        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "which", "photorec"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "photorec" not in result.stdout:
                self.text.insert(tk.END, "Photorec is not available on the device.\n")
                return

            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "photorec", "/sdcard", save_dir],
                capture_output=True,
                text=True,
                timeout=600
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"Recovered files saved to {save_dir}\n")
            else:
                self.text.insert(tk.END, f"Failed to recover deleted files: {result.stderr}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error recovering deleted files: {e}\n")

    def recover_without_root(self, save_dir):
        try:
            self.text.insert(tk.END, "Attempting to recover files from /sdcard...\n")

            temp_dir = "/sdcard/recovered_files"
            subprocess.run(
                ["adb", "-s", self.device_id, "shell", "mkdir", "-p", temp_dir],
                capture_output=True,
                text=True,
                timeout=10
            )

            self.text.insert(tk.END, "Searching for deleted files...\n")
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "find", "/sdcard", "-type", "f", "-name", "*.tmp", "-o", "-name", "*.bak"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                deleted_files = result.stdout.strip().split("\n")
                if deleted_files:
                    self.text.insert(tk.END, f"Found {len(deleted_files)} potentially recoverable files.\n")

                    for file in deleted_files:
                        subprocess.run(
                            ["adb", "-s", self.device_id, "shell", "cp", file, temp_dir],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )

                    result = subprocess.run(
                        ["adb", "-s", self.device_id, "pull", temp_dir, save_dir],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    if result.returncode == 0:
                        self.text.insert(tk.END, f"Recovered files saved to {save_dir}\n")
                    else:
                        self.text.insert(tk.END, f"Failed to pull recovered files: {result.stderr}\n")
                else:
                    self.text.insert(tk.END, "No recoverable files found.\n")
            else:
                self.text.insert(tk.END, f"Failed to search for deleted files: {result.stderr}\n")

            subprocess.run(
                ["adb", "-s", self.device_id, "shell", "rm", "-rf", temp_dir],
                capture_output=True,
                text=True,
                timeout=10
            )

        except Exception as e:
            self.text.insert(tk.END, f"Error recovering files on non-rooted device: {e}\n")

    def create_adb_backup(self):
        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return
        try:
            backup_file = os.path.join(save_dir, "backup.ab")
            result = subprocess.run(
                ["adb", "-s", self.device_id, "backup", "-all", "-f", backup_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"ADB backup created at {backup_file}\n")
                self.convert_backup_to_tar(backup_file, save_dir)
            else:
                self.text.insert(tk.END, f"Failed to create ADB backup: {result.stderr}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error creating ADB backup: {e}\n")

    def convert_backup_to_tar(self, backup_file, save_dir):
        try:
            tar_file = os.path.join(save_dir, "backup.tar")
            result = subprocess.run(
                ["java", "-jar", "abe.jar", "unpack", backup_file, tar_file],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"Backup converted to tar format at {tar_file}\n")
            else:
                self.text.insert(tk.END, f"Failed to convert backup: {result.stderr}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error converting backup: {e}\n")

    def extract_social_media(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return

        self.text.insert(tk.END, "Extracting social media artifacts...\n")

        self.extract_whatsapp_data(save_dir)
        self.extract_instagram_data(save_dir)

        self.text.insert(tk.END, "Social media artifact extraction completed.\n")

    def extract_whatsapp_data(self, save_dir):
        try:
            whatsapp_backup_path = "/sdcard/WhatsApp/Databases/msgstore.db.crypt12"
            whatsapp_media_path = "/sdcard/WhatsApp/Media/"

            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", whatsapp_backup_path, save_dir],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"WhatsApp backup database extracted to {save_dir}\n")
            else:
                self.text.insert(tk.END, f"Failed to extract WhatsApp backup database: {result.stderr}\n")

            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", whatsapp_media_path, os.path.join(save_dir, "WhatsApp_Media")],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"WhatsApp media files extracted to {os.path.join(save_dir, 'WhatsApp_Media')}\n")
            else:
                self.text.insert(tk.END, f"Failed to extract WhatsApp media files: {result.stderr}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error extracting WhatsApp data: {e}\n")

    def extract_instagram_data(self, save_dir):
        try:
            self.text.insert(tk.END, "Instagram data extraction requires the user to export data manually via the app.\n")
            self.text.insert(tk.END, "Please use Instagram's 'Download Your Data' feature and transfer the file to the device.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error extracting Instagram data: {e}\n")

    def extract_sms_calls(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return

        sms_db = "/data/data/com.android.providers.telephony/databases/mmssms.db"
        call_db = "/data/data/com.android.providers.contacts/databases/calllog.db"

        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "test", "-f", sms_db],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                self.text.insert(tk.END, f"SMS database not found: {sms_db}\n")
                return

            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", sms_db, save_dir],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"SMS database extracted to {save_dir}\n")
                self.display_sms_logs(os.path.join(save_dir, "mmssms.db"))
            else:
                self.text.insert(tk.END, f"Failed to extract SMS database: {result.stderr}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error during extraction: {e}\n")

    def convert_backup_to_tar(self, backup_file, save_dir):
        try:
            tar_file = os.path.join(save_dir, "sms_call_backup.tar")
            self.text.insert(tk.END, "Converting backup to tar format...\n")

            result = subprocess.run(
                ["java", "-jar", "abe.jar", "unpack", backup_file, tar_file],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                self.text.insert(tk.END, f"Backup converted to tar format at {tar_file}\n")
                self.extract_sms_calls_from_tar(tar_file, save_dir)
            else:
                self.text.insert(tk.END, f"Failed to convert backup: {result.stderr}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error converting backup: {e}\n")

    def extract_sms_calls_from_tar(self, tar_file, save_dir):
        try:
            import tarfile

            self.text.insert(tk.END, "Extracting SMS and Call Logs from tar file...\n")

            with tarfile.open(tar_file, "r") as tar:
                tar.extractall(path=save_dir)

            sms_db_path = os.path.join(save_dir, "apps/com.android.providers.telephony/db/mmssms.db")
            call_db_path = os.path.join(save_dir, "apps/com.android.providers.telephony/db/calllog.db")

            if os.path.exists(sms_db_path):
                self.text.insert(tk.END, "SMS database found. Extracting SMS logs...\n")
                self.display_sms_logs(sms_db_path)
            else:
                self.text.insert(tk.END, "SMS database not found in backup.\n")

            if os.path.exists(call_db_path):
                self.text.insert(tk.END, "Call Log database found. Extracting Call Logs...\n")
                self.display_call_logs(call_db_path)
            else:
                self.text.insert(tk.END, "Call Log database not found in backup.\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error extracting SMS and Call Logs: {e}\n")

    def extract_browser_history(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:  # Check if the user canceled the dialog
            self.text.insert(tk.END, "No save directory selected. Operation aborted.\n")
            return

        history_db = "/data/data/com.android.chrome/app_chrome/Default/History"

        try:
            # Check if the history database exists on the device
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "test", "-f", history_db],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                self.text.insert(tk.END, f"Browser history database not found: {history_db}\n")
                return

        # Extract the browser history database
            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", history_db, save_dir],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                self.text.insert(tk.END, f"Browser history extracted to {save_dir}\n")
                self.display_browser_history(os.path.join(save_dir, "History"))
            else:
                self.text.insert(tk.END, f"Failed to extract browser history: {result.stderr}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error extracting browser history: {e}\n")

    def display_browser_history(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, last_visit_time FROM urls")
            history_logs = cursor.fetchall()
            self.text.insert(tk.END, "Browser History:\n")
            for log in history_logs:
                self.text.insert(tk.END, f"URL: {log[0]}, Title: {log[1]}, Last Visited: {log[2]}\n")
            conn.close()
        except Exception as e:
            self.text.insert(tk.END, f"Error reading browser history: {e}\n")

    def track_location(self):
        save_dir = filedialog.askdirectory(title="Select Save Location")
        location_db = "/data/data/com.google.android.gms/databases/locations.db"
        result = subprocess.run(["adb", "-s", self.device_id, "pull", location_db, save_dir], capture_output=True, text=True)
        if result.returncode == 0:
            self.text.insert(tk.END, f"Location history extracted to {save_dir}\n")
            self.display_location_history(os.path.join(save_dir, "locations.db"))
        else:
            self.text.insert(tk.END, f"Failed to extract location history: {result.stderr}\n")

    def display_location_history(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, latitude, longitude FROM locations")
            location_logs = cursor.fetchall()
            self.text.insert(tk.END, "Location History:\n")
            for log in location_logs:
                self.text.insert(tk.END, f"Timestamp: {log[0]}, Latitude: {log[1]}, Longitude: {log[2]}\n")
            conn.close()
        except Exception as e:
            self.text.insert(tk.END, f"Error reading location history: {e}\n")

    def generate_file_hash(self):
        file_path = filedialog.askopenfilename(title="Select File to Generate Hash")
        if not file_path:
            return
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        file_hash = hasher.hexdigest()
        self.text.insert(tk.END, f"SHA-256 Hash of {file_path}: {file_hash}\n")

    def extract_file_metadata(self):
        file_path = filedialog.askopenfilename(title="Select File to Extract Metadata")
        if not file_path:
            return
        file_stats = os.stat(file_path)
        metadata = {
            "File Name": os.path.basename(file_path),
            "File Size (Bytes)": file_stats.st_size,
            "Last Modified": datetime.datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "File Type": os.path.splitext(file_path)[1]
        }
        self.text.insert(tk.END, "File Metadata:\n" + json.dumps(metadata, indent=4) + "\n")

    def analyze_network_traffic(self):
        pcap_file = filedialog.askopenfilename(title="Select PCAP File for Analysis")
        if not pcap_file:
            return
        packets = rdpcap(pcap_file)
        self.text.insert(tk.END, f"Total Packets: {len(packets)}\n")
        for i, packet in enumerate(packets[:10]):  # Display first 10 packets
            self.text.insert(tk.END, f"Packet {i+1}:\n{packet.summary()}\n")

    def data_carving(self):
        image_path = filedialog.askopenfilename(title="Select Disk Image for Data Carving")
        if not image_path:
            return
        save_dir = filedialog.askdirectory(title="Select Save Location")
        self.text.insert(tk.END, f"Performing data carving on {image_path}. Results will be saved in {save_dir}\n")

    def timeline_analysis(self):
        directory = filedialog.askdirectory(title="Select Directory for Timeline Analysis")
        if not directory:
            return
        self.text.insert(tk.END, f"Performing timeline analysis on {directory}\n")

    def keyword_search(self):
        directory = filedialog.askdirectory(title="Select Directory for Keyword Search")
        if not directory:
            return
        keyword = simpledialog.askstring("Input", "Enter keyword to search")
        if not keyword:
            return
        self.text.insert(tk.END, f"Searching for '{keyword}' in {directory}\n")

    def image_analysis(self):
        image_path = filedialog.askopenfilename(title="Select Image for Analysis")
        if not image_path:
            return

        self.text.insert(tk.END, f"Analyzing image: {image_path}\n")

        try:
            self.extract_exif_metadata(image_path)
            self.generate_image_hash(image_path)
            self.detect_image_tampering(image_path)
            self.extract_gps_data(image_path)
            self.check_for_hidden_data(image_path)

        except UnidentifiedImageError:
            self.text.insert(tk.END, "Error: The selected file is not a valid image.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error during image analysis: {e}\n")

    def extract_exif_metadata(self, image_path):
        try:
            with Image.open(image_path) as img:
                exif_data = img._getexif()
                if exif_data:
                    self.text.insert(tk.END, "EXIF Metadata:\n")
                    for tag_id, value in exif_data.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        self.text.insert(tk.END, f"{tag_name}: {value}\n")
                else:
                    self.text.insert(tk.END, "No EXIF metadata found.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error extracting EXIF metadata: {e}\n")

    def generate_image_hash(self, image_path):
        try:
            with open(image_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                self.text.insert(tk.END, f"SHA-256 Hash: {file_hash}\n")

            img = Image.open(image_path)
            phash = imagehash.phash(img)
            self.text.insert(tk.END, f"Perceptual Hash (pHash): {phash}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error generating image hash: {e}\n")

    def detect_image_tampering(self, image_path):
        try:
            from PIL import ImageChops, ImageEnhance
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp_file:
                tmp_path = tmp_file.name
                img = Image.open(image_path)
                img.save(tmp_path, "JPEG", quality=95)

                original = Image.open(image_path).convert("L")
                resaved = Image.open(tmp_path).convert("L")

                ela_image = ImageChops.difference(original, resaved)
                ela_image = ImageEnhance.Brightness(ela_image).enhance(10)

                ela_path = os.path.join(os.path.dirname(image_path), "ela_result.jpg")
                ela_image.save(ela_path)
                self.text.insert(tk.END, f"ELA result saved to: {ela_path}\n")

                self.display_image(ela_path)

        except Exception as e:
            self.text.insert(tk.END, f"Error detecting image tampering: {e}\n")

    def extract_gps_data(self, image_path):
        try:
            with Image.open(image_path) as img:
                exif_data = img._getexif()
                if not exif_data:
                    self.text.insert(tk.END, "No GPS data found.\n")
                    return

                gps_info = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == "GPSInfo":
                        for gps_tag_id in value:
                            gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_info[gps_tag_name] = value[gps_tag_id]

                if gps_info:
                    self.text.insert(tk.END, "GPS Data:\n")
                    for key, value in gps_info.items():
                        self.text.insert(tk.END, f"{key}: {value}\n")
                else:
                    self.text.insert(tk.END, "No GPS data found.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error extracting GPS data: {e}\n")

    def check_for_hidden_data(self, image_path):
        try:
            self.text.insert(tk.END, f"Checking for hidden data in {image_path}...\n")

            img = Image.open(image_path)

            self.text.insert(tk.END, "Checking for LSB steganography...\n")
            self.detect_lsb_steganography(img)

            self.text.insert(tk.END, "Checking for metadata anomalies...\n")
            self.check_metadata_anomalies(img)

            self.text.insert(tk.END, "Checking for hidden files using binwalk...\n")
            self.check_for_hidden_files(image_path)

            self.text.insert(tk.END, "Checking for steganography using stegano...\n")
            self.check_stegano_library(image_path)

            self.text.insert(tk.END, "Hidden data check completed.\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error checking for hidden data: {e}\n")

    def detect_lsb_steganography(self, img):
        try:
            img = img.convert("RGB")
            pixels = img.load()

            lsb_data = []
            for y in range(img.height):
                for x in range(img.width):
                    r, g, b = pixels[x, y]
                    lsb_data.append(r & 1)
                    lsb_data.append(g & 1)
                    lsb_data.append(b & 1)

            if any(lsb_data):
                self.text.insert(tk.END, "Potential LSB steganography detected.\n")
            else:
                self.text.insert(tk.END, "No LSB steganography detected.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error detecting LSB steganography: {e}\n")

    def check_metadata_anomalies(self, img):
        try:
            exif_data = img._getexif()
            if exif_data:
                self.text.insert(tk.END, "EXIF Metadata:\n")
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    self.text.insert(tk.END, f"{tag_name}: {value}\n")

                suspicious_fields = ["Software", "Comment", "Artist"]
                for field in suspicious_fields:
                    if field in exif_data:
                        self.text.insert(tk.END, f"Suspicious metadata field found: {field}\n")
            else:
                self.text.insert(tk.END, "No EXIF metadata found.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error checking metadata anomalies: {e}\n")

    def check_for_hidden_files(self, image_path):
        try:
            result = subprocess.run(
                ["binwalk", image_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.text.insert(tk.END, "Binwalk results:\n")
                self.text.insert(tk.END, result.stdout + "\n")
            else:
                self.text.insert(tk.END, f"Binwalk failed: {result.stderr}\n")
        except FileNotFoundError:
            self.text.insert(tk.END, "Binwalk is not installed. Please install it to check for hidden files.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error running binwalk: {e}\n")

    def check_stegano_library(self, image_path):
        try:
            from stegano import lsb

            hidden_message = lsb.reveal(image_path)
            if hidden_message:
                self.text.insert(tk.END, f"Hidden message found using stegano: {hidden_message}\n")
            else:
                self.text.insert(tk.END, "No hidden message found using stegano.\n")
        except ImportError:
            self.text.insert(tk.END, "Stegano library is not installed. Install it using: pip install stegano\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error using stegano library: {e}\n")

    def display_image(self, image_path):
        try:
            img = Image.open(image_path)
            img.thumbnail((300, 300))
            img = ImageTk.PhotoImage(img)
            label = tk.Label(self.content_frame, image=img)
            label.image = img  # Keep a reference to avoid garbage collection
            label.pack(side=tk.LEFT, padx=5, pady=5)
        except Exception as e:
            self.text.insert(tk.END, f"Error displaying image: {e}\n")
    
    def get_geolocation_data(self):
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        save_dir = filedialog.askdirectory(title="Select Save Location")
        if not save_dir:
            return

        self.text.insert(tk.END, "Extracting geolocation data...\n")

        try:
        # Extract geolocation data from the device
            geolocation_db = "/data/data/com.google.android.gms/databases/locations.db"
            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", geolocation_db, save_dir],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                self.text.insert(tk.END, f"Geolocation data extracted to {save_dir}\n")
                self.display_geolocation_data(os.path.join(save_dir, "locations.db"))
            else:
                self.text.insert(tk.END, f"Failed to extract geolocation data: {result.stderr}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error extracting geolocation data: {e}\n")

    def display_geolocation_data(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, latitude, longitude FROM locations")
            location_logs = cursor.fetchall()
            self.text.insert(tk.END, "Geolocation Data:\n")
            for log in location_logs:
                self.text.insert(tk.END, f"Timestamp: {log[0]}, Latitude: {log[1]}, Longitude: {log[2]}\n")
            conn.close()
        except Exception as e:
            self.text.insert(tk.END, f"Error reading geolocation data: {e}\n")

    def analyze_apk(self):
        """Analyze an APK file to extract information such as permissions, activities, and services."""
        apk_path = filedialog.askopenfilename(title="Select APK File for Analysis", filetypes=[("APK Files", "*.apk")])
        if not apk_path:
            return

        self.text.insert(tk.END, f"Analyzing APK: {apk_path}\n")

        try:
            # Extract the APK file
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Extract the AndroidManifest.xml file
                manifest = apk_zip.read('AndroidManifest.xml')
                
                # Parse the manifest file
                from xml.etree import ElementTree as ET
                root = ET.fromstring(manifest)
                
                # Extract permissions
                permissions = []
                for item in root.findall("uses-permission"):
                    permissions.append(item.attrib["{http://schemas.android.com/apk/res/android}name"])
                
                # Extract activities
                activities = []
                for item in root.findall("application/activity"):
                    activities.append(item.attrib["{http://schemas.android.com/apk/res/android}name"])
                
                # Extract services
                services = []
                for item in root.findall("application/service"):
                    services.append(item.attrib["{http://schemas.android.com/apk/res/android}name"])
                
                # Display the extracted information
                self.text.insert(tk.END, "Permissions:\n")
                for perm in permissions:
                    self.text.insert(tk.END, f"- {perm}\n")
                
                self.text.insert(tk.END, "\nActivities:\n")
                for activity in activities:
                    self.text.insert(tk.END, f"- {activity}\n")
                
                self.text.insert(tk.END, "\nServices:\n")
                for service in services:
                    self.text.insert(tk.END, f"- {service}\n")
        
        except Exception as e:
            self.text.insert(tk.END, f"Error analyzing APK: {e}\n")

    def analyze_app_permissions(self):
        """Analyze the permissions of an APK file."""
        apk_path = filedialog.askopenfilename(
            title="Select APK File for Permission Analysis",
            filetypes=[("APK Files", "*.apk")]
        )
        if not apk_path:
            return

        self.text.insert(tk.END, f"Analyzing permissions for APK: {apk_path}\n")

        try:
        # Extract the APK file
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            # Extract the AndroidManifest.xml file
                manifest = apk_zip.read('AndroidManifest.xml')
            
            # Parse the manifest file
                from xml.etree import ElementTree as ET
                root = ET.fromstring(manifest)
            
            # Extract permissions
                permissions = []
                for item in root.findall("uses-permission"):
                    permissions.append(item.attrib["{http://schemas.android.com/apk/res/android}name"])
            
            # Display the extracted permissions
                self.text.insert(tk.END, "Permissions:\n")
                for perm in permissions:
                    self.text.insert(tk.END, f"- {perm}\n")
    
        except Exception as e:
            self.text.insert(tk.END, f"Error analyzing APK permissions: {e}\n")
    def scan_for_malware(self):
        """Scan the entire device for malware and display a detailed report."""
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        self.text.insert(tk.END, "Scanning the device for malware...\n")

        try:
            # Step 1: Scan for suspicious files
            self.text.insert(tk.END, "Scanning for suspicious files...\n")
            suspicious_files = self.scan_for_suspicious_files()
            if suspicious_files:
                self.text.insert(tk.END, "Suspicious files found:\n")
                for file in suspicious_files:
                    self.text.insert(tk.END, f"- {file}\n")
            else:
                self.text.insert(tk.END, "No suspicious files found.\n")

        # Step 2: Scan for suspicious apps
            self.text.insert(tk.END, "Scanning for suspicious apps...\n")
            suspicious_apps = self.scan_for_suspicious_apps()
            if suspicious_apps:
                self.text.insert(tk.END, "Suspicious apps found:\n")
                for app, reason in suspicious_apps:
                    self.text.insert(tk.END, f"- {app}: {reason}\n")
            else:
                self.text.insert(tk.END, "No suspicious apps found.\n")

        # Step 3: Generate a summary
            summary = self.generate_malware_scan_summary(suspicious_files, suspicious_apps)
            self.text.insert(tk.END, "\nMalware Scan Summary:\n")
            self.text.insert(tk.END, summary)

        # Step 4: Display a message box with the results
            messagebox.showinfo("Malware Scan Results", summary)

        except Exception as e:
            self.text.insert(tk.END, f"Error during malware scan: {e}\n")


    def scan_for_suspicious_files(self):
        """Scan the device for suspicious files."""
        suspicious_files = []

        try:
            # Search for files with suspicious extensions or names
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "find", "/sdcard", "-type", "f", 
                "-name", "*.apk", "-o", "-name", "*.exe", "-o", "-name", "*.bat"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                files = result.stdout.strip().split("\n")
                for file in files:
                    if file:  # Skip empty lines
                        suspicious_files.append(file)
            else:
                self.text.insert(tk.END, f"Failed to scan for suspicious files: {result.stderr}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error scanning for suspicious files: {e}\n")

        return suspicious_files


    def scan_for_suspicious_apps(self):
        """Scan the device for suspicious apps."""
        suspicious_apps = []

        try:
            # List all installed apps
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "list", "packages", "-3"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.text.insert(tk.END, f"Failed to list installed apps: {result.stderr}\n")
                return suspicious_apps

            packages = result.stdout.strip().split("\n")
            packages = [pkg.replace("package:", "") for pkg in packages]

            # Check each app for suspicious permissions
            for package in packages:
                result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "dumpsys", "package", package],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode != 0:
                    self.text.insert(tk.END, f"Failed to scan {package}: {result.stderr}\n")
                    continue

            # Look for suspicious permissions
                suspicious_permissions = [
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.READ_CONTACTS",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.CAMERA",
                    "android.permission.RECORD_AUDIO"
                ]

                for perm in suspicious_permissions:
                    if perm in result.stdout:
                        suspicious_apps.append((package, f"Suspicious permission: {perm}"))
                        break

        except Exception as e:
            self.text.insert(tk.END, f"Error scanning for suspicious apps: {e}\n")

        return suspicious_apps


    def generate_malware_scan_summary(self, suspicious_files, suspicious_apps):
        """Generate a summary of the malware scan results."""
        summary = "Malware Scan Summary:\n\n"

    # Add suspicious files to the summary
        if suspicious_files:
            summary += "Suspicious Files Found:\n"
            for file in suspicious_files:
                summary += f"- {file}\n"
        else:
            summary += "No suspicious files found.\n"

    # Add suspicious apps to the summary
        if suspicious_apps:
            summary += "\nSuspicious Apps Found:\n"
            for app, reason in suspicious_apps:
                summary += f"- {app}: {reason}\n"
        else:
            summary += "\nNo suspicious apps found.\n"

    # Add recommendations
        if suspicious_files or suspicious_apps:
            summary += "\nRecommendations:\n"
            summary += "- Remove or quarantine suspicious files and apps.\n"
            summary += "- Install a trusted antivirus app for further scanning.\n"
        else:
            summary += "\nYour device appears to be clean.\n"

        return summary
    
    def clear_app_data(self):
        """Clear app data for a selected app on the connected device (non-rooted)."""
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        self.text.insert(tk.END, "Clearing app data...\n")

        try:
        # Use ADB to list installed apps
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "list", "packages", "-3"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.text.insert(tk.END, f"Failed to list installed apps: {result.stderr}\n")
                return

        # Extract package names
            packages = result.stdout.strip().split("\n")
            packages = [pkg.replace("package:", "") for pkg in packages]

            if not packages:
                self.text.insert(tk.END, "No third-party apps found to clear data.\n")
                return

        # Prompt the user to select an app
            selected_package = simpledialog.askstring("Input", "Enter the package name of the app to clear data:")
            if not selected_package:
                self.text.insert(tk.END, "No package name provided. Operation aborted.\n")
                return

            if selected_package not in packages:
                self.text.insert(tk.END, f"Package '{selected_package}' not found on the device.\n")
                return

        # Clear app data
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "clear", selected_package],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.text.insert(tk.END, f"App data cleared for package: {selected_package}\n")
            else:
                self.text.insert(tk.END, f"Failed to clear app data: {result.stderr}\n")

        except subprocess.TimeoutExpired:
            self.text.insert(tk.END, "Operation timed out.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error clearing app data: {e}\n")

    def clear_cache(self):
        """Clear the cache for a selected app on the connected device."""
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        self.text.insert(tk.END, "Clearing cache...\n")

        try:
        # Use ADB to list installed apps
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "list", "packages", "-3"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.text.insert(tk.END, f"Failed to list installed apps: {result.stderr}\n")
                return

        # Extract package names
            packages = result.stdout.strip().split("\n")
            packages = [pkg.replace("package:", "") for pkg in packages]

            if not packages:
                self.text.insert(tk.END, "No third-party apps found to clear cache.\n")
                return

        # Prompt the user to select an app
            selected_package = simpledialog.askstring("Input", "Enter the package name of the app to clear cache:")
            if not selected_package:
                self.text.insert(tk.END, "No package name provided. Operation aborted.\n")
                return

            if selected_package not in packages:
                self.text.insert(tk.END, f"Package '{selected_package}' not found on the device.\n")
                return

        # Clear app cache
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "clear", "--cache-only", selected_package],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.text.insert(tk.END, f"Cache cleared for package: {selected_package}\n")
            else:
                self.text.insert(tk.END, f"Failed to clear cache: {result.stderr}\n")

        except subprocess.TimeoutExpired:
            self.text.insert(tk.END, "Operation timed out.\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error clearing cache: {e}\n")

    def factory_reset(self):
        """Perform a factory reset on the connected device."""
        if not self.device_id:
            self.text.insert(tk.END, "No device connected. Please detect a device first.\n")
            return

        confirmation = messagebox.askyesno(
            "Confirm Factory Reset",
            "Are you sure you want to perform a factory reset? This will erase all data on the device!"
        )
        if not confirmation:
            self.text.insert(tk.END, "Factory reset canceled.\n")
            return

        try:
            self.text.insert(tk.END, "Performing factory reset...\n")
            result = subprocess.run(
                ["adb", "-s", self.device_id, "reboot", "recovery"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self.text.insert(tk.END, "Device rebooted into recovery mode. Please manually confirm the factory reset.\n")
            else:
                self.text.insert(tk.END, f"Failed to reboot into recovery mode: {result.stderr}\n")
        except Exception as e:
            self.text.insert(tk.END, f"Error performing factory reset: {e}\n")

    def export_report(self):
        """Export the forensic report to a PDF file."""
        save_path = filedialog.asksaveasfilename(
            title="Save Report As",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")]
        )
        if not save_path:
            return

        try:
        # Create a PDF document
            c = canvas.Canvas(save_path, pagesize=letter)
            width, height = letter

        # Add content to the PDF
            c.setFont("Helvetica", 12)
            c.drawString(50, height - 50, "Digital Forensic Report")
            c.drawString(50, height - 70, "=" * 50)

        # Get the content from the text widget
            report_content = self.text.get(1.0, tk.END)
            lines = report_content.split("\n")

        # Write the content to the PDF
            y_position = height - 100
            for line in lines:
                if y_position < 50:  # Add a new page if the content exceeds the page height
                    c.showPage()
                    y_position = height - 50
                    c.setFont("Helvetica", 12)
                c.drawString(50, y_position, line)
                y_position -= 15

        # Save the PDF
            c.save()
            self.text.insert(tk.END, f"Report exported to {save_path}\n")

        except Exception as e:
            self.text.insert(tk.END, f"Error exporting report: {e}\n")

   


# Registration Window
class RegistrationWindow:
    def __init__(self):
        self.window = tk.Toplevel()
        self.window.title("Register")
        self.window.geometry("400x250")

        # Username
        self.label_username = tk.Label(self.window, text="Username:")
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(self.window)
        self.entry_username.pack(pady=5)

        # Password
        self.label_password = tk.Label(self.window, text="Password:")
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(self.window, show="*")
        self.entry_password.pack(pady=5)

        # Confirm Password
        self.label_confirm_password = tk.Label(self.window, text="Confirm Password:")
        self.label_confirm_password.pack(pady=5)
        self.entry_confirm_password = tk.Entry(self.window, show="*")
        self.entry_confirm_password.pack(pady=5)

        # Register Button
        self.button_register = tk.Button(self.window, text="Register", command=self.register)
        self.button_register.pack(pady=10)

    def register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        confirm_password = self.entry_confirm_password.get()

        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),  # Call the standalone function
            )
            conn.commit()
            messagebox.showinfo("Success", "Registration successful! You can now log in.")
            self.window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")
        finally:
            conn.close()


# Login Window
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("400x250")

        # Username
        self.label_username = tk.Label(root, text="Username:")
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(root)
        self.entry_username.pack(pady=5)

        # Password
        self.label_password = tk.Label(root, text="Password:")
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(root, show="*")
        self.entry_password.pack(pady=5)

        # Login Button
        self.button_login = tk.Button(root, text="Login", command=self.authenticate)
        self.button_login.pack(pady=10)

        # Register Button
        self.button_register = tk.Button(root, text="Register", command=self.open_registration)
        self.button_register.pack(pady=5)

        # Forgot Password Button
        self.button_forgot_password = tk.Button(root, text="Forgot Password", command=self.open_password_recovery)
        self.button_forgot_password.pack(pady=5)

    def authenticate(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and verify_password(password, result[0]):  # Call the standalone function
            self.root.destroy()
            self.launch_main_app(username)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def open_registration(self):
        RegistrationWindow()

    def open_password_recovery(self):
        PasswordRecoveryWindow()

    def launch_main_app(self, username):
        root = tk.Tk()
        app = AdvancedForensicTool(root, username)
        root.mainloop()


# Main Application


    if __name__ == "__main__":
        initialize_db()
        root = tk.Tk()
        login_app = LoginWindow(root)
        root.mainloop()
        def __init__(self, root, username):
            self.root = root
            self.username = username
            self.root.title(f"Advanced Digital Forensic Tool - Welcome, {username}")
            self.root.geometry("1000x700")
            self.device_id = None
            self.file_list = []
            self.is_running = False  # Add this line to track if a process is running
            self.status_var = tk.StringVar()  # Add this line to initialize the status variable
            self.setup_ui()  # Call the setup_ui method