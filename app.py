import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import os
import numpy as np
import binascii
import traceback
import uuid
import re
import string
import json
import mimetypes
import hashlib
import time
from datetime import datetime
from collections import defaultdict, Counter, deque
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from PIL import Image
import math
import warnings
warnings.filterwarnings('ignore')


import os
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'frontend', 'templates'))
STATIC_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'frontend', 'static'))

print("\n" + "="*50)
print("🔍 PATH DEBUGGING INFO")
print(f"1. app.py is located at: {BASE_DIR}")
print(f"2. Flask is looking for templates in: {TEMPLATE_DIR}")
print(f"3. Does the templates folder exist? {os.path.exists(TEMPLATE_DIR)}")
print(f"4. Does index.html exist? {os.path.exists(os.path.join(TEMPLATE_DIR, 'index.html'))}")
print("="*50 + "\n")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

app.config['VAULT_FOLDER'] = 'secure_vault'
os.makedirs(app.config['VAULT_FOLDER'], exist_ok=True)
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['PAYLOAD_FOLDER'] = os.path.join(BASE_DIR, 'payloads')
app.config['DNA_FOLDER'] = os.path.join(BASE_DIR, 'dna_profiles')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PAYLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DNA_FOLDER'], exist_ok=True)

import mimetypes
mimetypes.init()


import os
import numpy as np
import hashlib
import json
import re
import struct
import math
import binascii
from datetime import datetime
from collections import defaultdict, Counter, deque
import warnings
warnings.filterwarnings('ignore')

class FileTypeValidator:
    """Accurate file type detection using magic bytes"""
    
    # Clean media file signatures
    MEDIA_SIGNATURES = {
        'JPEG': [b'\xFF\xD8\xFF'],
        'PNG': [b'\x89PNG'],
        'GIF': [b'GIF8'],
        'BMP': [b'BM'],
        'TIFF': [b'II*\x00', b'MM\x00*'],
        'WEBP': [b'RIFF'],
        'ICO': [b'\x00\x00\x01\x00'],
        'MP3': [b'\xff\xfb', b'\xff\xf3', b'\xff\xf2', b'ID3'],
        'WAV': [b'RIFF'],
        'FLAC': [b'fLaC'],
        'OGG': [b'OggS'],
        'MP4': [b'\x00\x00\x00', b'ftyp'],
        'AVI': [b'RIFF'],
        'MKV': [b'\x1aE\xdf\xa3'],
        'MOV': [b'\x00\x00\x00', b'moov', b'ftyp'],
        'PDF': [b'%PDF'],
        'HTML': [b'<!DOCTYPE', b'<html'],
        'XML': [b'<?xml'],
        'JSON': [b'{', b'['],
        'ZIP': [b'PK\x03\x04'],
        'RAR': [b'Rar!\x1a\x07'],
        'GZIP': [b'\x1f\x8b\x08'],
    }
    
    # Executable signatures
    EXECUTABLE_SIGNATURES = {
        'PE_EXE': [b'MZ'],
        'ELF': [b'\x7fELF'],
        'MACH_O': [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'],
        'DEX': [b'dex\n'],
        'JAVA_CLASS': [b'\xca\xfe\xba\xbe'],
        'SCRIPT_BAT': [b'@echo off', b'@ECHO OFF'],
        'SCRIPT_PS1': [b'Invoke-', b'Set-ExecutionPolicy', b'Write-Host'],
        'SCRIPT_VBS': [b'CreateObject', b'WScript.Shell'],
        'SCRIPT_SH': [b'#!/bin/', b'#!/usr/bin/'],
    }
    
    @classmethod
    def identify_file_type(cls, filepath):
        """Identify actual file type from magic bytes"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(512)
            
            # Check executables first
            for file_type, signatures in cls.EXECUTABLE_SIGNATURES.items():
                for sig in signatures:
                    if header.startswith(sig):
                        return file_type, 'EXECUTABLE'
            
            # Check media files
            for file_type, signatures in cls.MEDIA_SIGNATURES.items():
                for sig in signatures:
                    if header.startswith(sig):
                        # Special check for RIFF (could be WAV, AVI, or WEBP)
                        if sig == b'RIFF':
                            if b'WAVE' in header[8:12]:
                                return 'WAV', 'MEDIA'
                            elif b'AVI ' in header[8:12]:
                                return 'AVI', 'MEDIA'
                            elif b'WEBP' in header[8:12]:
                                return 'WEBP', 'MEDIA'
                            continue
                        return file_type, 'MEDIA'
            
            # Check if it's text
            try:
                text = header.decode('utf-8', errors='ignore')
                printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / max(len(text), 1)
                if printable_ratio > 0.9:
                    return 'TEXT', 'TEXT'
            except:
                pass
            
            return 'UNKNOWN', 'UNKNOWN'
            
        except Exception:
            return 'ERROR', 'UNKNOWN'
    
    @classmethod
    def is_media_file(cls, filepath):
        _, category = cls.identify_file_type(filepath)
        return category == 'MEDIA'
    
    @classmethod
    def is_executable(cls, filepath):
        _, category = cls.identify_file_type(filepath)
        return category == 'EXECUTABLE'
    
    @classmethod
    def is_script(cls, filepath):
        file_type, _ = cls.identify_file_type(filepath)
        return file_type in ['SCRIPT_BAT', 'SCRIPT_PS1', 'SCRIPT_VBS', 'SCRIPT_SH']


class ThreatDNAEngine:
    """PERFECTLY ACCURATE Threat DNA Engine"""
    
    def __init__(self):
        self.file_validator = FileTypeValidator()
        
        # Comprehensive malicious pattern database
        self.malware_signatures = {
            # METERPRETER / METASPLOIT - Very specific patterns
            'meterpreter': {
                'binary_patterns': [
                    b'meterpreter', b'reverse_tcp', b'bind_tcp', b'windows/',
                    b'ReflectiveLoader', b'stdapi_', b'core_channel_open',
                    b'core_migrate', b'priv_passwd', b'hashdump',
                    b'msfencode', b'msfvenom', b'payload/windows',
                    b'stage0', b'stage1', b'metsvc', b'ki_trap',
                    b'\xfc\xe8\x82', b'\xfc\xe8\x89', b'\xfc\x48\x83',
                ],
                'api_patterns': [
                    'VirtualAlloc', 'VirtualProtect', 'CreateThread',
                    'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibrary',
                    'GetProcAddress', 'VirtualAllocEx', 'QueueUserAPC',
                    'NtCreateThreadEx', 'RtlCreateUserThread'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (6.5, 8.5),
                'threat_level': 'CRITICAL'
            },
            
            # COBALT STRIKE
            'cobalt_strike': {
                'binary_patterns': [
                    b'beacon', b'ReflectiveLoader', b'CobaltStrike',
                    b'%s as %s\\\\%s', b'Malleable C2', b'postex_',
                    b'execute-assembly', b'beacon>',
                    b'HTTP/1.1 200 OK\r\nContent-Length: ',
                ],
                'api_patterns': [
                    'VirtualAlloc', 'CreateThread', 'InternetConnect',
                    'HttpOpenRequest', 'InternetReadFile', 'WinHttpOpen',
                    'WinHttpConnect', 'WinHttpSendRequest'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (6.0, 8.0),
                'threat_level': 'CRITICAL'
            },
            
            # RANSOMWARE
            'ransomware': {
                'binary_patterns': [
                    b'CryptEncrypt', b'CryptDecrypt', b'CryptGenKey',
                    b'CryptAcquireContext', b'CryptDeriveKey',
                    b'vssadmin delete', b'wbadmin delete',
                    b'YOUR_FILES_ARE_ENCRYPTED', b'README_TO_DECRYPT',
                    b'.encrypted', b'.locked', b'ransom note',
                    b'bitcoin', b'wallet', b'restore_files',
                ],
                'api_patterns': [
                    'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
                    'FindFirstFile', 'FindNextFile', 'DeleteFile',
                    'MoveFile', 'CreateFile', 'WriteFile',
                    'CryptAcquireContext', 'RegSetValue'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (6.5, 8.5),
                'threat_level': 'CRITICAL'
            },
            
            # RAT / TROJAN
            'rat_trojan': {
                'binary_patterns': [
                    b'socket', b'connect', b'recv', b'send',
                    b'cmd.exe', b'powershell.exe',
                    b'reverse_shell', b'bind_shell',
                    b'-WindowStyle Hidden', b'-NoProfile',
                    b'CreateProcess', b'CreatePipe',
                ],
                'api_patterns': [
                    'socket', 'connect', 'recv', 'send', 'WSAStartup',
                    'CreateProcess', 'CreatePipe', 'SetHandleInformation',
                    'ReadFile', 'WriteFile', 'InternetOpen', 'HttpSendRequest'
                ],
                'min_api_matches': 4,
                'min_pattern_matches': 2,
                'entropy_range': (4.5, 7.5),
                'threat_level': 'CRITICAL'
            },
            
            # KEYLOGGER / SPYWARE
            'spyware': {
                'binary_patterns': [
                    b'SetWindowsHookEx', b'GetAsyncKeyState', b'GetKeyState',
                    b'GetClipboardData', b'keylog', b'WH_KEYBOARD_LL',
                    b'GetForegroundWindow', b'GetWindowText',
                ],
                'api_patterns': [
                    'SetWindowsHookEx', 'GetAsyncKeyState', 'GetClipboardData',
                    'GetForegroundWindow', 'GetWindowText', 'WriteFile',
                    'CreateFile', 'InternetConnect', 'HttpSendRequest'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (4.0, 7.0),
                'threat_level': 'HIGH'
            },
            
            # ROOTKIT
            'rootkit': {
                'binary_patterns': [
                    b'\\Device\\', b'\\Driver\\', b'bootkit',
                    b'ZwCreateFile', b'ZwSetInformationFile',
                    b'SSDT', b'hook', b'inline', b'patch_guard',
                    b'ntoskrnl', b'hal.dll',
                ],
                'api_patterns': [
                    'NtCreateFile', 'NtWriteFile', 'NtDeviceIoControlFile',
                    'ZwSystemDebugControl', 'ZwLoadDriver', 'ZwSetSystemInformation',
                    'IoCreateDevice', 'IoCreateSymbolicLink'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (5.0, 7.5),
                'threat_level': 'CRITICAL'
            },
            
            # INFO STEALER
            'infostealer': {
                'binary_patterns': [
                    b'browser', b'password', b'cookie', b'history',
                    b'chrome', b'firefox', b'edge', b'opera',
                    b'login data', b'web data', b'cookies.sqlite',
                    b'AppData\\\\Local\\\\Google', b'Mozilla\\\\Firefox',
                    b'Telegram', b'Discord', b'Steam',
                ],
                'api_patterns': [
                    'FindFirstFile', 'FindNextFile', 'ReadFile', 'CreateFile',
                    'WriteFile', 'InternetConnect', 'HttpSendRequest',
                    'CryptUnprotectData', 'RegQueryValue'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (4.0, 6.5),
                'threat_level': 'HIGH'
            },
            
            # BOTNET / DDoS
            'botnet': {
                'binary_patterns': [
                    b'flood', b'synflood', b'udpflood', b'httpflood',
                    b'CnC', b'command and control', b'botnet',
                    b'attack', b'target=', b'threads=',
                    b'ddos', b'zombie',
                ],
                'api_patterns': [
                    'socket', 'connect', 'send', 'recv', 'WSAStartup',
                    'bind', 'listen', 'accept', 'select', 'ioctlsocket',
                    'CreateThread', 'CreateProcess'
                ],
                'min_api_matches': 3,
                'min_pattern_matches': 2,
                'entropy_range': (4.0, 7.0),
                'threat_level': 'HIGH'
            },
            
            # SHELLCODE / EXPLOIT
            'shellcode': {
                'binary_patterns': [
                    b'\xfc\xe8\x82', b'\xfc\xe8\x89', b'\xfc\x48\x83',
                    b'\x31\xc0\x50\x68', b'\x31\xd2\x52\x68',
                    b'\x8b\xec\x83\xec', b'\x64\xa1\x30\x00',
                    b'\x0f\x31', b'\xcd\x80', b'\x0f\x05',
                ],
                'api_patterns': [
                    'VirtualAlloc', 'VirtualProtect', 'CreateThread',
                    'LoadLibrary', 'GetProcAddress', 'WriteProcessMemory'
                ],
                'min_api_matches': 2,
                'min_pattern_matches': 2,
                'entropy_range': (6.0, 8.5),
                'threat_level': 'CRITICAL'
            }
        }
        
        # Behavioral categories for tracking
        self.behavioral_categories = {
            'crypto_ops': [
                b'CryptEncrypt', b'CryptDecrypt', b'CryptGenKey',
                b'CryptAcquireContext', b'CryptDeriveKey', b'CryptExportKey',
                b'AES', b'RSA', b'RC4', b'encrypt', b'decrypt'
            ],
            'network_ops': [
                b'socket', b'connect', b'WSAStartup', b'gethostbyname',
                b'InternetOpen', b'InternetConnect', b'HttpOpenRequest',
                b'HttpSendRequest', b'URLDownloadToFile', b'WinHttpOpen',
                b'recv', b'send', b'bind', b'listen', b'C2', b'beacon'
            ],
            'persistence': [
                b'Run', b'RunOnce', b'Schedule', b'SchTasks',
                b'CreateService', b'RegSetValue', b'Startup',
                b'Registry', b'HKCU', b'HKLM', b'CurrentVersion\\Run',
                b'boot execute', b'crontab', b'systemd'
            ],
            'injection': [
                b'VirtualAlloc', b'WriteProcessMemory', b'CreateRemoteThread',
                b'ReflectiveLoader', b'QueueUserAPC', b'ProcessInject',
                b'CreateRemoteThread', b'NtCreateThreadEx',
                b'MapViewOfSection', b'process hollow'
            ],
            'evasion': [
                b'IsDebugger', b'AntiVM', b'AntiSandbox',
                b'CheckRemoteDebugger', b'NtQueryInformationProcess',
                b'GetTickCount', b'rdtsc', b'cpuid',
                b'vmware', b'vbox', b'qemu', b'sandboxie',
                b'obfuscate', b'XOR', b'base64'
            ],
            'collection': [
                b'GetClipboardData', b'GetAsyncKeyState', b'GetKeyState',
                b'SetWindowsHookEx', b'GetForegroundWindow',
                b'keylog', b'screenshot', b'clipboard',
                b'credentials', b'password', b'browser'
            ],
            'privilege_escalation': [
                b'SeDebugPrivilege', b'token', b'impersonate',
                b'AdjustTokenPrivileges', b'OpenProcessToken',
                b'DuplicateToken', b'getsystem', b'elevate',
                b'runas', b'sudo', b'suid'
            ],
            'data_exfiltration': [
                b'upload', b'exfiltrate', b'POST', b'FTP',
                b'SMTP', b'send', b'archive', b'compress',
                b'tunnel', b'proxy', b'encrypted channel'
            ]
        }
    
    def extract_dna(self, filepath):
        """PERFECT DNA extraction - accurate for ALL file types"""
        try:
            # STEP 1: Get real file type
            file_type, category = self.file_validator.identify_file_type(filepath)
            
            # Read file content
            with open(filepath, 'rb') as f:
                content = f.read()
            
            file_size = len(content)
            
            # STEP 2: Calculate entropy
            entropy = self._calculate_entropy(content)
            
            # STEP 3: Extract behaviors and API patterns
            behaviors = self._extract_behaviors(content)
            api_patterns = self._extract_api_patterns(content)
            
            # STEP 4: SCAN FOR MALWARE SIGNATURES (works for ALL file types)
            malware_scan = self._scan_malware_signatures(content, api_patterns, entropy, file_type, category)
            
            # STEP 5: Determine if file is actually malicious
            is_malicious = malware_scan['is_malicious']
            
            # STEP 6: Calculate mutation score
            if is_malicious:
                mutation_score = self._calculate_mutation_score(
                    content, entropy, behaviors, api_patterns, malware_scan
                )
            else:
                # Clean files get ZERO or very low mutation score
                mutation_score = self._calculate_clean_file_score(entropy, file_type, category)
            
            # STEP 7: Determine threat family
            if is_malicious:
                threat_family = malware_scan['primary_threat']
            else:
                threat_family = self._determine_clean_label(file_type, category, entropy, behaviors)
            
            dna_hash = hashlib.sha256(content[:20480]).hexdigest()
            
            dna_profile = {
                'file_hash': dna_hash,
                'entropy': entropy,
                'behaviors': behaviors,
                'api_patterns': api_patterns,
                'mutation_score': mutation_score,
                'threat_family': threat_family,
                'file_type': file_type,
                'category': category,
                'is_malicious': is_malicious,
                'malware_scan': {
                    'detected_threats': malware_scan['detected_threats'],
                    'primary_threat': malware_scan['primary_threat'],
                    'confidence': malware_scan['confidence'],
                    'threat_level': malware_scan['threat_level']
                },
                'timestamp': datetime.now().isoformat(),
                'size': file_size,
                'sha256': hashlib.sha256(content).hexdigest(),
                'md5': hashlib.md5(content).hexdigest()
            }
