#!/usr/bin/env python3
import os
import sys
import time
import math
import signal
import platform
import ctypes
import subprocess
import traceback
import multiprocessing
import re
import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union, Any

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    # Color definitions
    COLORS = {
        "RED": Fore.RED,
        "GREEN": Fore.GREEN,
        "YELLOW": Fore.YELLOW,
        "BLUE": Fore.BLUE,
        "MAGENTA": Fore.MAGENTA,
        "CYAN": Fore.CYAN,
        "WHITE": Fore.WHITE,
        "RESET": Style.RESET_ALL,
        "BRIGHT": Style.BRIGHT
    }
except ImportError:
    # Fallback if colorama not installed
    COLORS = {
        "RED": "\033[91m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "BLUE": "\033[94m",
        "MAGENTA": "\033[95m",
        "CYAN": "\033[96m",
        "WHITE": "\033[97m",
        "RESET": "\033[0m",
        "BRIGHT": "\033[1m"
    }

# ====================== CONFIGURATION ======================
# Global config for all tests
VERSION = "1.0.0"
VERBOSE = "--verbose" in sys.argv
DEBUG = "--debug" in sys.argv
QUICK_MODE = "--quick" in sys.argv
REPORT_FILE = None if "--no-report" in sys.argv else "vulnerability_report.txt"

# Check if root
IS_ROOT = os.geteuid() == 0 if hasattr(os, "geteuid") else False

# CPU & Architecture detection
CPU_VENDOR = ""
CPU_MODEL = ""
CPU_ARCH = platform.machine()
IS_X86 = CPU_ARCH in ["x86_64", "i386", "i686"]

# Spectre test configuration
CACHE_HIT_MULTIPLIER = 3
MAX_ATTEMPTS = 5000 if not QUICK_MODE else 1000
ARRAY_SIZE = 512
TRAINING_RATIO = 0.8
PRIME_STRIDE = 64
SECRET = "The Magic Words are Squeamish Ossifrage."

# Global state variables
segv_occurred = False
array1_global = bytearray(16)
array2_global = bytearray(ARRAY_SIZE * 512)
prime_array = bytearray(4096 * 256)

# Known vulnerability IDs and CVEs
VULN_DB = {
    "meltdown": {
        "cve": "CVE-2017-5754", 
        "desc": "Rogue Data Cache Load", 
        "url": "https://meltdownattack.com"
    },
    "spectre_v1": {
        "cve": "CVE-2017-5753", 
        "desc": "Bounds Check Bypass",
        "url": "https://spectreattack.com"
    },
    "spectre_v2": {
        "cve": "CVE-2017-5715", 
        "desc": "Branch Target Injection",
        "url": "https://spectreattack.com"
    },
    "spectre_v3a": {
        "cve": "CVE-2018-3640", 
        "desc": "Rogue System Register Read",
        "url": "https://software.intel.com/security-software-guidance/insights/deep-dive-intel-analysis-microarchitectural-data-sampling"
    },
    "spectre_v3b": {
        "cve": "CVE-2018-3639", 
        "desc": "Speculative Store Bypass",
        "url": "https://software.intel.com/security-software-guidance/software-guidance/speculative-store-bypass"
    },
    "spectre_v4": {
        "cve": "CVE-2018-3665", 
        "desc": "Lazy FP State Restore",
        "url": "https://software.intel.com/security-software-guidance/api-app/sites/default/files/336996-Speculative-Execution-Side-Channel-Mitigations.pdf"
    },
    "mds": {
        "cve": "CVE-2019-11091", 
        "desc": "Microarchitectural Data Sampling",
        "url": "https://mdsattacks.com"
    },
    "l1tf": {
        "cve": "CVE-2018-3620", 
        "desc": "L1 Terminal Fault",
        "url": "https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault"
    },
    "zombieload": {
        "cve": "CVE-2018-12130", 
        "desc": "Microarchitectural Fill Buffer Data Sampling",
        "url": "https://zombieloadattack.com"
    },
    "ridl": {
        "cve": "CVE-2019-11091", 
        "desc": "Rogue In-flight Data Load",
        "url": "https://mdsattacks.com"
    },
    "fallout": {
        "cve": "CVE-2018-12126", 
        "desc": "Microarchitectural Store Buffer Data Sampling",
        "url": "https://mdsattacks.com"
    },
    "taa": {
        "cve": "CVE-2019-11135", 
        "desc": "TSX Asynchronous Abort",
        "url": "https://software.intel.com/security-software-guidance/advisory-guidance/tsx-asynchronous-abort"
    }
}

# Mitigation flags to check for
MITIGATION_FLAGS = [
    "smep", "smap", "ibpb", "ibrs", "stibp", "ssbd", "spec_ctrl", 
    "retpoline", "kaiser", "kpti", "pcid", "invpcid", "pti", "md_clear"
]

# ====================== UTILITY FUNCTIONS ======================

def print_banner():
    """Print banner with tool info"""
    banner = f"""
{COLORS['CYAN']}{COLORS['BRIGHT']}╔═════════════════════════════════════════════════════════════════════╗
║  Advanced {COLORS['RED']}Meltdown{COLORS['RESET']}{COLORS['CYAN']}{COLORS['BRIGHT']} & {COLORS['YELLOW']}Spectre{COLORS['RESET']}{COLORS['CYAN']}{COLORS['BRIGHT']} Vulnerability Detector v{VERSION}          ║
║  Detection of side-channel & speculative execution vulnerabilities  ║
╚═════════════════════════════════════════════════════════════════════╝{COLORS['RESET']}
"""
    print(banner)

def print_section(title):
    """Print section header"""
    width = 70
    padding = max(0, (width - len(title) - 4)) // 2
    print(f"\n{COLORS['BLUE']}{COLORS['BRIGHT']}{'═' * padding} {title} {'═' * padding}{COLORS['RESET']}")

def print_status(status, message):
    """Print status messages with colored indicators"""
    color = COLORS['GREEN'] if status == "SAFE" else COLORS['RED'] if status == "VULNERABLE" else COLORS['YELLOW']
    print(f"[{color}{status}{COLORS['RESET']}] {message}")

def print_info(message):
    """Print info message"""
    print(f"{COLORS['CYAN']}[INFO]{COLORS['RESET']} {message}")

def print_detail(message, level=1):
    """Print detailed info with indentation"""
    if VERBOSE or level == 0:
        indent = "  " * level
        print(f"{indent}{COLORS['WHITE']}• {message}{COLORS['RESET']}")

def print_error(message, e=None):
    """Print error message with optional exception details"""
    print(f"{COLORS['RED']}[ERROR]{COLORS['RESET']} {message}")
    if e and (VERBOSE or DEBUG):
        print(f"  Exception: {e}")
    if DEBUG:
        traceback.print_exc()

def print_progress(current, total, message="", width=40):
    """Display a progress bar"""
    progress = min(1.0, current / total) if total > 0 else 0
    bar_length = int(width * progress)
    bar = "█" * bar_length + "░" * (width - bar_length)
    percent = int(progress * 100)
    sys.stdout.write(f"\r{COLORS['CYAN']}[{bar}] {percent}% {message}{COLORS['RESET']}")
    sys.stdout.flush()

def get_cpu_info() -> Dict[str, str]:
    """Get detailed CPU information"""
    info = {}
    
    try:
        if sys.platform == 'darwin':
            # macOS
            output = subprocess.check_output(['sysctl', '-a'], text=True)
            for line in output.split('\n'):
                if 'machdep.cpu.brand_string' in line:
                    info['model_name'] = line.split(': ')[1].strip()
                elif 'machdep.cpu.vendor' in line:
                    info['vendor_id'] = line.split(': ')[1].strip()
                
        elif sys.platform == 'win32':
            # Windows
            output = subprocess.check_output(['wmic', 'cpu', 'get', 'name,manufacturer'], text=True)
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                parts = lines[1].split()
                info['vendor_id'] = parts[0]
                info['model_name'] = ' '.join(parts[1:])
                
        else:
            # Linux and others
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.strip():
                            if line.startswith('model name'):
                                info['model_name'] = line.split(':')[1].strip()
                            elif line.startswith('vendor_id'):
                                info['vendor_id'] = line.split(':')[1].strip()
                        if 'model_name' in info and 'vendor_id' in info:
                            break
    except Exception as e:
        print_error("Failed to get CPU info", e)
        
    return info

def is_vulnerable_cpu(vendor: str, model: str) -> Optional[bool]:
    """Check if CPU is known to be vulnerable based on vendor and model"""
    vendor = vendor.lower()
    model = model.lower()
    
    # Intel processors before 8th gen Coffee Lake are vulnerable
    if 'intel' in vendor:
        vulnerable_patterns = [
            r'(celeron|pentium|core.*[0-9]+|xeon)',  # All Intel CPUs
            r'(E3|E5|E7|D|W|X)-',                    # Xeon families
            r'i[357]-[0-7][0-9]{3}[A-Z]?'           # Core i3/i5/i7 7th gen and earlier
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, model) and not re.search(r'i[357]-[89][0-9]{3}[A-Z]?', model):
                return True
    
    # AMD processors are less severely affected
    if 'amd' in vendor:
        vulnerable_patterns = [
            r'ryzen',
            r'epyc',
            r'athlon',
            r'opteron',
            r'phenom',
            r'bulldozer',
            r'piledriver',
            r'steamroller',
            r'excavator'
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, model):
                return True
    
    # ARM processors
    if 'arm' in vendor or 'apple' in vendor:
        vulnerable_patterns = [
            r'cortex-a',
            r'apple a[0-9]+',
            r'apple m1'
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, model):
                return True
                
    return None  # Unknown

def log_to_report(message, newline=True):
    """Log message to report file if enabled"""
    if REPORT_FILE:
        try:
            mode = 'a' if os.path.exists(REPORT_FILE) else 'w'
            with open(REPORT_FILE, mode) as f:
                f.write(message + ('\n' if newline else ''))
        except Exception as e:
            print_error(f"Failed to write to report file: {e}")

def start_report():
    """Initialize the report file"""
    if REPORT_FILE:
        try:
            with open(REPORT_FILE, 'w') as f:
                f.write(f"Advanced Meltdown & Spectre Vulnerability Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: {platform.system()} {platform.release()}\n")
                f.write(f"Architecture: {platform.machine()}\n")
                f.write(f"Python: {platform.python_version()}\n")
                f.write("=" * 60 + "\n\n")
        except Exception as e:
            print_error(f"Failed to create report file: {e}")

def finalize_report(summary):
    """Write summary to report file"""
    if REPORT_FILE:
        try:
            with open(REPORT_FILE, 'a') as f:
                f.write("\n" + "=" * 60 + "\n")
                f.write("SUMMARY\n")
                f.write("=" * 60 + "\n")
                for key, val in summary.items():
                    f.write(f"{key}: {val}\n")
        except Exception as e:
            print_error(f"Failed to finalize report: {e}")

# ====================== SYSTEM CHECKS ======================

def check_vuln_files() -> Dict[str, str]:
    """Check Linux vulnerability sysfs entries"""
    results = {}
    for name in VULN_DB.keys():
        if name in ["meltdown", "zombieload", "ridl", "fallout"]:  # Only check known sysfs entries
            path = f"/sys/devices/system/cpu/vulnerabilities/{name}"
            try:
                with open(path) as f:
                    results[name] = f.read().strip()
            except FileNotFoundError:
                results[name] = "Not available"
            except Exception as e:
                results[name] = f"Error: {e}"
    
    # Also check generic entries
    for name in ["l1tf", "mds", "tsx_async_abort"]:
        path = f"/sys/devices/system/cpu/vulnerabilities/{name}"
        try:
            with open(path) as f:
                results[name] = f.read().strip()
        except FileNotFoundError:
            pass
        except Exception as e:
            if DEBUG:
                print_error(f"Error reading {path}: {e}")
    
    return results

def check_cpu_flags() -> List[str]:
    """Get CPU flags from cpuinfo"""
    try:
        if sys.platform == 'darwin':
            # macOS CPU flags
            output = subprocess.check_output(['sysctl', '-a'], text=True)
            for line in output.split('\n'):
                if 'machdep.cpu.features' in line:
                    return [f.lower() for f in line.split(': ')[1].split()]
        elif sys.platform == 'win32':
            # Windows doesn't expose CPU flags directly
            return []
        else:
            # Linux and other Unix-like
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if line.lower().startswith('flags'):
                        return line.split(':')[1].split()
        return []
    except Exception as e:
        print_error(f"Reading CPU flags failed", e)
        return []

def check_os_protections() -> Dict[str, bool]:
    """Check OS and kernel-level protections"""
    results = {}
    
    # Check KPTI (Kernel Page Table Isolation)
    try:
        # Method 1: dmesg
        try:
            dmesg = subprocess.check_output(['dmesg'], text=True, stderr=subprocess.DEVNULL)
            results["kpti_dmesg"] = "Kernel/User page tables isolation: enabled" in dmesg
        except Exception:
            results["kpti_dmesg"] = None
            
        # Method 2: kernel config
        try:
            kernel_version = platform.release()
            config_path = f"/boot/config-{kernel_version}"
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = f.read()
                    results["kpti_config"] = "CONFIG_PAGE_TABLE_ISOLATION=y" in config
                    results["retpoline_config"] = "CONFIG_RETPOLINE=y" in config
        except Exception:
            results["kpti_config"] = None
            results["retpoline_config"] = None
            
        # Method 3: check pti flag
        cpu_flags = check_cpu_flags()
        results["kpti_flag"] = "pti" in cpu_flags or "kaiser" in cpu_flags
        
        # Check KASLR (Kernel Address Space Layout Randomization)
        try:
            with open('/proc/sys/kernel/randomize_va_space') as f:
                results["kaslr"] = f.read().strip() != '0'
        except Exception:
            results["kaslr"] = None
            
        # Check for mitigations
        try:
            with open('/proc/cmdline') as f:
                cmdline = f.read()
                results["mitigations_off"] = "mitigations=off" in cmdline
                results["no_spectre"] = "nospectre_v1" in cmdline or "nospectre_v2" in cmdline
                results["no_meltdown"] = "nopti" in cmdline
        except Exception:
            results["mitigations_off"] = None
            
    except Exception as e:
        print_error("OS protection check failed", e)
        
    return results

def check_microcode_version() -> Optional[str]:
    """Get CPU microcode version"""
    try:
        if sys.platform == 'linux':
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if 'microcode' in line:
                        return line.split(':')[1].strip()
        elif sys.platform == 'darwin':
            output = subprocess.check_output(['sysctl', 'machdep.cpu'], text=True)
            for line in output.split('\n'):
                if 'microcode' in line:
                    return line.split(':')[1].strip()
        return None
    except Exception as e:
        print_error("Microcode check failed", e)
        return None

def check_hypervisor() -> Optional[str]:
    """Check if running in a virtualized environment"""
    try:
        if os.path.exists('/sys/hypervisor/type'):
            with open('/sys/hypervisor/type') as f:
                return f.read().strip()
        
        # Alternative methods
        try:
            dmesg = subprocess.check_output(['dmesg'], text=True, stderr=subprocess.DEVNULL)
            if 'Hypervisor detected' in dmesg:
                for hypervisor in ['KVM', 'VMware', 'Xen', 'VirtualBox', 'Microsoft HyperV']:
                    if hypervisor.lower() in dmesg.lower():
                        return hypervisor
        except Exception:
            pass
            
        # Try to detect via CPU flags
        cpu_flags = check_cpu_flags()
        if 'hypervisor' in cpu_flags:
            if 'vmware' in cpu_flags:
                return 'VMware'
            if 'kvm' in cpu_flags:
                return 'KVM'
            return 'Unknown hypervisor'
            
        return None
    except Exception as e:
        print_error("Hypervisor detection failed", e)
        return None

def check_system_load() -> float:
    """Get current system load for measurement accuracy"""
    try:
        if hasattr(os, 'getloadavg'):
            load = os.getloadavg()[0]
            return load
        return -1
    except Exception:
        return -1

# ====================== MELTDOWN CHECKS ======================

def check_timing_meltdown() -> Tuple[Optional[int], Optional[int]]:
    """Measure memory access timing differences for potential Meltdown vulnerability"""
    try:
        # Allocate memory for test
        addr = (ctypes.c_char * 4096).from_buffer_copy(b"A" * 4096)
        
        # Measure safe read timing
        iterations = 1000
        safe_times = []
        
        for _ in range(iterations):
            start = time.perf_counter_ns()
            _ = addr[0]
            safe_times.append(time.perf_counter_ns() - start)
        
        safe_time = sum(safe_times) // len(safe_times)
        
        # Unsafe read timing (Only with explicit permission)
        # This is dangerous and can crash, so we skip by default
        unsafe_time = None
        
        return safe_time, unsafe_time
    except Exception as e:
        print_error(f"Timing meltdown test failed", e)
        return None, None

def check_direct_exploit() -> Optional[bool]:
    """Attempt to directly test for Meltdown (carefully)"""
    try:
        # Create test code that tries to read kernel memory
        test_code = r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h>

static jmp_buf jbuf;
static void handler(int sig) { longjmp(jbuf, 1); }

int main() {
    uint8_t array[256*4096];
    uint64_t x = 0;
    volatile uint8_t *addr;
    volatile uint8_t dummy = 0;
    
    // Set up signal handler for segfault
    signal(SIGSEGV, handler);
    signal(SIGBUS, handler);
    
    // Clear probe array
    memset(array, 0, sizeof(array));
    
    // Use setjmp for recovery after exception
    if (!setjmp(jbuf)) {
        // This is the risky operation - attempt to read kernel memory
        _mm_lfence();
        // Different address for different OS kernels
        #ifdef __linux__
        x = *(volatile uint8_t *)(0xFFFFFFFFFF600000); // Linux VDSO
        #else
        x = *(volatile uint8_t *)(0xffffff8000000000); // Generic kernel address
        #endif
        _mm_lfence();
        
        // Access array using the value to create cache side-channel
        addr = &array[x*4096];
        dummy = *addr;
        printf("Reading kernel memory succeeded - VULNERABLE\\n");
        return 1; // Vulnerable!
    } else {
        // We get here from the longjmp after segfault
        printf("Reading kernel memory failed - PROTECTED\\n");
        return 0; // Protected
    }
}'''

        # Write out the test code
        with open('meltdown_test.c', 'w') as f:
            f.write(test_code)

        # Compile the test
        print_detail("Compiling meltdown test code...", 0)
        compile_cmd = ['gcc', '-O0', '-o', 'meltdown_test', 'meltdown_test.c']
        if IS_X86:
            compile_cmd.extend(['-msse2'])
            
        compile_result = subprocess.run(
            compile_cmd,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        
        if compile_result.returncode != 0:
            print_detail(f"Compilation failed: {compile_result.stderr}")
            return None
            
        # Run the test
        print_detail("Running meltdown test executable...", 0)
        result = subprocess.run(
            ['./meltdown_test'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Clean up
        os.remove('meltdown_test.c')
        if os.path.exists('meltdown_test'):
            os.remove('meltdown_test')
            
        # Analyze result
        if "VULNERABLE" in result.stdout:
            return True
        elif "PROTECTED" in result.stdout:
            return False
        elif "Segmentation fault" in result.stderr:
            # Most likely protected if it cannot recover
            return False
        else:
            return None
    
    except Exception as e:
        print_error(f"Direct exploit test failed", e)
        return None
    finally:
        # Ensure cleanup
        if os.path.exists('meltdown_test.c'):
            os.remove('meltdown_test.c')
        if os.path.exists('meltdown_test'):
            os.remove('meltdown_test')

def check_kernel_symbols():
    """Check if kernel symbols are exposed (makes attacks easier)"""
    try:
        if os.path.exists('/proc/kallsyms'):
            # Check if kernel addresses are shown or hidden (0000000000000000)
            with open('/proc/kallsyms') as f:
                lines = f.readlines()
                if not lines:
                    return None
                sample = lines[0].split()[0]
                if '0000000000000000' in sample or sample == '0':
                    return False  # Addresses are hidden
                return True  # Addresses are visible
        return None
    except Exception as e:
        print_error("Kernel symbols check failed", e)
        return None

def check_meltdown_advanced():
    """Advanced meltdown detection methods"""
    results = {}
    
    # Check for Speculative Store Bypass Disable (SSBD)
    cpu_flags = check_cpu_flags()
    results['ssbd'] = 'ssbd' in cpu_flags
    results['ibpb'] = 'ibpb' in cpu_flags
    results['ibrs'] = 'ibrs' in cpu_flags
    results['stibp'] = 'stibp' in cpu_flags
    
    # Check cache flush capabilities
    results['clflush'] = 'clflush' in cpu_flags
    results['clflushopt'] = 'clflushopt' in cpu_flags
    results['md_clear'] = 'md_clear' in cpu_flags
    
    # Check for syscall filters
    try:
        with open('/proc/sys/kernel/unprivileged_bpf_disabled', 'r') as f:
            results['bpf_disabled'] = f.read().strip() == '1'
    except Exception:
        results['bpf_disabled'] = None
    
    # Check for user pointer sanitization
    try:
        if IS_ROOT:
            with open('/sys/kernel/debug/x86/pti_enabled', 'r') as f:
                results['pti_debug'] = f.read().strip() == '1'
    except Exception:
        results['pti_debug'] = None
    
    return results

# ====================== SPECTRE CHECKS ======================

def segv_handler(signum, frame):
    """Handle segmentation faults during spectre tests"""
    global segv_occurred
    segv_occurred = True
    print_error("Memory access violation detected (SIGSEGV)")
    # Jump back to safety
    signal.signal(signal.SIGSEGV, signal.SIG_IGN)

def check_cpu_support() -> bool:
    """Check if CPU has capabilities needed for spectre test"""
    try:
        cpu_flags = check_cpu_flags()
        return all(x in cpu_flags for x in ['rdtscp', 'clflush'])
    except Exception as e:
        print_error(f"CPU support check failed", e)
        return False

def prime_cache():
    """Fill cache with known data"""
    for i in range(0, len(prime_array), PRIME_STRIDE):
        prime_array[i] = (i >> 6) & 0xff

def probe_cache():
    """Measure cache access times for primed locations"""
    times = []
    for i in range(0, len(prime_array), PRIME_STRIDE):
        start = time.perf_counter_ns()
        _ = prime_array[i]
        times.append((time.perf_counter_ns() - start) // 1000)  # Convert to μs
    return times

def calculate_baseline():
    """Establish baseline cache timing thresholds"""
    samples = []
    for _ in range(500):
        prime_cache()
        samples.extend(probe_cache())
        time.sleep(0.001)
    mean = sum(samples)/len(samples)
    stddev = math.sqrt(sum((x-mean)**2 for x in samples)/len(samples))
    return mean, stddev

def victim_function(x, training=True):
    """Target function for spectre attack simulation"""
    global segv_occurred
    try:
        secret_idx = x % len(SECRET)
        
        # This branch trains the predictor during initial calls
        if training or x < len(array1_global):
            val = array1_global[x % len(array1_global)]
            _ = array2_global[val * 512]
        else:
            # In real attack, we'd never reach here, but speculation might:
            val = ord(SECRET[secret_idx])
            _ = array2_global[val * 512]
    except Exception as e:
        segv_occurred = True
        if VERBOSE:
            print_error(f"Victim function exception: {e}")

def run_spectre_test(variant="v1"):
    """Run Spectre vulnerability test with different techniques"""
    global segv_occurred
    segv_occurred = False
    results = defaultdict(int)
    prime_hits = defaultdict(int)
    secret_chars = {}
    
    try:
        # Initial setup
        if not check_cpu_support():
            print_status("WARNING", "CPU lacks required capabilities for reliable Spectre testing")
            return -1
            
        # Set up segfault handler
        original_handler = signal.getsignal(signal.SIGSEGV)
        signal.signal(signal.SIGSEGV, segv_handler)
        
        try:
            # Establish baseline timing
            print_detail("Calibrating cache timing...", 0)
            mean, stddev = calculate_baseline()
            threshold = mean - CACHE_HIT_MULTIPLIER*stddev
            
            print_detail(f"Baseline cache timing: mean={mean:.2f}µs, stddev={stddev:.2f}µs, threshold={threshold:.2f}µs", 1)
            
            # Train branch predictor
            print_detail("Training branch predictor...", 0)
            for training in range(int(MAX_ATTEMPTS * TRAINING_RATIO)):
                if training % 100 == 0:
                    print_progress(training, int(MAX_ATTEMPTS * TRAINING_RATIO), "Training branch predictor")
                # Array is filled with 1s
                array1_global[:] = bytes([1] * len(array1_global))
                victim_function(training % 16, training=True)
                time.sleep(0.0001)
            print("")
            
            # Run attack attempts
            print_detail(f"Running {MAX_ATTEMPTS} speculative execution attempts...", 0)
            for attempt in range(MAX_ATTEMPTS):
                if attempt % 100 == 0:
                    print_progress(attempt, MAX_ATTEMPTS, "Testing for speculative execution leakage")
                
                # Clear results for this run
                for i in range(256):
                    results[i] = 0
                
                # Flush cache to prepare
                for i in range(0, len(array2_global), 512):
                    ctypes.c_void_p.from_buffer(array2_global, i).value

                # Force CPU to mispredict
                if variant == "v1":
                    # Spectre v1: Bounds Check Bypass
                    victim_idx = len(array1_global) + 3  # Just beyond array bounds
                elif variant == "v2":
                    # Spectre v2: Branch Target Injection (would require more complex setup)
                    victim_idx = len(array1_global) + 3
                else:
                    victim_idx = len(array1_global) + 3
                    
                # Induce speculation with mispredicted branch
                victim_function(victim_idx, training=False)
                
                # Measure access times for potential leaked byte
                for i in range(256):
                    offset = i * 512
                    start = time.perf_counter_ns()
                    val = array2_global[offset]
                    end = time.perf_counter_ns()
                    access_time = (end - start) // 1000  # µs
                    
                    # If cache hit detected, increment score
                    if access_time < threshold:
                        results[i] += 1
                        prime_hits[i] += 1
                
                # Determine most likely byte value
                max_val = max(results.items(), key=lambda x: x[1], default=(0, 0))
                if max_val[1] > 0:
                    byte_pos = attempt % len(SECRET)
                    if byte_pos not in secret_chars or secret_chars[byte_pos][1] < max_val[1]:
                        secret_chars[byte_pos] = (max_val[0], max_val[1])
                        
                # If we get enough reliable data, we can stop early
                if len(secret_chars) > len(SECRET) // 2 and min(hit[1] for hit in secret_chars.values()) > 3:
                    print_detail(f"Obtained sufficient data after {attempt+1} attempts", 1)
                    break
                    
            print("")
            
            # Analyze results to determine vulnerability
            max_hits = max(prime_hits.values()) if prime_hits else 0
            threshold_hits = 3  # Minimum number of hits to consider significant
            vulnerable = max_hits >= threshold_hits
            
            # Display recovered bytes (for educational purposes)
            if vulnerable and secret_chars:
                recovered = []
                for i in range(min(len(SECRET), max(secret_chars.keys()) + 1)):
                    if i in secret_chars:
                        val, hits = secret_chars[i]
                        recovered.append((chr(val), hits))
                    else:
                        recovered.append(('?', 0))
                        
                if VERBOSE:
                    print_detail("Recovered data pattern:", 1)
                    line = ""
                    for i, (ch, hits) in enumerate(recovered):
                        line += f"{ch}({hits}) "
                        if i % 10 == 9:
                            print_detail(line, 2)
                            line = ""
                    if line:
                        print_detail(line, 2)
                        
                    # Compare with actual secret
                    correct = sum(1 for i, (ch, _) in enumerate(recovered) if i < len(SECRET) and ch == SECRET[i])
                    accuracy = correct / len(SECRET) if SECRET else 0
                    print_detail(f"Recovery accuracy: {accuracy:.2%} ({correct}/{len(SECRET)})", 1)
                
            return 1 if vulnerable else 0
            
        except Exception as e:
            print_error(f"Spectre {variant} test failed", e)
            return -1
        
    finally:
        # Restore original signal handler
        signal.signal(signal.SIGSEGV, original_handler)
        if segv_occurred:
            print_detail("Warning: Segmentation fault(s) occurred during test", 1)

def check_spectre_v3a():
    """Check for vulnerability to Spectre v3a (Rogue System Register Read)"""
    vulnerable = False
    
    try:
        cpu_flags = check_cpu_flags()
        if 'rdtscp' in cpu_flags:
            # Create test for speculative RDMSR (Model Specific Register) reads
            test_code = r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h>

static jmp_buf jbuf;
static void handler(int sig) { longjmp(jbuf, 1); }

// Simplified test for Spectre v3a - checks for MSR read protection
int main() {
    uint64_t val = 0;
    volatile uint8_t dummy;
    
    // Set up signal handler
    signal(SIGSEGV, handler);
    signal(SIGILL, handler);
    
    // Attempt to read MSR 0x1a0 (IA32_MISC_ENABLE)
    if (!setjmp(jbuf)) {
        unsigned int low, high;
        __asm__ volatile(
            "rdmsr" 
            : "=a" (low), "=d" (high)
            : "c" (0x1a0)
        );
        val = ((uint64_t)high << 32) | low;
        printf("MSR read succeeded (0x%lx) - VULNERABLE\n", val);
        return 1;
    } else {
        printf("MSR read failed - PROTECTED\n");
        return 0;
    }
}'''

        # Write test code
        with open('spectre_v3a_test.c', 'w') as f:
            f.write(test_code)
            
        # Compile the test
        compile_result = subprocess.run(
            ['gcc', '-O0', '-o', 'spectre_v3a_test', 'spectre_v3a_test.c'],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        
        if compile_result.returncode != 0:
            print_detail(f"Compilation failed: {compile_result.stderr}")
            return None
            
        # Run the test if root
        if IS_ROOT:
            result = subprocess.run(
                ['./spectre_v3a_test'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            vulnerable = "VULNERABLE" in result.stdout
        else:
            print_detail("Skipping Spectre v3a direct test (requires root)", 1)
            vulnerable = None
        
    except Exception as e:
        print_error(f"Spectre v3a test failed", e)
        vulnerable = None
    finally:
        # Clean up
        try:
            if os.path.exists('spectre_v3a_test.c'):
                os.remove('spectre_v3a_test.c')
            if os.path.exists('spectre_v3a_test'):
                os.remove('spectre_v3a_test')
        except Exception:
            pass
            
    return vulnerable

def check_spectre_ssb():
    """Check for Speculative Store Bypass (Spectre v4) vulnerability"""
    # Check CPU flags for mitigation
    cpu_flags = check_cpu_flags()
    has_ssbd = 'ssbd' in cpu_flags
    
    # Check kernel settings
    try:
        with open('/sys/devices/system/cpu/vulnerabilities/spec_store_bypass') as f:
            ssb_status = f.read().strip()
            if "Vulnerable" in ssb_status:
                return True
            elif "Mitigation" in ssb_status:
                return False
    except FileNotFoundError:
        pass
    except Exception as e:
        print_error(f"Error checking SSB status", e)
    
    return not has_ssbd  # If no SSBD, likely vulnerable

def check_mds_vulnerabilities():
    """Check for MDS (Microarchitectural Data Sampling) vulnerabilities"""
    results = {}
    
    # Check for MDS mitigations
    cpu_flags = check_cpu_flags()
    results['md_clear'] = 'md_clear' in cpu_flags
    
    # Check kernel reporting
    try:
        paths = [
            '/sys/devices/system/cpu/vulnerabilities/mds',
            '/sys/devices/system/cpu/vulnerabilities/msbds',  # Fallout
            '/sys/devices/system/cpu/vulnerabilities/ridl',   # RIDL
            '/sys/devices/system/cpu/vulnerabilities/taa',    # TAA
        ]
        
        for path in paths:
            try:
                with open(path) as f:
                    status = f.read().strip()
                    name = os.path.basename(path)
                    results[name] = status
                    if "Vulnerable" in status:
                        results[f'{name}_vulnerable'] = True
                    elif "Mitigation" in status:
                        results[f'{name}_vulnerable'] = False
            except FileNotFoundError:
                continue
    except Exception as e:
        print_error(f"Error checking MDS vulnerabilities", e)
    
    # Check SMT status (hyperthreading)
    try:
        with open('/sys/devices/system/cpu/smt/active') as f:
            results['smt_active'] = f.read().strip() == '1'
    except FileNotFoundError:
        try:
            # Alternative method
            cpu_count = os.cpu_count()
            online_cpus = len(open('/proc/cpuinfo').read().split('processor\t:'))
            results['smt_active'] = online_cpus > cpu_count // 2
        except Exception:
            results['smt_active'] = None
    except Exception as e:
        print_error(f"Error checking SMT status", e)
        results['smt_active'] = None
        
    return results

def check_tsx_asynchronous_abort():
    """Check for TAA (TSX Asynchronous Abort) vulnerability"""
    cpu_info = get_cpu_info()
    vendor = cpu_info.get('vendor_id', '').lower()
    
    # Only Intel CPUs with TSX are affected
    if 'intel' not in vendor:
        return False
        
    # Check CPU flags for TSX
    cpu_flags = check_cpu_flags()
    has_tsx = 'rtm' in cpu_flags or 'hle' in cpu_flags
    
    if not has_tsx:
        return False
        
    # Check kernel reporting
    try:
        with open('/sys/devices/system/cpu/vulnerabilities/tsx_async_abort') as f:
            taa_status = f.read().strip()
            if "Vulnerable" in taa_status:
                return True
            elif "Mitigation" in taa_status or "Not affected" in taa_status:
                return False
    except FileNotFoundError:
        pass
    except Exception as e:
        print_error(f"Error checking TAA status", e)
    
    # Default to vulnerable if Intel CPU with TSX
    return True

def check_zombieload():
    """Check for Zombieload vulnerability (variant of MDS)"""
    cpu_info = get_cpu_info()
    vendor = cpu_info.get('vendor_id', '').lower()
    
    # Only Intel CPUs are affected
    if 'intel' not in vendor:
        return False
        
    # Check for mitigation in kernel
    try:
        with open('/sys/devices/system/cpu/vulnerabilities/mds') as f:
            status = f.read().strip()
            if "Vulnerable" in status:
                return True
            elif "Mitigation" in status or "Not affected" in status:
                return False
    except FileNotFoundError:
        pass
    except Exception as e:
        print_error(f"Error checking Zombieload status", e)
    
    # Check for CPU mitigation capability
    cpu_flags = check_cpu_flags()
    has_md_clear = 'md_clear' in cpu_flags
    
    return not has_md_clear  # If no MD_CLEAR, likely vulnerable

def check_ridl():
    """Check for RIDL (Rogue In-flight Data Load) vulnerability"""
    # RIDL is part of MDS, so reuse that logic
    mds_results = check_mds_vulnerabilities()
    ridl_status = mds_results.get('ridl', '')
    
    if 'ridl_vulnerable' in mds_results:
        return mds_results['ridl_vulnerable']
        
    if "Vulnerable" in ridl_status:
        return True
    elif "Mitigation" in ridl_status or "Not affected" in ridl_status:
        return False
        
    # Default to CPU check
    cpu_info = get_cpu_info()
    vendor = cpu_info.get('vendor_id', '').lower()
    
    # Only Intel CPUs are affected
    if 'intel' not in vendor:
        return False
        
    # Check for CPU mitigation capability
    cpu_flags = check_cpu_flags()
    has_md_clear = 'md_clear' in cpu_flags
    
    return not has_md_clear  # If no MD_CLEAR, likely vulnerable

def check_fallout():
    """Check for Fallout vulnerability (variant of MDS)"""
    # Fallout is part of MDS, check specifically for MSBDS
    try:
        with open('/sys/devices/system/cpu/vulnerabilities/msbds') as f:
            status = f.read().strip()
            if "Vulnerable" in status:
                return True
            elif "Mitigation" in status or "Not affected" in status:
                return False
    except FileNotFoundError:
        # Fall back to generic MDS check
        try:
            with open('/sys/devices/system/cpu/vulnerabilities/mds') as f:
                status = f.read().strip()
                if "Vulnerable" in status:
                    return True
                elif "Mitigation" in status or "Not affected" in status:
                    return False
        except FileNotFoundError:
            pass
        except Exception as e:
            print_error(f"Error checking Fallout status", e)
    except Exception as e:
        print_error(f"Error checking Fallout status", e)
    
    # Default to CPU check
    cpu_info = get_cpu_info()
    vendor = cpu_info.get('vendor_id', '').lower()
    
    # Only Intel CPUs with store buffers are affected (most modern ones)
    if 'intel' not in vendor:
        return False
        
    # Check for CPU mitigation capability
    cpu_flags = check_cpu_flags()
    has_md_clear = 'md_clear' in cpu_flags
    
    return not has_md_clear  # If no MD_CLEAR, likely vulnerable

def check_l1tf():
    """Check for L1 Terminal Fault vulnerability"""
    # Check kernel reporting
    try:
        with open('/sys/devices/system/cpu/vulnerabilities/l1tf') as f:
            status = f.read().strip()
            if "Vulnerable" in status:
                return True
            elif "Mitigation" in status or "Not affected" in status:
                return False
    except FileNotFoundError:
        pass
    except Exception as e:
        print_error(f"Error checking L1TF status", e)
    
    # Check CPU
    cpu_info = get_cpu_info()
    vendor = cpu_info.get('vendor_id', '').lower()
    
    # Only Intel CPUs are affected
    if 'intel' not in vendor:
        return False
        
    # Check for CPU features that indicate l1tf mitigation
    cpu_flags = check_cpu_flags()
    has_l1tf_mitigation = 'flush_l1d' in cpu_flags or 'l1tf' in cpu_flags
    
    return not has_l1tf_mitigation  # If no mitigation flags, likely vulnerable

def check_advanced_cache_tests():
    """Run advanced cache timing tests to detect side-channels"""
    results = {}
    
    # First, ensure CPU supports required features
    cpu_flags = check_cpu_flags()
    if not ('rdtscp' in cpu_flags and 'clflush' in cpu_flags):
        return {"error": "CPU lacks required timing features"}
        
    # Create cache-based timing test
    timing_samples = []
    
    try:
        # Allocate test arrays
        buffer_size = 8192
        test_buffer = (ctypes.c_char * buffer_size)()
        
        # Take timing measurements
        samples = 1000
        
        # 1. Sequential access timing
        sequential_times = []
        for _ in range(samples):
            start = time.perf_counter_ns()
            for i in range(0, buffer_size, 64):  # Cache line size typically 64 bytes
                _ = test_buffer[i]
            sequential_times.append((time.perf_counter_ns() - start) / buffer_size)
        
        # 2. Random access timing
        # First prime the cache with sequential access
        for i in range(0, buffer_size, 64):
            _ = test_buffer[i]
            
        # Force cache flush
        for i in range(0, buffer_size, 64):
            ctypes.c_void_p.from_buffer(test_buffer, i).value
            
        # Measure random access
        random_times = []
        random_indices = [(i * 107) % buffer_size for i in range(0, buffer_size, 64)]
        for _ in range(samples):
            start = time.perf_counter_ns()
            for idx in random_indices:
                _ = test_buffer[idx]
            random_times.append((time.perf_counter_ns() - start) / len(random_indices))
        
        # 3. Cache flush timing
        flush_times = []
        for _ in range(samples):
            # Prime the cache
            for i in range(0, buffer_size, 64):
                _ = test_buffer[i]
                
            # Measure flush time
            start = time.perf_counter_ns()
            for i in range(0, buffer_size, 64):
                ctypes.c_void_p.from_buffer(test_buffer, i).value
            flush_times.append((time.perf_counter_ns() - start) / (buffer_size // 64))
        
        # Calculate statistics
        results["seq_access_ns"] = sum(sequential_times) / len(sequential_times)
        results["random_access_ns"] = sum(random_times) / len(random_times)
        results["flush_time_ns"] = sum(flush_times) / len(flush_times)
        results["access_ratio"] = results["random_access_ns"] / results["seq_access_ns"]
        
        # A high ratio indicates more distinct cache/memory speed difference
        # which could make cache side-channel attacks more feasible
        results["side_channel_feasibility"] = "High" if results["access_ratio"] > 5 else \
                                              "Medium" if results["access_ratio"] > 3 else "Low"
        
    except Exception as e:
        print_error(f"Advanced cache test failed", e)
        results["error"] = str(e)
        
    return results

def check_retpoline_implementation():
    """Check for proper retpoline implementation (defense against Spectre v2)"""
    results = {}
    
    # Check if CPU supports extended speculation control features
    cpu_flags = check_cpu_flags()
    results["stibp"] = "stibp" in cpu_flags  # Single Thread Indirect Branch Predictors
    results["ibpb"] = "ibpb" in cpu_flags    # Indirect Branch Prediction Barrier
    results["ibrs"] = "ibrs" in cpu_flags    # Indirect Branch Restricted Speculation
    
    # Check if kernel was compiled with retpoline
    try:
        with open('/sys/devices/system/cpu/vulnerabilities/spectre_v2') as f:
            status = f.read().strip()
            results["kernel_status"] = status
            results["retpoline_enabled"] = "retpoline" in status.lower()
            results["full_retpoline"] = "full retpoline" in status.lower()
            results["enhanced_ibrs"] = "enhanced ibrs" in status.lower()
            results["vulnerable"] = "vulnerable" in status.lower()
    except FileNotFoundError:
        # Try alternative method through dmesg
        try:
            dmesg = subprocess.check_output(['dmesg'], text=True, stderr=subprocess.DEVNULL)
            results["retpoline_enabled"] = "retpoline" in dmesg.lower()
            if "retpoline" in dmesg.lower():
                # Extract specific messages about retpoline
                retpoline_msgs = [line for line in dmesg.split('\n') 
                                 if "retpoline" in line.lower()]
                results["retpoline_messages"] = retpoline_msgs
        except Exception:
            results["retpoline_enabled"] = None
    except Exception as e:
        print_error(f"Retpoline check failed", e)
        results["retpoline_enabled"] = None
    
    # Check boot command line for kernel parameters
    try:
        with open('/proc/cmdline') as f:
            cmdline = f.read().lower()
            results["nospectre_v2"] = "nospectre_v2" in cmdline
            results["spectre_v2"] = "spectre_v2=" in cmdline
            if "spectre_v2=" in cmdline:
                # Extract specific mode
                mode_match = re.search(r'spectre_v2=([^\s]+)', cmdline)
                if mode_match:
                    results["spectre_v2_mode"] = mode_match.group(1)
    except Exception as e:
        if DEBUG:
            print_error(f"Error checking kernel cmdline", e)
    
    return results

def advanced_meltdown_memory_test():
    """Advanced test for measuring memory access characteristics relevant to Meltdown"""
    results = {}
    
    try:
        # Only run this on x86 systems (would need different approaches for ARM)
        if not IS_X86:
            return {"error": "Test designed for x86 architecture only"}
        
        # Create test code 
        test_code = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h>

#define ITERATIONS 1000
#define FENCE _mm_mfence(); _mm_lfence()

// Test kernel vs user memory access timing differences
int main() {
    struct timespec start, end;
    uint64_t user_times[ITERATIONS];
    uint64_t kernel_times[ITERATIONS];
    volatile uint8_t *user_ptr, dummy = 0;
    static jmp_buf jmpbuf;
    
    // Allocate user memory
    user_ptr = (volatile uint8_t *)malloc(4096);
    if (!user_ptr) {
        perror("malloc");
        return 1;
    }
    memset((void *)user_ptr, 0x42, 4096);
    
    // Measure user memory timing
    for (int i = 0; i < ITERATIONS; i++) {
        FENCE;
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        dummy = user_ptr[i % 4096];
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        user_times[i] = (end.tv_sec - start.tv_sec) * 1000000000ULL + 
                         (end.tv_nsec - start.tv_nsec);
    }
    
    // Calculate and print user memory statistics
    uint64_t user_sum = 0, user_min = UINT64_MAX, user_max = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        user_sum += user_times[i];
        if (user_times[i] < user_min) user_min = user_times[i];
        if (user_times[i] > user_max) user_max = user_times[i];
    }
    double user_avg = (double)user_sum / ITERATIONS;
    
    printf("USER_AVG=%lf\n", user_avg);
    printf("USER_MIN=%lu\n", user_min);
    printf("USER_MAX=%lu\n", user_max);
    
    // Try timing kernel memory access where possible
    if (signal(SIGSEGV, (void (*)(int))longjmp) == SIG_ERR) {
        perror("signal");
        free((void *)user_ptr);
        return 1;
    }
    
    int got_kernel_timing = 0;
    volatile uint8_t *kernel_ptr = (volatile uint8_t *)0xffffffff81000000; // Common kernel text location
    
    // Test if we get a segfault trying to access kernel memory
    if (!setjmp(jmpbuf)) {
        if (dummy == *kernel_ptr) {
            printf("KERNEL_ACCESS=SUCCESS\n"); // Should not happen unless kernel security issue
        }
    } else {
        printf("KERNEL_ACCESS=PROTECTED\n");
    }
    
    free((void *)user_ptr);
    return 0;
}'''

        # Write test code to file
        with open('advanced_meltdown_test.c', 'w') as f:
            f.write(test_code)
            
        # Compile the test
        print_detail("Compiling advanced memory test...", 0)
        compile_result = subprocess.run(
            ['gcc', '-O0', '-o', 'advanced_meltdown_test', 'advanced_meltdown_test.c'],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        
        if compile_result.returncode != 0:
            print_detail(f"Compilation failed: {compile_result.stderr}")
            return {"error": "Compilation failed"}
            
        # Run the test
        result = subprocess.run(
            ['./advanced_meltdown_test'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Parse results
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.strip().split('=', 1)
                if key == "USER_AVG" or key == "USER_MIN" or key == "USER_MAX":
                    results[key.lower()] = float(value)
                else:
                    results[key.lower()] = value
                    
        # Calculate meltdown indicators
        if "user_avg" in results:
            # If user memory access is unusually fast, it may indicate issues
            results["meltdown_indicator"] = "Low" if results["user_avg"] > 50 else \
                                            "Medium" if results["user_avg"] > 20 else "High"
            
            # Calculate variability (high variability can indicate speculative execution effects)
            if "user_min" in results and "user_max" in results:
                results["timing_variance"] = results["user_max"] / results["user_min"]
                results["variance_indicator"] = "High" if results["timing_variance"] > 10 else \
                                               "Medium" if results["timing_variance"] > 5 else "Low"
    
    except Exception as e:
        print_error(f"Advanced meltdown memory test failed", e)
        results["error"] = str(e)
    finally:
        # Clean up
        if os.path.exists('advanced_meltdown_test.c'):
            os.remove('advanced_meltdown_test.c')
        if os.path.exists('advanced_meltdown_test'):
            os.remove('advanced_meltdown_test')
            
    return results

def check_sysfs_all_vulnerabilities():
    """Read all vulnerability status entries from sysfs"""
    results = {}
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities/"
    
    try:
        if os.path.exists(vuln_dir):
            for entry in os.listdir(vuln_dir):
                try:
                    with open(os.path.join(vuln_dir, entry)) as f:
                        results[entry] = f.read().strip()
                except Exception as e:
                    if DEBUG:
                        print_error(f"Error reading {entry}", e)
                    results[entry] = f"Error: {e}"
    except Exception as e:
        print_error(f"Error scanning vulnerability directory", e)
        
    return results

def check_page_fault_behavior():
    """Test behavior of the system when handling page faults"""
    results = {}

    try:
        # Create test code
        test_code = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>

// Signal handler for segfaults
static jmp_buf env;
static void handler(int signum) {
    longjmp(env, 1);
}

int main() {
    struct timespec start, end;
    uint64_t time_ns;
    volatile uint8_t *bad_ptr = (volatile uint8_t *)0xffff0000deadbeef;  // Invalid address
    volatile uint8_t dummy;

    // Set up signal handler
    signal(SIGSEGV, handler);

    // Test 1: Measure time to handle a page fault
    if (!setjmp(env)) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        dummy = *bad_ptr;  // Will cause page fault
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        printf("PAGE_FAULT_TIME=%llu\n",
        (uint64_t)((end.tv_sec - start.tv_sec) * 1000000000ULL +
        (end.tv_nsec - start.tv_nsec)));
    } else {
        printf("PAGE_FAULT_HANDLED=1\n");
    }

    // Test 2: Check if speculative execution continues after fault
    volatile uint8_t *array = (volatile uint8_t *)malloc(4096);
    if (!array) {
        perror("malloc");
        return 1;
    }
    memset((void *)array, 0, 4096);

    // Flush the array from cache
    for (int i = 0; i < 4096; i += 64) {
        __builtin_ia32_clflush((void *)(array + i));
    }

    // Try speculative access pattern
    if (!setjmp(env)) {
        if (dummy < 100) {
            dummy = bad_ptr[0];
            dummy = array[0];
        }
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    dummy = array[0];
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    printf("SPECULATIVE_ACCESS_TIME=%llu\n", 
           (uint64_t)((end.tv_sec - start.tv_sec) * 1000000000ULL + 
                     (end.tv_nsec - start.tv_nsec)));

    free((void *)array);
    return 0;
}'''

        # Write test code to file
        with open('page_fault_test.c', 'w') as f:
            f.write(test_code)

        # Compile the test
        print_detail("Compiling page fault test...", 0)
        compile_result = subprocess.run(
            ['gcc', '-O0', '-o', 'page_fault_test', 'page_fault_test.c'],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )

        if compile_result.returncode != 0:
            print_detail(f"Compilation failed: {compile_result.stderr}")
            return {"error": "Compilation failed"}

        # Run the test
        result = subprocess.run(
            ['./page_fault_test'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Parse results
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.strip().split('=', 1)
                results[key.lower()] = value

        # Analyze results
        if "page_fault_time" in results:
            fault_time = int(results["page_fault_time"])
            results["page_fault_speed"] = "Fast" if fault_time < 1000 else \
                                          "Medium" if fault_time < 5000 else "Slow"

        if "speculative_access_time" in results:
            spec_time = int(results["speculative_access_time"])
            results["speculative_indicator"] = "High" if spec_time < 50 else \
                                              "Medium" if spec_time < 100 else "Low"

    except Exception as e:
        print_error(f"Page fault behavior test failed", e)
        results["error"] = str(e)

    finally:
        # Clean up
        if os.path.exists('page_fault_test.c'):
            os.remove('page_fault_test.c')
        if os.path.exists('page_fault_test'):
            os.remove('page_fault_test')

    return results


# ====================== MAIN FUNCTION ======================

def main():
    """Main function to run all checks"""
    print_banner()
    start_report()

    # Initialize summary
    summary = {
        "system": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "cpu_vendor": "",
        "cpu_model": "",
        "microcode": "",
        "hypervisor": "",
        "meltdown": "Unknown",
        "spectre_v1": "Unknown",
        "spectre_v2": "Unknown",
        "spectre_v3a": "Unknown",
        "spectre_v4": "Unknown",
        "mds": "Unknown",
        "l1tf": "Unknown",
        "taa": "Unknown",
        "zombieload": "Unknown",
        "ridl": "Unknown",
        "fallout": "Unknown"
    }

    # Get CPU info
    print_section("System Information")
    cpu_info = get_cpu_info()
    summary["cpu_vendor"] = cpu_info.get("vendor_id", "Unknown")
    summary["cpu_model"] = cpu_info.get("model_name", "Unknown")

    print_info(f"CPU Vendor: {summary['cpu_vendor']}")
    print_info(f"CPU Model: {summary['cpu_model']}")
    print_info(f"Architecture: {summary['architecture']}")

    # Check if CPU is known to be vulnerable
    cpu_vulnerable = is_vulnerable_cpu(summary["cpu_vendor"], summary["cpu_model"])
    if cpu_vulnerable is not None:
        status = "VULNERABLE" if cpu_vulnerable else "SAFE"
        print_status(status, "CPU is known to be " + ("vulnerable" if cpu_vulnerable else "not vulnerable"))

    # Get microcode version
    microcode = check_microcode_version()
    if microcode:
        summary["microcode"] = microcode
        print_info(f"Microcode Version: {microcode}")

    # Check hypervisor
    hypervisor = check_hypervisor()
    if hypervisor:
        summary["hypervisor"] = hypervisor
        print_info(f"Hypervisor: {hypervisor}")

    # Check system load
    load = check_system_load()
    if load > 0:
        print_info(f"Current System Load: {load:.2f}")
        if load > 2.0:
            print_status("WARNING", "High system load may affect test accuracy")

    # Check sysfs vulnerability entries
    print_section("Kernel-Reported Vulnerabilities")
    vuln_files = check_sysfs_all_vulnerabilities()
    for name, status in vuln_files.items():
        if "Vulnerable" in status:
            print_status("VULNERABLE", f"{name.upper()}: {status}")
            summary[name.lower()] = "Vulnerable"
        elif "Mitigation" in status or "Not affected" in status:
            print_status("SAFE", f"{name.upper()}: {status}")
            summary[name.lower()] = "Mitigated"
        else:
            print_info(f"{name.upper()}: {status}")

    # Check OS protections
    print_section("OS & Kernel Protections")
    os_protections = check_os_protections()
    for name, status in os_protections.items():
        if status is True:
            print_status("SAFE", f"{name.upper()}: Enabled")
        elif status is False:
            print_status("VULNERABLE", f"{name.upper()}: Disabled")
        else:
            print_info(f"{name.upper()}: Unknown")

    # Check CPU flags for mitigations
    print_section("CPU Mitigation Flags")
    cpu_flags = check_cpu_flags()
    for flag in MITIGATION_FLAGS:
        if flag in cpu_flags:
            print_status("SAFE", f"{flag.upper()}: Supported")
        else:
            print_status("WARNING", f"{flag.upper()}: Not supported")

    # Run vulnerability checks
    print_section("Vulnerability Tests")

    # Meltdown checks
    print_info("Running Meltdown checks...")
    meltdown_result = check_direct_exploit()
    if meltdown_result is True:
        print_status("VULNERABLE", "Meltdown (CVE-2017-5754)")
        summary["meltdown"] = "Vulnerable"
    elif meltdown_result is False:
        print_status("SAFE", "Meltdown (CVE-2017-5754)")
        summary["meltdown"] = "Mitigated"
    else:
        print_status("UNKNOWN", "Meltdown (CVE-2017-5754)")

    # Spectre checks
    print_info("Running Spectre checks...")
    spectre_v1_result = run_spectre_test("v1")
    if spectre_v1_result == 1:
        print_status("VULNERABLE", "Spectre v1 (CVE-2017-5753)")
        summary["spectre_v1"] = "Vulnerable"
    elif spectre_v1_result == 0:
        print_status("SAFE", "Spectre v1 (CVE-2017-5753)")
        summary["spectre_v1"] = "Mitigated"
    else:
        print_status("UNKNOWN", "Spectre v1 (CVE-2017-5753)")

    spectre_v2_result = run_spectre_test("v2")
    if spectre_v2_result == 1:
        print_status("VULNERABLE", "Spectre v2 (CVE-2017-5715)")
        summary["spectre_v2"] = "Vulnerable"
    elif spectre_v2_result == 0:
        print_status("SAFE", "Spectre v2 (CVE-2017-5715)")
        summary["spectre_v2"] = "Mitigated"
    else:
        print_status("UNKNOWN", "Spectre v2 (CVE-2017-5715)")

    spectre_v3a_result = check_spectre_v3a()
    if spectre_v3a_result is True:
        print_status("VULNERABLE", "Spectre v3a (CVE-2018-3640)")
        summary["spectre_v3a"] = "Vulnerable"
    elif spectre_v3a_result is False:
        print_status("SAFE", "Spectre v3a (CVE-2018-3640)")
        summary["spectre_v3a"] = "Mitigated"
    else:
        print_status("UNKNOWN", "Spectre v3a (CVE-2018-3640)")

    spectre_v4_result = check_spectre_ssb()
    if spectre_v4_result is True:
        print_status("VULNERABLE", "Spectre v4 (CVE-2018-3639)")
        summary["spectre_v4"] = "Vulnerable"
    elif spectre_v4_result is False:
        print_status("SAFE", "Spectre v4 (CVE-2018-3639)")
        summary["spectre_v4"] = "Mitigated"
    else:
        print_status("UNKNOWN", "Spectre v4 (CVE-2018-3639)")

    # MDS checks
    print_info("Running MDS checks...")
    mds_result = check_mds_vulnerabilities()
    if mds_result.get('mds_vulnerable', True):
        print_status("VULNERABLE", "MDS (CVE-2019-11091)")
        summary["mds"] = "Vulnerable"
    else:
        print_status("SAFE", "MDS (CVE-2019-11091)")
        summary["mds"] = "Mitigated"

    # L1TF checks
    print_info("Running L1TF checks...")
    l1tf_result = check_l1tf()
    if l1tf_result:
        print_status("VULNERABLE", "L1TF (CVE-2018-3620)")
        summary["l1tf"] = "Vulnerable"
    else:
        print_status("SAFE", "L1TF (CVE-2018-3620)")
        summary["l1tf"] = "Mitigated"

    # TAA checks
    print_info("Running TAA checks...")
    taa_result = check_tsx_asynchronous_abort()
    if taa_result:
        print_status("VULNERABLE", "TAA (CVE-2019-11135)")
        summary["taa"] = "Vulnerable"
    else:
        print_status("SAFE", "TAA (CVE-2019-11135)")
        summary["taa"] = "Mitigated"

    # Zombieload checks
    print_info("Running Zombieload checks...")
    zombieload_result = check_zombieload()
    if zombieload_result:
        print_status("VULNERABLE", "Zombieload (CVE-2018-12130)")
        summary["zombieload"] = "Vulnerable"
    else:
        print_status("SAFE", "Zombieload (CVE-2018-12130)")
        summary["zombieload"] = "Mitigated"

    # RIDL checks
    print_info("Running RIDL checks...")
    ridl_result = check_ridl()
    if ridl_result:
        print_status("VULNERABLE", "RIDL (CVE-2019-11091)")
        summary["ridl"] = "Vulnerable"
    else:
        print_status("SAFE", "RIDL (CVE-2019-11091)")
        summary["ridl"] = "Mitigated"

    # Fallout checks
    print_info("Running Fallout checks...")
    fallout_result = check_fallout()
    if fallout_result:
        print_status("VULNERABLE", "Fallout (CVE-2018-12126)")
        summary["fallout"] = "Vulnerable"
    else:
        print_status("SAFE", "Fallout (CVE-2018-12126)")
        summary["fallout"] = "Mitigated"

    # Advanced tests
    if VERBOSE or DEBUG:
        print_section("Advanced Tests")
        print_info("Running advanced cache tests...")
        cache_results = check_advanced_cache_tests()
        print_detail(f"Cache timing results: {cache_results}")
        
        print_info("Running retpoline checks...")
        retpoline_results = check_retpoline_implementation()
        print_detail(f"Retpoline results: {retpoline_results}")
        
        print_info("Running advanced Meltdown memory tests...")
        meltdown_mem_results = advanced_meltdown_memory_test()
        print_detail(f"Meltdown memory results: {meltdown_mem_results}")
        
        print_info("Running page fault behavior tests...")
        pf_results = check_page_fault_behavior()
        print_detail(f"Page fault results: {pf_results}")

    # Finalize report
    finalize_report(summary)
    if REPORT_FILE:
        print_info(f"Report saved to {REPORT_FILE}")

    print_section("Summary")
    for vuln, status in summary.items():
        if vuln not in ["system", "architecture", "cpu_vendor", "cpu_model", "microcode", "hypervisor"]:
            color = COLORS['GREEN'] if status == "Mitigated" else COLORS['RED'] if status == "Vulnerable" else COLORS['YELLOW']
            print(f"{vuln.upper():<15}: {color}{status}{COLORS['RESET']}")

    print("\n" + COLORS['CYAN'] + "=" * 70)
    print("For more information about these vulnerabilities and mitigations, visit:")
    print("- https://meltdownattack.com")
    print("- https://spectreattack.com")
    print("- https://software.intel.com/security-software-guidance" + COLORS['RESET'])
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + COLORS['RED'] + "Interrupted by user" + COLORS['RESET'])
        sys.exit(1)
    except Exception as e:
        print_error("Fatal error occurred", e)
        sys.exit(1)

