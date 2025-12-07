#!/usr/bin/python3
from bcc import BPF
import requests
import json
from collections import defaultdict

# --- CONFIGURATION ---
# NOTE FOR GITHUB USERS: Update this IP to your AI Server's IP address.
AI_SERVER_IP = "YOUR_WINDOWS_IP" 
AI_URL = f"http://{AI_SERVER_IP}:11434/api/generate"

# --- KERNEL HOOKS (eBPF) ---
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char argv[256];
    char type[10]; 
};

BPF_PERF_OUTPUT(events);

// Helper: Check if string ends with suffix
static int ends_with(char *str, char *suffix) {
    int str_len = 0;
    int suf_len = 0;
    for (int i=0; i<256; i++) { if (str[i] == 0) break; str_len++; }
    for (int i=0; i<10; i++)  { if (suffix[i] == 0) break; suf_len++; }
    if (suf_len > str_len) return 0;
    for (int i=0; i<suf_len; i++) {
        if (str[str_len - i - 1] != suffix[suf_len - i - 1]) return 0;
    }
    return 1;
}

// Helper: Check if string starts with prefix
static int starts_with(char *str, char *prefix) {
    for (int i=0; i<20; i++) {
        if (prefix[i] == 0) return 1; 
        if (str[i] != prefix[i]) return 0;
    }
    return 1;
}

// Hook 1: Execution (sys_execve)
int syscall__execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *argv)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.type, "EXEC", 5);

    const char *arg0 = NULL;
    bpf_probe_read(&arg0, sizeof(arg0), &argv[0]);
    if (arg0) {
        bpf_probe_read_user_str(&data.argv, sizeof(data.argv), arg0);
    }
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Hook 2: File Open (sys_openat)
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.argv, sizeof(data.argv), filename);
    
    // --- NOISE FILTERING ---
    // 1. Drop System Noise (Libraries, Locales, Configs)
    if (starts_with(data.argv, "/lib") || starts_with(data.argv, "/usr/lib") || 
        starts_with(data.argv, "/usr/share") || starts_with(data.argv, "/etc/ssl") ||
        starts_with(data.argv, "/etc/fonts") || starts_with(data.argv, "/etc/host")) {
        return 0;
    }

    // 2. Drop File Extension Noise
    if (ends_with(data.argv, ".so") || ends_with(data.argv, ".cache") || 
        ends_with(data.argv, ".mo") || ends_with(data.argv, ".conf") ||
        ends_with(data.argv, ".crt") || ends_with(data.argv, ".curlrc")) {
        return 0; 
    }
    
    // 3. Drop standard noisy paths
    if (starts_with(data.argv, "/dev/") || starts_with(data.argv, "/proc/")) {
        return 0;
    }

    __builtin_memcpy(&data.type, "OPEN", 5);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

print(f"[+] CHRONOS: Connecting to Brain at {AI_SERVER_IP}...")
b = BPF(text=bpf_source)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")

process_memory = defaultdict(list)

def analyze_sequence(pid, history):
    print(f"    [?] Analyzing Behavioral Chain for PID {pid} (Waiting for AI)...")
    prompt = f"""
    Analyze this sequence. Return JSON ONLY.
    Sequence: {history}
    Context: 'curl' -> 'chmod' -> 'exec' is a Dropper.
    Format: {{"risk_score": <0-10>, "verdict": "<SAFE/MALICIOUS>", "reason": "<Short Explanation>"}}
    """
    try:
        # Timeout set to 30s to allow for local LLM inference time
        response = requests.post(AI_URL, json={
            "model": "llama3", "prompt": prompt, "stream": False, "format": "json"
        }, timeout=30)
        return json.loads(response.json()['response'])
    except Exception as e:
        return {"risk_score": 0, "verdict": "ERROR", "reason": str(e)}

def print_event(cpu, data, size):
    event = b["events"].event(data)
    pid = event.pid
    try:
        cmd = event.comm.decode('utf-8')
        args = event.argv.decode('utf-8')
        etype = event.type.decode('utf-8')
    except: return

    # User-Space Noise Filter
    ignore = ["node", "code", "ollama", "python", "chrome", "vmtools", "git"]
    if any(x in cmd for x in ignore): return

    event_str = f"[{etype}] {cmd} -> {args}"
    process_memory[pid].append(event_str)
    
    # Trigger Logic: Analyze if we see suspicious tools
    if any(x in event_str for x in ["curl", "chmod", "bash", "nc", "cat"]):
        if len(process_memory[pid]) >= 2:
            print(f"\n[!] CAPTURED KILL CHAIN (PID {pid}):")
            for step in process_memory[pid]:
                print(f"    {step}")
            
            result = analyze_sequence(pid, process_memory[pid])
            
            score = result.get('risk_score', 0)
            if score > 5:
                print(f"\033[91m    ==> ALERT: {result.get('verdict')} (Risk {score})\033[0m")
                print(f"    ==> REASON: {result.get('reason')}")
            else:
                print(f"\033[92m    ==> CLEAN: {result.get('verdict')} (Risk {score})\033[0m")
                print(f"    ==> REASON: {result.get('reason')}")
            
            process_memory[pid] = []

print("[+] CHRONOS: LIVE. Stateful Monitoring Active.")
b["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    try: b.perf_buffer_poll()
    except KeyboardInterrupt: exit()
