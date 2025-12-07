# 🛡️ Project CHRONOS: Distributed Behavioral EDR (eBPF + LLM)

![Status](https://img.shields.io/badge/Status-Operational-brightgreen) ![Tech](https://img.shields.io/badge/Tech-eBPF_%7C_Python_%7C_Llama3-blue) ![Focus](https://img.shields.io/badge/Focus-Kernel_Security_%7C_GenAI-red)

### **Executive Summary**
**CHRONOS** is a custom Endpoint Detection & Response (EDR) agent that bypasses traditional user-space logging by hooking directly into the Linux Kernel using **eBPF (Extended Berkeley Packet Filter)**.

Unlike standard tools that flag individual commands, CHRONOS uses a stateful "Short-Term Memory" to track execution chains (Kill Chains) and offloads analysis to a centralized **Generative AI node (Llama 3)**. This project demonstrates a **Hybrid-Cloud Architecture**, where a lightweight Linux sensor transmits telemetry to a GPU-accelerated Windows AI server for real-time behavioral analysis.

---

### 🏗️ Architecture: Hybrid-Cloud Simulation

The system is designed to simulate an Enterprise EDR environment:

* **The Sensor (Kali Linux):**
    * Utilizes `BCC` (BPF Compiler Collection) to attach kprobes to `sys_execve` and `sys_openat`.
    * **Custom Kernel Filtering:** Implemented C-based logic inside the kernel to drop system noise (`/lib`, `/usr/share`, config files) *before* it reaches user space, reducing CPU overhead by ~90%.
    * **Stateful Buffer:** Tracks Process IDs (PIDs) to build a "context window" of recent actions.
* **The Brain (Windows GPU Node):**
    * A centralized API running **Llama 3 (8B)** via Ollama.
    * Receives structured JSON telemetry.
    * Evaluates the *sequence* of events against known threat patterns (MITRE ATT&CK).
* **Networking:** Asynchronous HTTP/REST transmission over a Bridged Network adapter.

---

### 🧠 The "Kill Chain" Detection Logic

Most simple EDRs alert on keywords (e.g., "Alert on `curl`"). CHRONOS alerts on **Intent**.

The system buffers events to recognize the **Dropper Pattern (MITRE T1105)**:
1.  **Network Event:** `curl` downloads a payload.
2.  **File Event:** `chmod +x` modifies permissions.
3.  **Execution Event:** The file is executed immediately after.

*The AI engine recognizes that while `curl` is safe, the **sequence** `curl -> chmod -> exec` is malicious.*

---

### 📸 Proof of Concept

**Scenario:** A simulated "Low-and-Slow" fileless dropper attack (`attack_chain.sh`).

**Detection Output:**
![CHRONOS Detection Proof](Screenshot%202025-12-07%20172116.png)
*(Above: The sensor captures the full attack chain. The initial timeout represents the AI model loading into VRAM, followed by a high-fidelity **Risk 8 Alert** identifying the Dropper behavior.)*

---

### 💻 Installation & Usage

#### Prerequisites
* **Sensor Node:** Linux (Kali/Ubuntu) with `bpfcc-tools` and Python 3.
* **AI Node:** Any machine running Ollama with the `llama3` model pulled.

#### 1. Start the AI Node (Windows/Cloud)
```powershell
# Allow external connections
setx OLLAMA_HOST "0.0.0.0"
ollama serve
```

#### 2. Start the Kernel Sensor (Linux)
**Update the AI_SERVER_IP variable in chronos_sensor.py to match your AI Node's IP.**
```bash
# Must run as root to access Kernel Hooks
sudo python3 chronos_sensor.py
```

#### 3. Run the Simulation
```bash
./attack_chain.sh
```

### 🔍 Code Highlight: Kernel Noise Filtering

To ensure high performance, I wrote custom C functions to filter noise directly in the kernel:
```C
// C-Code running inside Linux Kernel (eBPF)
static int starts_with(char *str, char *prefix) {
    // Custom string comparison to drop /lib and /usr/share events
    // ...
}

int syscall__openat(...) {
    // Drop standard system library loads to prevent buffer overflow
    if (starts_with(data.argv, "/lib") || starts_with(data.argv, "/usr/lib")) {
        return 0;
    }
    // ...
}
```
