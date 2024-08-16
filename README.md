<div align="center">
<img src="https://raw.githubusercontent.com/Chainski/PandaLoader/main/assets/PandaLoader.png", width="400", height="400">
</div>
<div align="center">
  <a href="https://github.com/Chainski/PandaLoader">
    <img src="https://img.shields.io/github/languages/top/Chainski/PandaLoader?color=246AE6" alt="Top Language"></a>
  <a href="https://github.com/Chainski/PandaLoader/stargazers">
    <img src="https://img.shields.io/github/stars/Chainski/PandaLoader?style=flat&color=246AE6" alt="Stars"></a>
  <a href="https://github.com/Chainski/PandaLoader/forks">
    <img src="https://img.shields.io/github/forks/Chainski/PandaLoader?style=flat&color=246AE6" alt="Forks"></a>
  <a href="https://github.com/Chainski/PandaLoader/issues">
    <img src="https://img.shields.io/github/issues/Chainski/PandaLoader?style=flat&color=246AE6" alt="Issues"></a>
  <a href="https://github.com/Chainski/PandaLoader/commits">
    <img src="https://img.shields.io/github/commit-activity/m/Chainski/PandaLoader?color=246AE6" alt="Commit Activity"></a>
  <br>
  <a href="https://github.com/Chainski/PandaLoader?tab=MIT-1-ov-file">
    <img src="https://img.shields.io/github/license/Chainski/PandaLoader?color=246AE6" alt="License"></a>
  <a href="https://github.com/Chainski/PandaLoader/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/Chainski/PandaLoader?color=246AE6" alt="Contributors"></a>
  <a href="https://github.com/Chainski/PandaLoader">
  <img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FChainski%2FPandaLoader&count_bg=%23246AE6&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=views&edge_flat=false" alt="Views"></a>
  <a href="https://github.com/Chainski/PandaLoader">
    <img src="https://img.shields.io/github/repo-size/Chainski/PandaLoader?color=246AE6" alt="Repo Size"></a>
</div>

<h1 align="center">PandaLoader</h1>



PandaLoader is a WIP shellcode loader designed to evade detection by using various anti-analysis techniques and features such as anti-virtual machine (VM) detection, process injection, and payload decryption.


# Features
```
[~] Add Windows Defender Exclusions [admin required]
[~] Persistence [optional] 
[~] Mutex : Only a single instance of PandaLoader will be running at any given time
[~] Anti-VM Techniques: Ensures that the loader doesn't execute in a virtualized environment, which is commonly used for malware analysis.
[~] Obfuscation: Uses compile-time string obfuscation to hinder static analysis.
[~] XOR Encryption with Dynamic Key Generation: Protects the shellcode from being easily detected by antivirus tools.
[~] APC Injection: A stealthy method to execute code in the context of another process.
[~] ETW Patching: Prevents certain Windows logging mechanisms from being used to detect the malware's activities.
[~] Self-Dectruct [optional]
```

# How It Works 

#### Anti-VM Checks (IF ENABLED IN BUILDER)
Before loading the shellcode, PandaLoader performs extensive anti-VM checks to determine if it's running in a virtualized environment. This includes:
- Process Scanning: It checks for the presence of specific processes associated with VM environments (e.g., `vboxmouse.sys`, `vmwareuser.exe`).
File and Directory Scanning: It searches for files and directories related to `VM tools`, such as `VirtualBox` or `VMware`.
Machine Process Count: It checks if the number of running processes is below 100, which could indicate a `VM` or sandbox environment.
ETW (Event Tracing for Windows) Patch: It patches functions related to `ETW` to prevent the logging of events, which could be used for analysis.
If any `VM` indicators are detected, the loader will terminate.
- Payload Retrieval :
The shellcode is downloaded from a remote URL specified in the `SHELLCODE_URL` when using the builder.
It uses the WinINet API to download the payload into a `std::vector<BYTE>` buffer.
- Payload Decryption :
The decryption key is specified by the `XOR_DECRYPTION_KEY` which is the one generated using the builder.
The decryption is performed by the `XORDecrypt()` function, which iterates through the payload and `XORs` each byte with the corresponding byte in the key.
- Process Injection :
PandaLoader creates a suspended process, defaults to (`wmiprvse.exe` in this case) using `CreateProcessA`.
It then allocates memory in the target process using `VirtualAllocEx`, with `MEM_COMMIT` and `MEM_RESERVE` flags, making the allocated memory readable, writable, and executable (`PAGE_EXECUTE_READWRITE`).
The decrypted shellcode is written into the allocated memory using `WriteProcessMemory`.
After writing the shellcode, the memory permissions are adjusted to `PAGE_EXECUTE_READ` using `VirtualProtect` to reduce the chances of detection by security software.
- Shellcode Execution :
The shellcode is executed by queuing it as an APC (Asynchronous Procedure Call) to the suspended process thread using `QueueUserAPC`.
The thread is then resumed using `ResumeThread`, which causes the shellcode to be executed in the context of the target process.
- Persistence and Cleanup :
If persistence is enabled (ENABLE_STARTUP), the loader copies itself to a specific directory and creates a scheduled task to run on startup.
If the `MELT` option is enabled, the loader deletes itself after successful execution to reduce the footprint on the victim machine.

# PandaLoader Builder Usage Guide
The PandaLoader Builder is a tool designed to help you create a custom payload loader by performing several steps, including shellcode encryption and remote hosting.
- Open `PandaBuilder.cmd`
- Input Shellcode: Start by providing your raw shellcode as input to the Builder.
- Shellcode Encryption: The Builder will encrypt your shellcode using `XOR` encryption. This step is essential for obfuscating the payload, to bypass `AV/EDR` etc.
- Upload Encrypted Shellcode: After encryption, you will be prompted to upload the encrypted shellcode to a remote server.
- Provide Download Link: Once the shellcode is uploaded, the Builder will ask for the `download link` to the shellcode. This link is necessary for the next step.
- Building the Loader: Using the provided download link, the Builder will compile a custom C++ stub (the loader). This loader is designed to download and execute the encrypted shellcode from the remote server.
- Compile the Loader: The final step is compiling the loader using `Mingw-w64`, a cross-compiler for Windows. Ensure that `Mingw-w64` is installed on your system before running the Builder.
- **NOTE: If startup is selected the Builder will generate an uninstaller for you to remove the Loader.**

# Requirements:
- Operating System: Any x64 Windows system.
- Compiler: Mingw-w64 must be installed.

# Downloads
[MinGW builds](https://github.com/brechtsanders/winlibs_mingw/releases)

# Detections 0/26
https://avcheck.net/id/dfYuFYeviJV8

> [!TIP]
> Please avoid raising issues related to detections, as it is not productive. The goal of this project is to support teaching and learning.
This project is fully undetectable (FUD) on its release day (August 2024). However, a free, publicly available, and open-source loader will not stay undetected for long. 
Modifying the stub to avoid detection is challenging, and any progress made will likely be rendered useless due to constant AV signature updates within a few days.
Therefore, no updates will be provided to address detection issues, however PandaLoader offers a fully functional implementation that is easy to modify and extend. 



# Contributing

Contributions are welcome, You can be a small part of this project!

# Credits
- https://github.com/ac3ss0r `compile-time obfuscation`
- https://github.com/EvilBytecode `Anti-VM techniques`
- https://github.com/7etsuo/windows-api-function-cheatsheets `injection methods` 
- https://github.com/mustjoon/evade-stager-c/tree/main `staged loader method` 

# License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/Chainski/PandaLoader/blob/main/LICENSE) file for details


# Disclaimer
Important Notice: This tool is intended for educational purposes only.
This software, referred to as PandaLoader, is provided strictly for educational and research purposes. 
Under no circumstances should this tool be used for any malicious activities, including but not limited to unauthorized access, data theft, or any other harmful actions.

Usage Responsibility:
By accessing and using this tool, you acknowledge that you are solely responsible for your actions. 
Any misuse of this software is strictly prohibited, and the creator (Chainski) disclaims any responsibility for how this tool is utilized. 
You are fully accountable for ensuring that your usage complies with all applicable laws and regulations in your jurisdiction.

No Liability:
The creator (Chainski) of this tool shall not be held responsible for any damages or legal consequences resulting from the use or misuse of this software. 
This includes, but is not limited to, direct, indirect, incidental, consequential, or punitive damages arising out of your access, use, or inability to use the tool.

No Support:
The creator (Chainski) will not provide any support, guidance, or assistance related to the misuse of this tool. Any inquiries regarding malicious activities will be ignored.

Acceptance of Terms:
By using this tool, you signify your acceptance of this disclaimer. If you do not agree with the terms stated in this disclaimer, do not use the software.
