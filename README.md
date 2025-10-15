# Scripts for Hyper-V researching

Different scripts for Microsoft Hyper-V internals researches. Folder ida75 contains scripts, which is compatible with IDA PRO 7.5

- CreatemVmcallHandlersTable20H1.py - IDA Python script for extracting hvcalls from hvix64.exe, hvax64.exe Windows 10 20H1
- CreatemVmcallHandlersTable21H1.py - IDA Python script for extracting hvcalls from hvix64.exe, hvax64.exe Windows 10 21H1 (only 7.5)
- CreatemVmcallHandlersTable2016.py - IDA Python script for extracting hvcalls from hvix64.exe, hvax64.exe Windows Server 2016
- CreatemVmcallHandlersTable2019.py - IDA Python script for extracting hvcalls from hvix64.exe, hvax64.exe Windows Server 2019

For latest Windows versions (Windows Server 2025 and Windows 11) and older Windows version with fresh patches, i recommend to use Hvcall GUI C# app launcher for python scripts, which are dynamically extract hypercalls.
Extract hvcalls gui (later Hvcall GUI) video demonstration: https://www.youtube.com/watch?v=ohO4Hs4y59M or read that document: 

Some of scripts are using pykd: https://githomelab.ru/pykd/pykd/-/wikis/home.
If server is unavailable, you can use next instructions for pykd launching:

1. Install python 3.9
2. Install pykd module from pip

    ```pip install pykd```

3. Load 64-bit pykd.dll from [Download](https://yadi.sk/d/SUEX6-KzMiXM5w)
4. Load pykd.dll in WinDBG using

    ```
    .load "path_to_py_kd_dll"
    !py path_to_script
    ```

or see that resource: https://github.com/ivellioscolin/pykd

ParseAfdEndpointListHead.py - script for parsing afd!AfdEndpointListHead structure (WinDBG or WinDBG (classic), kd + pykd)

![](./images/image001.png)

ParseAfdTlTransportListHead.py - script for parsing afd!AfdTlTransportListHead (WinDBG or WinDBG (classic), kd + pykd)

![](./images/image002.png)