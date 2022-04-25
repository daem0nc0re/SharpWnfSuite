# SharpWnfSuite

This is the repository for Windows Notification Facility (WNF) tools.
Currently, a C# port of the tools in [wnfun](https://github.com/ionescu007/wnfun) developed by Alex Ionescu ([@aionescu](https://twitter.com/aionescu)) and Gabrielle Viala ([@pwissenlit](https://twitter.com/pwissenlit)) has been uploaded.
When I develop additional tools for Windows Notification Facility, they will be uploaded here.

## Table Of Contents
+ [SharpWnfSuite](#sharpwnfsuite)
    + [Usage](#usage)
        + [SharpWnfDump](#sharpwnfdump)
        + [SharpWnfNameDumper](#sharpwnfnamedumper)
        + [SharpWnfClient](#sharpwnfclient)
        + [SharpWnfServer](#sharpwnfserver)
        + [SharpWnfScan](#sharpwnfscan)
        + [SharpWnfInject](#sharpwnfinject)
    + [Reference](#reference)
    + [Acknowledgments](#acknowledgments)

## Usage
### SharpWnfDump

[Back to Top](#sharpwnfsuite)

[Project](./SharpWnfSuite/SharpWnfDump)

This tool dumps or manipulate information about WNF State Names.
Equivalent to [wnfdump.exe](https://github.com/ionescu007/wnfun/blob/master/wnftools_x64/wnfdump.exe) and [WnfDump.py](https://github.com/ionescu007/wnfun/blob/master/script_python/WnfDump.py).
I made some updates from the original tool (Exception Handling, Well-Known State Name and new WNF_DATA_SCOPE member).

To retrieve information of all Well-Known, Permanent and Persistent WNF State Names on your host, execute with `-d` (`--dump`) flag:

```
C:\dev>SharpWnfDump.exe -d

| WNF State Name [WnfWellKnownStateName Lifetime]                 | S | L | P | AC | N | CurSize | MaxSize | Changes |
----------------------------------------------------------------------------------------------------------------------
| WNF_WEBA_CTAP_DEVICE_STATE                                      | S | W | N | RO | U |       0 |      12 |       0 |
| WNF_WEBA_CTAP_DEVICE_CHANGE_NOTIFY                              | S | W | N | RO | U |       0 |       4 |       0 |
| WNF_PNPA_DEVNODES_CHANGED                                       | S | W | N | RO | U |       0 |       0 |     400 |

--snip--
```

If you want to retrieve Security Descripter information, set `-s` (`--sid`) flag:

```
C:\dev>SharpWnfDump.exe -d -s

| WNF State Name [WnfWellKnownStateName Lifetime]                 | S | L | P | AC | N | CurSize | MaxSize | Changes |
----------------------------------------------------------------------------------------------------------------------
| WNF_WEBA_CTAP_DEVICE_STATE                                      | S | W | N | RO | U |       0 |      12 |       0 |

	D:(A;;CCDC;;;SY)(A;;CCDC;;;BA)(A;;CCDC;;;S-1-5-80-242729624-280608522-2219052887-3187409060-2225943459)(A;;CC;;;AU)(A;;CC;;;AC)

--snip--
```

If you want to retrieve buffer data, set `-v` (`--value`) or `-r` (`--read`) flag:

```
C:\dev>SharpWnfDump.exe -d -v

| WNF State Name [WnfWellKnownStateName Lifetime]                 | S | L | P | AC | N | CurSize | MaxSize | Changes |
----------------------------------------------------------------------------------------------------------------------
| WNF_WEBA_CTAP_DEVICE_STATE                                      | S | W | N | RO | U |       0 |      12 |       0 |

--snip--

| WNF_AUDC_RENDER                                                 | S | W | N | RO | U |    4096 |    4096 |     345 |

		00000000 | 01 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 | ........ ........
		00000010 | 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 | ........ ........
		00000020 | 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 | ........ ........

--snip--
```

To retrieve information of all Temporary WNF State Names on your host, execute with `-b` (`--brut`) flag:

```
C:\dev>SharpWnfDump.exe -b

| WNF State Name [WnfDataScopeSystem Scope]                       | S | L | P | AC | N | CurSize | MaxSize | Changes |
----------------------------------------------------------------------------------------------------------------------
| 0x41C64E6DA3BC5045                                              | S | T | N | RO | U |       4 |       ? |       4 |
| 0x41C64E6DA3BC5845                                              | S | T | N | RO | U |       4 |       ? |       4 |

--snip--
```

The `-b` (`--brut`) flag can be used with `-v` (`--value`) or `-r` (`--read`) flag, but cannot be used with `-s` (`--sid`) flag.

The meaning of each column in the table obtained from the results of `--dump` or `--brut` option is as follows:

| Column Name | Description |
| :--- | :--- |
| `WNF State Name` | WNF State Names are outputted here |
| `S` | Data scope for WNF State Name. The meanings of the alphabets displayed are as follows:<br><br>+ `S` : System Scope<br>+ `s` : Session Scope<br>+ `U` : User Scope<br>+ `P` : Process Scope<br>+ `M` : Machine Scope<br>+ `p` : Physical Machine Scope |
| `L` | Lifetime for WNF State Name. The meanings of the alphabets displayed are as follows:<br><br>+ `W` : Well-Known<br>+ `P` : Permanent<br>+ `V` : Persistent (Volatile)<br>+ `T` : Temporary |
| `P` | Displays if the WNF State Name is permanent:<br><br>+ `Y` : Yes<br>+ `N` : No |
| `AC` | Access control for the WNF State Name:<br><br>+ `RW` : Readable and Writable<br>+ `RO` : Read-Only<br>+ `WO` : Write-Only<br>+ `NA` : Not Readable and Writable |
| `N` | Displays subscriber existence:<br><br>+ `A` : Subscriber exists<br>+ `I` : No subscriber exists<br>+ `U` : Unknown |
| `CurSize` | The number means current buffer size used for the WNF State Name. |
| `MaxSize` | The number means maximum buffer size can be used for the WNF State Name. |
| `Changes` | The number means how many times updated. |

If you want to retrieve information about a specific WNF State Name, execute `SharpWnfDump.exe` with `-i` (`--info`) option as follows:

```
C:\dev>SharpWnfDump.exe -i WNF_SHEL_APPRESOLVER_SCAN

| WNF State Name                                                  | S | L | P | AC | N | CurSize | MaxSize | Changes |
----------------------------------------------------------------------------------------------------------------------
| WNF_SHEL_APPRESOLVER_SCAN                                       | S | W | N | RW | A |       4 |       4 |      26 |

```

The `-i` (`--info`) option can be used with `-v` (`--value`), `-r` (`--read`), and `-s` (`--sid`) flag:

```
C:\dev>SharpWnfDump.exe -i WNF_SHEL_APPRESOLVER_SCAN -s -v

| WNF State Name                                                  | S | L | P | AC | N | CurSize | MaxSize | Changes |
----------------------------------------------------------------------------------------------------------------------
| WNF_SHEL_APPRESOLVER_SCAN                                       | S | W | N | RW | A |       4 |       4 |      26 |

        D:(A;;CC;;;WD)(A;;CCDC;;;AU)(A;;CCDC;;;AC)

                00000000 | 11 00 00 00                                     | ....

```

To read data from a specific WNF State Name, use `-r` (`--read`) flag as follows:

```
C:\dev>SharpWnfDump.exe -r WNF_SHEL_APPRESOLVER_SCAN

WNF_SHEL_APPRESOLVER_SCAN:

        00000000 | 11 00 00 00                                     | ....

```

To write data to a specific WNF State Name, use `-w` (`--write`) flag as follows (data for write should be provided with a file):

```
C:\dev>echo hi>test.txt

C:\dev>SharpWnfDump.exe -w WNF_SHEL_APPRESOLVER_SCAN test.txt

[>] Trying to write data.
    |-> Target WNF Name : WNF_SHEL_APPRESOLVER_SCAN
    |-> Data Source     : C:\dev\test.txt

[+] Data is written successfully.


C:\dev>SharpWnfDump.exe -r WNF_SHEL_APPRESOLVER_SCAN

WNF_SHEL_APPRESOLVER_SCAN:

        00000000 | 68 69 0D 0A                                     | hi..

```


### SharpWnfNameDumper

[Back to Top](#sharpwnfsuite)

[Project](./SharpWnfSuite/SharpWnfNameDumper)

This tool dumps Well-Known State Name from DLL (typically perf_nt_c.dll).
Equivalent to [WnfNameDumper.py](https://github.com/ionescu007/wnfun/blob/master/script_python/WnfNameDumper.py).

Typically, Well-Know State Names is contained in perf_nt_c.dll (it is in the Windows Performance Analyzer).
To dump Well-Know State Names from DLL, execute `SharpWnfNameDumper.exe` with `-d` (`--dump`) option as follows:

```
C:\dev>SharpWnfNameDumper.exe -d perf_nt_c.dll

[>] Output results in C# style.

public enum WELL_KNOWN_WNF_NAME : ulong
{
    WNF_9P_REDIRECTOR_STARTED = 0x41C61E54A3BC1075UL,
    WNF_9P_UNKNOWN_DISTRO_NAME = 0x41C61E54A3BC0875UL,

--snip--
```

If you want to dump description for Well-Known State Names, set `-v` flag:

```
C:\dev>SharpWnfNameDumper.exe -d perf_nt_c.dll -v

[>] Output results in C# style.

public enum WELL_KNOWN_WNF_NAME : ulong
{
    // The Plan 9 Redirector was started and is ready to accept requests.
    WNF_9P_REDIRECTOR_STARTED = 0x41C61E54A3BC1075UL,
    // The Plan 9 Redirector got a request for an unknown WSL distribution and there is no user callback registered to query it.
    WNF_9P_UNKNOWN_DISTRO_NAME = 0x41C61E54A3BC0875UL,

--snip--
```

To specify the output format, use `-f` (`--format`) option. `SharpWnfNameDumper.exe` supports C#, C (`-f c`) and Python (`-f py`) format (default format is C#):

```
C:\dev>SharpWnfNameDumper.exe -d perf_nt_c.dll -f py

[>] Output results in Python style.

g_WellKnownWnfNames = {
    "WNF_9P_REDIRECTOR_STARTED": 0x41C61E54A3BC1075,
    "WNF_9P_UNKNOWN_DISTRO_NAME": 0x41C61E54A3BC0875,

--snip--
```

To output the result to a file, use `-o` (`--output`) option to specify output file path:

```
C:\dev>SharpWnfNameDumper.exe -d perf_nt_c.dll -o result.txt

[>] Output results in C# style.


C:\dev>type result.txt
public enum WELL_KNOWN_WNF_NAME : ulong
{
    WNF_9P_REDIRECTOR_STARTED = 0x41C61E54A3BC1075UL,
    WNF_9P_UNKNOWN_DISTRO_NAME = 0x41C61E54A3BC0875UL,

--snip--
```

To take diff from 2 DLLs, use `-D` (`--diff`) option:

```
C:\dev>SharpWnfNameDumper.exe -D perf_nt_c_old.dll perf_nt_c_new.dll

[>] Output results in C# style.

################################################
#                   NEW KEYS                   #
################################################


public enum WELL_KNOWN_WNF_NAME : ulong
{
    WNF_SHEL_CHAT_ICON_BADGE = 0x0D83063EA3B8A035UL,
    WNF_SHEL_ENTERPRISE_START_PINS_POLICY_VALUE_CHANGED = 0x0D83063EA3B89475UL,
    WNF_SHEL_FILE_EXPLORER_PINNED_FOLDERS = 0x0D83063EA3B8ACF5UL,
    WNF_SHEL_MAC_AUTO_UPDATE_SUCCEEDED = 0x0D83063EA3B89875UL
}
```


### SharpWnfClient

[Back to Top](#sharpwnfsuite)

[Project](./SharpWnfSuite/SharpWnfClient)

This is a tool for a subscribe WNF State Name.
Equivalent to [wnfclient-rtl.exe](https://github.com/ionescu007/wnfun/blob/master/wnftools_x64/wnfclient-rtl.exe) and [WnfClientServer.py](https://github.com/ionescu007/wnfun/blob/master/script_python/WnfClientServer.py).

For example, if you want to monitor the state of `WNF_SHEL_APPLICATION_STARTED`, execute `SharpWnfClient.exe` as follows:

```
C:\dev>SharpWnfClient.exe WNF_SHEL_APPLICATION_STARTED

[>] Received data from server.
    |-> Timestamp : 393
    |-> Buffer Size : 106 byte(s)
    |-> Data :
                00000000 | 61 00 3A 00 7B 00 31 00-61 00 63 00 31 00 34 00 | a.:.{.1. a.c.1.4.
                00000010 | 65 00 37 00 37 00 2D 00-30 00 32 00 65 00 37 00 | e.7.7.-. 0.2.e.7.
                00000020 | 2D 00 34 00 65 00 35 00-64 00 2D 00 62 00 37 00 | -.4.e.5. d.-.b.7.
                00000030 | 34 00 34 00 2D 00 32 00-65 00 62 00 31 00 61 00 | 4.4.-.2. e.b.1.a.
                00000040 | 65 00 35 00 31 00 39 00-38 00 62 00 37 00 7D 00 | e.5.1.9. 8.b.7.}.
                00000050 | 5C 00 6E 00 6F 00 74 00-65 00 70 00 61 00 64 00 | \.n.o.t. e.p.a.d.
                00000060 | 2E 00 65 00 78 00 65 00-00 00                   | ..e.x.e. ..
```

Then, if you start Slack application, should see following result:

```
[>] Received data from server.
    |-> Timestamp : 394
    |-> Buffer Size : 54 byte(s)
    |-> Data :
                00000000 | 61 00 3A 00 63 00 6F 00-6D 00 2E 00 73 00 71 00 | a.:.c.o. m...s.q.
                00000010 | 75 00 69 00 72 00 72 00-65 00 6C 00 2E 00 73 00 | u.i.r.r. e.l...s.
                00000020 | 6C 00 61 00 63 00 6B 00-2E 00 73 00 6C 00 61 00 | l.a.c.k. ..s.l.a.
                00000030 | 63 00 6B 00 00 00                               | c.k...

```


### SharpWnfServer

[Back to Top](#sharpwnfsuite)

[Project](./SharpWnfSuite/SharpWnfServer)

This tool creates a temporary lifetime WNF State Name and sends some message to the subscriber.
Equivalent to [wnfserver.exe](https://github.com/ionescu007/wnfun/blob/master/wnftools_x64/wnfserver.exe) and [WnfClientServer.py](https://github.com/ionescu007/wnfun/blob/master/script_python/WnfClientServer.py).

To start new WNF State Name server, simply execute `SharpWnfServer.exe`. We should enter an interactive shell as follows:

```
C:\dev>SharpWnfServer.exe

[+] New WNF State Name is created successfully : 0x41C64E6DA67F7145


Encoded State Name: 0x41C64E6DA67F7145, Decoded State Name: 0x5C37131
        Version: 1, Lifetime: Temporary, Scope: Machine, Permanent: NO, Sequence Number: 0xB86E, Owner Tag: 0x0

Sending input data to WNF subscriber...

[INPUT]>
```

After executing `SharpWnfServer.exe`, execute `SharpWnfClient.exe` with WNF State Name provided with `SharpWnfServer.exe` from another terminal. You should receive "Hello, world!" as a message from `SharpWnfServer.exe`:

```
C:\dev>SharpWnfClient.exe 0x41C64E6DA67F7145

[>] Received data from server.
    |-> Timestamp : 1
    |-> Buffer Size : 13 byte(s)
    |-> Data :
                00000000 | 48 65 6C 6C 6F 2C 20 77-6F 72 6C 64 21          | Hello,.w orld!

```

To publish additional message to `SharpWnfClient.exe`, enter your message to the interactive shell of `SharpWnfServer.exe`:

```
[INPUT]> This is wnf test
Sending input data to WNF subscriber...

[INPUT]>
```

Then, you should see the message in the terminal for `SharpWnfClient.exe` as follows:

```
[>] Received data from server.
    |-> Timestamp : 2
    |-> Buffer Size : 16 byte(s)
    |-> Data :
                00000000 | 54 68 69 73 20 69 73 20-77 6E 66 20 74 65 73 74 | This.is. wnf.test

```


### SharpWnfScan

[Back to Top](#sharpwnfsuite)

[Project](./SharpWnfSuite/SharpWnfScan)

This tool is based on [modexp](https://twitter.com/modexpblog)'s [wnfscan](https://github.com/odzhan/injection/blob/master/wnf/wnfscan.c), and dumps WNF subscription information from process.

```
C:\dev>SharpWnfScan.exe

SharpWnfScan - Tool for dumping WNF information from process.

Usage: SharpWnfScan.exe [Options]

        -h, --help      : Displays this help message.
        -p, --pid       : Specifies the target PID.
        -n, --name      : Specifies the target process name.
        -s, --statename : Specifies a wnf state name for filtering.
        -a, --all       : Flag to dump information from all process.
        -d, --debug     : Flag to enable SeDebugPrivilege. Administrative privilege is required.
```

To dump a specific process, set `-p` option as follows:

```
C:\dev>SharpWnfScan.exe -p 9236

Process Name : explorer.exe
Process ID   : 9236
Architecture : x64

WNF_SUBSCRIPTION_TABLE @ 0x0000000000F6EEB0

        WNF_NAME_SUBSCRIPTION @ 0x00000000157D79C0
        StateName : 0x41C61439A3BC1075 (WNF_TZ_STORE_CHANGED)

                WNF_USER_SUBSCRIPTION @ 0x00000000156B3E50
                Callback @ 0x00007FFAC69ECD40 (Windows.Globalization.dll!DllCanUnloadNow)
                Context  @ 0x00007FFAC6B41840 (Windows.Globalization.dll!DllCanUnloadNow)

        WNF_NAME_SUBSCRIPTION @ 0x00000000157D65C0
        StateName : 0x41C61439A3BC0875 (WNF_TZ_LEGACY_STORE_CHANGED)

                WNF_USER_SUBSCRIPTION @ 0x00000000156B3CF0
                Callback @ 0x00007FFAC69ECD40 (Windows.Globalization.dll!DllCanUnloadNow)
                Context  @ 0x00007FFAC6B41840 (Windows.Globalization.dll!DllCanUnloadNow)

--snip--
```

You can specifies target processes by name with `-n` option:

```
C:\dev>SharpWnfScan.exe -n notepad

Process Name : notepad.exe
Process ID   : 6812
Architecture : x86
Warning      : To get detailed symbol information of WOW64 process, should be built as 32 bit binary.

WNF_SUBSCRIPTION_TABLE @ 0x02960F08

        WNF_NAME_SUBSCRIPTION @ 0x02986DC8
        StateName : 0x7851E3FA3BC0875 (WNF_RPCF_FWMAN_RUNNING)

                WNF_USER_SUBSCRIPTION @ 0x02992778
                Callback @ 0x766DFDB0 (rpcrt4.dll)
                Context  @ 0x00000000 (N/A)

--snip--
```

To filter with state name, set hex or well know wnf name string to `-s` option as follows:

```
C:\dev>SharpWnfScan.exe -n notepad -s WNF_RPCF_FWMAN_RUNNING

Process Name : notepad.exe
Process ID   : 10676
Architecture : x64

WNF_SUBSCRIPTION_TABLE @ 0x000002AB85EF08F0

        WNF_NAME_SUBSCRIPTION @ 0x000002AB85F2DF70
        StateName : 0x07851E3FA3BC0875 (WNF_RPCF_FWMAN_RUNNING)

                WNF_USER_SUBSCRIPTION @ 0x000002AB85F1E220
                Callback @ 0x00007FFADA9673B0 (rpcrt4.dll!I_RpcBindingSetPrivateOption)
                Context  @ 0x0000000000000000 (N/A)



C:\dev>SharpWnfScan.exe -n notepad -s 0x7851E3FA3BC0875

Process Name : notepad.exe
Process ID   : 10676
Architecture : x64

WNF_SUBSCRIPTION_TABLE @ 0x000002AB85EF08F0

        WNF_NAME_SUBSCRIPTION @ 0x000002AB85F2DF70
        StateName : 0x07851E3FA3BC0875 (WNF_RPCF_FWMAN_RUNNING)

                WNF_USER_SUBSCRIPTION @ 0x000002AB85F1E220
                Callback @ 0x00007FFADA9673B0 (rpcrt4.dll!I_RpcBindingSetPrivateOption)
                Context  @ 0x0000000000000000 (N/A)
```

To dump all processes at a time, use `-a` option:

```
C:\dev>SharpWnfScan.exe -a

Process Name  : gamingservices
Process ID    : 5600
Architecture  : N/A
Error Message : Access is denied

--snip--

Process Name : chrome.exe
Process ID   : 10248
Architecture : x64

WNF_SUBSCRIPTION_TABLE @ 0x0000019D34FA6930

        WNF_NAME_SUBSCRIPTION @ 0x0000019D34FC5A70
        StateName : 0x418A073AA3BC88F5 (WNF_WIL_USER_FEATURE_STORE)

                WNF_USER_SUBSCRIPTION @ 0x0000019D34FC59C0
                Callback @ 0x00007FFADA72F720 (combase.dll!ObjectStublessClient32)
                Context  @ 0x00007FFADA8A3F10 (combase.dll!Ordinal183essClient32)

        WNF_NAME_SUBSCRIPTION @ 0x0000019D34FC5920
        StateName : 0x418A073AA3BC7C75 (WNF_WIL_MACHINE_FEATURE_STORE)

                WNF_USER_SUBSCRIPTION @ 0x0000019D34FC5870
                Callback @ 0x00007FFADA72F720 (combase.dll!ObjectStublessClient32)
                Context  @ 0x00007FFADA8A3F10 (combase.dll!Ordinal183essClient32)

--snip--
```

To enable `SeDebugPrivilege`, set `-d` flag as follows.
This option requires administrative privilege:

```
C:\dev>SharpWnfScan.exe -d -n lsass

[>] Trying to enable SeDebugPrivilege.
[+] SeDebugPrivilege is enabled successfully.

Process Name : lsass.exe
Process ID   : 1212
Architecture : x64

WNF_SUBSCRIPTION_TABLE @ 0x0000022C22A13B30

        WNF_NAME_SUBSCRIPTION @ 0x0000022C2320AAF0
        StateName : 0x418F1D23A3BC0875 (WNF_NSI_SERVICE_STATUS)

                WNF_USER_SUBSCRIPTION @ 0x0000022C23508260
                Callback @ 0x00007FFAD12C3C00 (winnsi.dll!NsiRpcSetParameterEx)
                Context  @ 0x0000000000000000 (N/A)

        WNF_NAME_SUBSCRIPTION @ 0x0000022C2340B1D0
        StateName : 0x17951A3BA3BC0875 (WNF_VTSV_CDS_SYNC)

                WNF_USER_SUBSCRIPTION @ 0x0000022C22AC9700
                Callback @ 0x00007FFAA08FFCE0 (vaultsvc.dll!ServiceMainameterEx)
                Context  @ 0x0000000000000000 (N/A)

--snip--
```


### SharpWnfInject

[Back to Top](#sharpwnfsuite)

[Project](./SharpWnfSuite/SharpWnfInject)

This tool is to investigate how attackers can abuse WNF for code injection technique:

```
C:\dev>SharpWnfInject.exe -h

SharpWnfInject - Tool to investigate WNF code injection technique.

Usage: SharpWnfInject.exe [Options]

        -h, --help  : Displays this help message.
        -n, --name  : Specifies WNF State Name to inject. Hex format or Well-known name format is accepted.
        -p, --pid   : Specifies PID to inject.
        -i, --input : Specifies the file path to shellcode.
        -d, --debug : Flag to enable SeDebugPrivilege. Requires administrative privilege.
```

This tool overwrite callback function pointer in `WNF_USER_SUBSCRIPTION` for a specific WNF State Name.
The code injection technique does not work for all WNF State Name.
For example, this technique is known to be available for `WNF_SHEL_APPLICATION_STARTED` used in `explorer.exe`.
To test this technique, execute this tool as following:

```
C:\dev>SharpWnfInject.exe -p 4040 -n WNF_SHEL_APPLICATION_STARTED -i payload.bin

[>] Trying to open the target process.
[+] Target process is opened successfully.
    |-> Process Name : explorer.exe
    |-> Process ID   : 4040
    |-> Architecture : x64
[>] Trying to get WNF_SUBSCRIPTION_TABLE.
[+] Got valid WNF_SUBSCRIPTION_TABLE.
    |-> Address : 0x0000000000B4BCB0
[>] Trying to get WNF_NAME_SUBSCRIPTION(s).
[+] Got 99 WNF_NAME_SUBSCRIPTION(s)
[>] Searching the WNF_NAME_SUBSCRIPTION for the specified WNF State Name.
[+] Got WNF_NAME_SUBSCRIPTION for the specified WNF State Name.
    |-> WNF State Name : WNF_SHEL_APPLICATION_STARTED (0x0D83063EA3BE0075)
    |-> Address        : 0x0000000007ED4640
[>] Trying to get WNF_USER_SUBSCRIPTION(s) for the target WNF_NAME_SUBSCRIPTION.
[+] Got 1 WNF_USER_SUBSCRIPTION(s).
[>] Trying to inject shellccode to the following WNF_USER_SUBSCRIPTION.
    |-> Address  : 0x00000000049A5930
    |-> Callback : 0x00007FFE6C1DEE90 (twinui.pcshell.dll)
[>] Trying to allocate shellcode buffer in remote process.
[+] Shellcode buffer is allocated successfully.
    |-> Shellcode buffer : 0x0000000000D20000
[>] Trying to write shellcode to remote process.
[+] Shellcode are written successfully.
    |-> Shellcode Length : 344 byte(s)
[>] Trying to overwrite callback function pointer.
[+] Callback function pointer is overwritten successfully.
[+] WNF State Data is updated successfully.
[>] Trying to revert callback function pointer.
[+] Callback function pointer is reverted successfully.
[+] Code injection is completed successfully.
```

If you want to enable `SeDebugPrivilege`, set `-d` flag and execute with administrative privilege.


## Reference

[Back to Top](#sharpwnfsuite)

+ [Windows Notification Facility: Peeling the Onion of the Most Undocumented Kernel Attack Surface Yet](https://www.youtube.com/watch?v=MybmgE95weo)
+ [Playing with the Windows Notification Facility (WNF)](https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html)
+ [wnfun](https://github.com/ionescu007/wnfun)
+ [Windows Process Injection : Windows Notification Facility](https://modexp.wordpress.com/2019/06/15/4083/)

## Acknowledgments

[Back to Top](#sharpwnfsuite)

Thanks for your research:

+ Alex Ionescu ([@aionescu](https://twitter.com/aionescu))
+ Gabrielle Viala ([@pwissenlit](https://twitter.com/pwissenlit))
+ odzhan ([@modexpblog](https://twitter.com/modexpblog))
