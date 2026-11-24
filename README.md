# tokenrun

Windows tool that lists processes with their token owners and runs a program under a token copied from a chosen process.

It needs SeAssignPrimaryTokenPrivilege, which a standard admin WinRM session does not hold. It creates the child with CreateProcessAsUserW, which honours the session id set on the copied token.

## Usage

```
tokenrun.exe list
tokenrun.exe run          --pid <pid>                 impersonated interactive cmd (target session)
tokenrun.exe exec         --pid <pid> --command <cmd> impersonated command, output on OUR channel
tokenrun.exe exec-desktop --pid <pid> --command <cmd> impersonated command on the TARGET's desktop
```

## Build

Cross-compile with MinGW-w64:

```
x86_64-w64-mingw32-gcc tokenrun.c -o tokenrun.exe -ladvapi32 -luserenv -luser32 -O2 -s
```

## License

MIT. See LICENSE.
