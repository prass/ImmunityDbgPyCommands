# ImmunityDbgPyCommands

## dlltrack
Script that tracks libs. It waits till the lib is loaded and then automatically sets breakpoints on every exported function.
### Usage:
```
!dlltrack DLLNAME1.dll DLLNAME2.dll ...
```
