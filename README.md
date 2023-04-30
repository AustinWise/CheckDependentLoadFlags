This will print the name of all executables that were not linked with the
[/DEPENDENTLOADFLAG:0x800](https://learn.microsoft.com/en-us/cpp/build/reference/dependentloadflag?view=msvc-170)
flag to `link.exe`.

Currently managed assemblies are not scanned.

To scan a folder:

```
dotnet run -- c:\src\dotnet\runtime\artifacts
```
