using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Windows.Win32.System.Diagnostics.Debug;

namespace CheckDependentLoadFlags
{
    internal class Program
    {
        static bool s_FoundBadDlls;
        static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Expected exactly one argument, the folder to scan");
                return 1;
            }

            string folderToScan = args[0];
            if (!Directory.Exists(folderToScan))
            {
                Console.WriteLine("Folder does not exist: " + folderToScan);
                return 1;
            }

            checkFolder(folderToScan);

            if (!s_FoundBadDlls)
            {
                Console.WriteLine("No bad PE files found.");
                return 0;
            }
            else
            {
                return 1;
            }
        }

        private static void checkFolder(string folderPath)
        {
            foreach (var f in Directory.EnumerateFiles(folderPath, " *.dll", SearchOption.AllDirectories).Concat(Directory.EnumerateFiles(folderPath, "*.dll", SearchOption.AllDirectories)))
            {
                if (IsMissingDllRestriction(f))
                {
                    Console.WriteLine(f);
                    s_FoundBadDlls = true;
                }
            }
        }

        static unsafe bool IsMissingDllRestriction(string path)
        {
            using var fs = File.OpenRead(path);

            int offset;
            int size;
            nint minSize;
            bool is32;
            using (var pe = new PEReader(fs, PEStreamOptions.LeaveOpen))
            {
                if (pe.HasMetadata)
                {
                    // Skip checking managed assemblies for now.
                    // TODO: check C++/CLI dlls.
                    return false;
                }

                if (pe.PEHeaders.PEHeader is null)
                {
                    throw new Exception("Miss PE headers in " + path);
                }

                if (pe.PEHeaders.PEHeader.ImportAddressTableDirectory.RelativeVirtualAddress == 0)
                {
                    // No imports, so it does not matter what the load configuration is.
                    return false;
                }

                var loadConfigDir = pe.PEHeaders.PEHeader.LoadConfigTableDirectory;
                if (loadConfigDir.RelativeVirtualAddress == 0)
                {
                    return true;
                }

                if (!pe.PEHeaders.TryGetDirectoryOffset(loadConfigDir, out offset))
                {
                    return true;
                }
                size = loadConfigDir.Size;

                if (pe.PEHeaders.PEHeader.Magic == PEMagic.PE32)
                {
                    minSize = Marshal.OffsetOf<IMAGE_LOAD_CONFIG_DIRECTORY32>(nameof(IMAGE_LOAD_CONFIG_DIRECTORY32.DependentLoadFlags));
                    is32 = true;
                }
                else
                {
                    Debug.Assert(pe.PEHeaders.PEHeader.Magic == PEMagic.PE32Plus);
                    minSize = Marshal.OffsetOf<IMAGE_LOAD_CONFIG_DIRECTORY64>(nameof(IMAGE_LOAD_CONFIG_DIRECTORY64.DependentLoadFlags));
                    is32 = false;
                }
                
                // field is a ushort;
                minSize += 4;

                if (size < minSize)
                {
                    return true;
                }
            }


            var structBytes = new byte[minSize];
            fs.Seek(offset, SeekOrigin.Begin);
            fs.ReadExactly(structBytes.AsSpan());

            int dependentLoadFlags;

            fixed (byte* pStructBytes = structBytes)
            {
                if (is32)
                {
                    IMAGE_LOAD_CONFIG_DIRECTORY32 loadConfig = default;
                    Buffer.MemoryCopy(pStructBytes, &loadConfig, minSize, minSize);
                    if (loadConfig.Size < minSize)
                    {
                        return true;
                    }
                    dependentLoadFlags = loadConfig.DependentLoadFlags;
                }
                else
                {
                    IMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = default;
                    Buffer.MemoryCopy(pStructBytes, &loadConfig, minSize, minSize);
                    if (loadConfig.Size < minSize)
                    {
                        return true;
                    }
                    dependentLoadFlags = loadConfig.DependentLoadFlags;
                }
            }

            return dependentLoadFlags != (int)Windows.Win32.System.LibraryLoader.LOAD_LIBRARY_FLAGS.LOAD_LIBRARY_SEARCH_SYSTEM32;
        }
    }
}