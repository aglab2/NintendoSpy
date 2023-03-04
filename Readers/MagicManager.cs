﻿using LiveSplit.ComponentUtil;
using MIPSInterpreter;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NintendoSpy.Readers
{
    class MagicManager
    {
        const uint ramMagic = 0x3C1A8000;
        const uint ramMagicMask = 0xfffff000;

        private Process process;
        public readonly ulong ramPtrBase;

        public readonly int osContPifRam = 0;
        public readonly int interpretedInstructionsOffset = 0;
        public readonly byte[] interpretedInstructions = null;

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public int AllocationProtect;
            public int __alignment1;
            public ulong RegionSize;
            public int State;
            public int Protect;
            public int Type;
            public int __alignment2;
        }

        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public MagicManager(Process process, long[] ramPtrBaseSuggestions, int offset, ref int loadingProgress)
        {
            GC.Collect();
            this.process = process;

            bool isRamFound = false;

            foreach (long ramPtrBaseSuggestion in ramPtrBaseSuggestions)
            {
                ramPtrBase = (ulong) ramPtrBaseSuggestion;
                if (IsRamBaseValid())
                {
                    isRamFound = true;
                    break;
                }
            }


            ulong parallelStart = 0;
            ulong parallelEnd = 0;
            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName.Contains("parallel_n64"))
                {
                    parallelStart = (ulong)module.BaseAddress;
                    parallelEnd = parallelStart + (ulong)module.ModuleMemorySize;
                }
            }

            ulong MaxAddress = process.Is64Bit() ? 0x800000000000U : 0xffffffffU;
            ulong address = 0;
            do
            {
                if (isRamFound)
                    break;

                int result = VirtualQueryEx(process.Handle, new UIntPtr(address), out MEMORY_BASIC_INFORMATION m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                if (address == (ulong)m.BaseAddress + (ulong)m.RegionSize || result == 0)
                    break;

                AllocationProtect prot = (AllocationProtect)(m.Protect & 0xff);
                if (prot == AllocationProtect.PAGE_EXECUTE_READWRITE
                 || prot == AllocationProtect.PAGE_EXECUTE_WRITECOPY
                 || prot == AllocationProtect.PAGE_READWRITE
                 || prot == AllocationProtect.PAGE_WRITECOPY
                 || prot == AllocationProtect.PAGE_READONLY)
                {
                    uint value;
                    bool readSuccess = process.ReadValue(new IntPtr((long)(address + (ulong)offset)), out value);
                    if (readSuccess)
                    {
                        if (!isRamFound && ((value & ramMagicMask) == ramMagic))
                        {
                            ramPtrBase = address + (ulong)offset;
                            isRamFound = true;
                        }
                    }

                    // scan only large regions - we want to find g_rdram
                    ulong regionSize = (ulong)m.RegionSize;
                    if (parallelStart <= address && address <= parallelEnd && regionSize >= 0x800000)
                    {
                        // g_rdram is aligned to 0x1000
                        ulong maxCnt = (ulong)m.RegionSize / 0x1000;
                        for (ulong num = 0; num < maxCnt; num++)
                        {
                            readSuccess = process.ReadValue(new IntPtr((long)(address + num * 0x1000)), out value);
                            if (readSuccess)
                            {
                                if (!isRamFound && ((value & ramMagicMask) == ramMagic))
                                {
                                    ramPtrBase = address + num * 0x1000;
                                    isRamFound = true;
                                }
                            }

                            if (isRamFound)
                                break;
                        }
                    }
                }

                address = (ulong)m.BaseAddress + (ulong)m.RegionSize;
            }
            while (address <= MaxAddress);

            if (!isRamFound)
                throw new ArgumentException("Failed to find rom and ram!");

            loadingProgress++;
            uint[] mem;
            {
                byte[] bytes = process.ReadBytes(new IntPtr((long)ramPtrBase), 0x400000);
                int size = bytes.Count() / 4;
                mem = new uint[size];
                for (int idx = 0; idx < size; idx++)
                {
                    mem[idx] = BitConverter.ToUInt32(bytes, 4 * idx);
                }
            }

            DecompManager dm = new DecompManager(mem);
            if (!dm.osContPifRam.HasValue)
                throw new ArgumentException("Failed to gControllerPads!");

            loadingProgress++;
            osContPifRam = dm.osContPifRam.Value & 0xffffff;
            interpretedInstructionsOffset = dm.interpretedInstructionsOffset.Value;
            interpretedInstructions = dm.interpretedInstructions;
        }

        bool IsRamBaseValid()
        {
            uint value = 0;
            bool readSuccess = process.ReadValue(new IntPtr((long)ramPtrBase), out value);
            return readSuccess && ((value & ramMagicMask) == ramMagic);
        }

        public bool isValid()
        {
            return IsRamBaseValid() && osContPifRam != 0;
        }
    }
}
