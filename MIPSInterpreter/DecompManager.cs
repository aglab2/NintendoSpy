using System;
using System.Collections.Generic;
using System.Linq;

namespace MIPSInterpreter
{
    public class DecompManager
    {
        public int? interpretedInstructionsOffset;
        public byte[] interpretedInstructions = null;
        public int? osContPifRam = null;

        // Magic regarding RAM dynamic decompiling
        static unsafe List<int> IndicesOf(uint[] arrayToSearchThrough, uint[] patternToFind)
        {
            List<int> ret = new List<int>();
            if (patternToFind.Length > arrayToSearchThrough.Length)
                return ret;

            fixed (uint* arrayToSearchThroughPtr = arrayToSearchThrough, patternToFindPtr = patternToFind)
            {
                for (int i = 0; i <= arrayToSearchThrough.Length - patternToFind.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < patternToFind.Length; j++)
                    {
                        if (arrayToSearchThroughPtr[i + j] != patternToFindPtr[j])
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found)
                    {
                        ret.Add(i);
                    }
                }
            }

            return ret;
        }

        static unsafe List<int> FindAll(uint[] arrayToSearchThrough, uint val)
        {
            List<int> list = new List<int>();
            fixed (uint* ptr = arrayToSearchThrough)
            {
                for (int i = 0; i < arrayToSearchThrough.Length; i++)
                {
                    if (ptr[i] == val)
                        list.Add(i);
                }
            }

            return list;
        }

        static readonly uint[] OsGetCount = new uint[]
        {
            0x40024800, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsDisableInt = new uint[]
        {
            0x40086000, 0x2401FFFE, 0x01014824, 0x40896000, 0x31020001, 0x00000000, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsDisableInt2 = new uint[]
        {
            0x40086000, 0x2401FFFE, 0x01014824, 0x40896000, 0x31020001, 0x8D480000, 0x3108FF00, 0x110B000E
        };

        static readonly uint[] OsRestoreInt = new uint[]
        {
            0x40086000, 0x01044025, 0x40886000, 0x00000000, 0x00000000, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsWritebackDCache = new uint[]
        {
            0x18A00011, 0x00000000, 0x240B2000, 0x00AB082B, 0x1020000F, 0x00000000, 0x00804025, 0x00854821,
            0x0109082B, 0x10200008, 0x00000000, 0x310A000F, 0x2529FFF0, 0x010A4023, 0xBD190000, 0x0109082B,
            0x1420FFFD, 0x25080010, 0x03E00008, 0x00000000, 0x3C088000, 0x010B4821, 0x2529FFF0, 0xBD010000,
            0x0109082B, 0x1420FFFD, 0x25080010, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsInvalDCache = new uint[]
        {
            0x18A0001F, 0x00000000, 0x240B2000, 0x00AB082B, 0x1020001D, 0x00000000, 0x00804025, 0x00854821,
            0x0109082B, 0x10200016, 0x00000000, 0x310A000F, 0x11400007, 0x2529FFF0, 0x010A4023, 0xBD150000,
            0x0109082B, 0x1020000E, 0x00000000, 0x25080010, 0x312A000F, 0x11400006, 0x00000000, 0x012A4823,
            0xBD350010, 0x0128082B, 0x14200005, 0x00000000, 0xBD110000, 0x0109082B, 0x1420FFFD, 0x25080010,
            0x03E00008, 0x00000000, 0x3C088000, 0x010B4821, 0x2529FFF0, 0xBD010000, 0x0109082B, 0x1420FFFD,
            0x25080010, 0x03E00008, 0x00000000
        };

        static bool IsVAddr(uint addr)
        {
            if (0x80000000 != (0xff000000 & addr))
                return false;

            uint off = addr & 0x00ffffff;
            if (off > 0x800000)
                return false;

            return true;
        }

        static List<int> FindAllJumpsTo(uint[] mem, int pos)
        {
            Instruction jmpInst = new Instruction
            {
                cmd = Cmd.JAL,
                jump = (uint)(4 * pos)
            };
            uint jmpInstVal = Converter.ToUInt(jmpInst);
            return FindAll(mem, jmpInstVal);
        }

        static SortedSet<int> FindAllJumpsTo(uint[] mem, List<int> poses)
        {
            SortedSet<int> jumps = new SortedSet<int>();
            foreach (int pos in poses)
            {
                foreach (var jump in FindAllJumpsTo(mem, pos))
                {
                    jumps.Add(jump);
                }
            }

            return jumps;
        }

        static SortedSet<int> FindAllJumpsTo(uint[] mem, uint[] data)
        {
            return FindAllJumpsTo(mem, IndicesOf(mem, data));
        }

        static int CountJumps(uint[] mem, int regionStart, int regionEnd)
        {
            int jmpCount = 0;
            for (int i = regionStart; i <= regionEnd; i++)
            {
                var inst = Decompiler.Decode(mem[i]);
                if (inst.cmd == Cmd.JAL)
                {
                    jmpCount++;
                }
            }

            return jmpCount;
        }

        static uint GetSecondArgumentToJAL(uint[] mem, uint off)
        {
            uint vaddr = 0x80000000 | (off << 2);
            Interpreter interpreter = new Interpreter(mem);
            const uint InstructionsToInterpretCount = 16;
            const uint BytesToInterpretCount = InstructionsToInterpretCount << 2;
            interpreter.pc = vaddr - BytesToInterpretCount;

            Instruction? inst;
            for (int i = 0; i < InstructionsToInterpretCount + 2 /*JAL + delay slot*/; i++)
            {
                inst = interpreter.GetInstruction();
                if (inst.HasValue)
                    interpreter.Execute(inst.Value);
            }

            return (uint) interpreter.gpr[(int)Register.A1];
        }

        static bool IsPrologInstruction(Instruction inst)
        {
            return inst.cmd == Cmd.ADDIU && inst.rt == Register.SP && inst.rs == Register.SP && inst.imm < 0;
        }

        static int FindProlog(uint[] mem, int start, int maxScanLength)
        {
            for (int i = start - 1; i > start - maxScanLength; i--)
            {
                var inst = Decompiler.Decode(mem[i]);
                if (IsPrologInstruction(inst))
                {
                    return i;
                }
            }

            throw new ArgumentException("Failed to detect the prolog");
        }

        public DecompManager(uint[] mem)
        {
            SortedSet<int> osGetCountJumps = FindAllJumpsTo(mem, OsGetCount);
            var disableOff = IndicesOf(mem, OsDisableInt);
            foreach (int off in IndicesOf(mem, OsDisableInt2))
            {
                disableOff.Add(off - 4);
            }
            SortedSet<int> osDisableIntJumps = FindAllJumpsTo(mem, disableOff);
            SortedSet<int> osRestoreIntJumps = FindAllJumpsTo(mem, OsRestoreInt);
            // Discover all osGetTime function that look like calls to 3 functions
            // OSTime osGetTime()
            // {
            //    ... saveMask = __osDisableInt();
            //    ... tmptime = osGetCount();
            //    ... __osRestoreInt(saveMask);
            // }
            List<int> osGetTimes = new List<int>();
            foreach (int regionStart in osDisableIntJumps)
            {
                try
                {
                    const int MaxRegionLength = 0x18;
                    var view = osRestoreIntJumps.GetViewBetween(regionStart, regionStart + MaxRegionLength);
                    if (view.Count == 0)
                        continue;

                    var regionEnd = view.First();
                    view = osGetCountJumps.GetViewBetween(regionStart, regionEnd);
                    if (view.Count == 0)
                        continue;

                    // Must be only calls to __osDisableInt + osGetCount + __osRestoreInt
                    if (3 != CountJumps(mem, regionStart, regionEnd))
                        continue;

                    osGetTimes.Add(FindProlog(mem, regionStart, 0x10));
                }
                catch (Exception) { }
            }

            SortedSet<int> osWritebackDCacheJumps = FindAllJumpsTo(mem, OsWritebackDCache);
            SortedSet<int> osInvalDCacheJumps = FindAllJumpsTo(mem, OsInvalDCache);

            // Discover all __osSiRawStartDma that looks like call to 3 functions with 4th being after prolog
            //  s32 __osSiRawStartDma(s32 direction, void* dramAddr)
            // {
            //   ... if (__osSiDeviceBusy())
            //   ...    osWritebackDCache(dramAddr, 64);
            //   ... IO_WRITE(SI_DRAM_ADDR_REG, osVirtualToPhysical(dramAddr));
            //   ...     osInvalDCache(dramAddr, 64);
            // }
            List<int> osSiRawStartDmas = new List<int>();
            foreach (int regionStart in osWritebackDCacheJumps)
            {
                try
                {
                    const int MaxRegionLength = 0x18;
                    var view = osInvalDCacheJumps.GetViewBetween(regionStart, regionStart + MaxRegionLength);
                    if (view.Count == 0)
                        continue;

                    int regionEnd = view.First();

                    // Must be only calls to osWritebackDCache + osVirtualToPhysical + osInvalDCache
                    if (3 != CountJumps(mem, regionStart, regionEnd))
                        continue;

                    osSiRawStartDmas.Add(FindProlog(mem, regionStart, 0x20));
                }
                catch (Exception) { }
            }

            SortedSet<int> osGetTimeJumps = FindAllJumpsTo(mem, osGetTimes);
            SortedSet<int> osSiRawStartDmaJumps = FindAllJumpsTo(mem, osSiRawStartDmas);

            // Discover all osContInit, we do not need the functions themselves but __osContPifRam passed to __osSiRawStartDma
            // We know that 'osContInit' calls to 'osGetTime' and '__osSiRawStartDma' 2 times
            foreach (int regionStart in osGetTimeJumps)
            {
                try
                {
                    const int MaxRegionLength = 0x80;
                    var view = osSiRawStartDmaJumps.GetViewBetween(regionStart, regionStart + MaxRegionLength);
                    if (view.Count != 2)
                        continue;

                    // Interpret the code around both JALs
                    List<uint> osContPifRams = new List<uint>();
                    foreach (int jump in view)
                    {
                        osContPifRams.Add(GetSecondArgumentToJAL(mem, (uint)jump));
                    }

                    if (osContPifRams[0] != osContPifRams[1])
                        continue;

                    uint vosContPifRam = osContPifRams[0];
                    if (!IsVAddr(vosContPifRam))
                        continue;

                    int regionEnd = view.Last();
                    int regionLength = regionEnd - regionStart;
                    var interpretedSegment = new ArraySegment<uint>(mem, regionStart, regionLength);

                    interpretedInstructionsOffset = regionStart << 2;
                    interpretedInstructions = new byte[regionLength << 2];
                    var interpretedInstructionsIdx = 0;
                    foreach (uint num in interpretedSegment)
                    {
                        Array.Copy(BitConverter.GetBytes(num), 0, interpretedInstructions, interpretedInstructionsIdx, 4);
                        interpretedInstructionsIdx += 4;
                    }

                    osContPifRam = (int) vosContPifRam;
                    return;
                }
                catch (Exception) { }
            }
        }
    }
}
