using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MIPSInterpreter
{
    struct MaskPair
    {
        public uint val;
        public uint mask;

        public MaskPair(uint val, uint mask)
        {
            this.val = val;
            this.mask = mask;
        }

        public override string ToString()
        {
            return $"0x{val:X8}, 0x{mask:X8}";
        }
    }

    public class DecompManager
    {
        public int? interpretedInstructionsOffset;
        public byte[] interpretedInstructions = null;
        public int? gControllerPads = null;

        // Magic regarding RAM dynamic decompiling
        static unsafe List<int> IndicesOf(uint[] arrayToSearchThrough, MaskPair[] patternToFind)
        {
            List<int> ret = new List<int>();
            if (patternToFind.Length > arrayToSearchThrough.Length)
                return ret;

            fixed (MaskPair* patternToFindPtr = patternToFind)
            fixed (uint* arrayToSearchThroughPtr = arrayToSearchThrough)
            {
                for (int i = 0; i <= arrayToSearchThrough.Length - patternToFind.Length; i++)
                {
                    bool found = true;
                    for (int j = 0; j < patternToFind.Length; j++)
                    {
                        var data = arrayToSearchThroughPtr[i + j];
                        var expectedAfterMasking = patternToFindPtr[j].val;
                        var mask = patternToFindPtr[j].mask;
                        var maskedData = data & (~mask);
                        var leftoverData = data & mask;
                        if (maskedData != expectedAfterMasking || (0 != mask && 0 == leftoverData))
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

        static readonly MaskPair[] OsDisableInt = new MaskPair[]
        {
            new MaskPair(0x40006000, 0x001F0000), // MFC0     T0, Status              MFC0     __, Status
            new MaskPair(0x2400FFFE, 0x001F0000), // ADDIU    AT, R0, 0xFFFE          ADDIU    __, R0, 0xFFFE
            new MaskPair(0x00000024, 0x03FFF800), // AND      T1, T0, AT              AND      __, __, __
            new MaskPair(0x40806000, 0x001F0000), // MTC0     T1, Status              MTC0     __, Status
            new MaskPair(0x30020001, 0x03E00000), // ANDI     V0, T0, 0x0001          ANDI     V0, __, 0x0001
        };

        static readonly MaskPair[] OsRestoreInt = new MaskPair[]
        {
            new MaskPair(0x40006000, 0x001F0000), // MFC0     T0, Status              MFC0     __, Status
            new MaskPair(0x00040025, 0x03E0F800), // OR       T0, T0, A0              OR       __, __, A0
            new MaskPair(0x40806000, 0x001F0000), // MTC0     T0, Status              MTC0     __, Status
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0x03E00008, 0x00000000), // JR       RA                      JR       RA
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
        };

        static readonly MaskPair[] OsWritebackDCache = new MaskPair[]
        {
            new MaskPair(0x00000023, 0x03FFF800), // SUBU     T0, T0, T2              SUBU     __, __, __
            new MaskPair(0xBC190000, 0x03E00000), // CACHE    (D, IIndexLoadData), T0, 0x0000 CACHE    (D, IIndexLoadData), __, 0x0000
            new MaskPair(0x0000002B, 0x03FFF800), // SLTU     AT, T0, T1              SLTU     __, __, __
            new MaskPair(0x1400FFFD, 0x03E00000), // BNE      R0, 0xFFFFFFF4(AT)      BNE      R0, 0xFFFFFFF4(__)
            new MaskPair(0x24000010, 0x03FF0000), // ADDIU    T0, T0, 0x0010          ADDIU    __, __, 0x0010
            new MaskPair(0x03E00008, 0x00000000), // JR       RA                      JR       RA
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0x3C008000, 0x001F0000), // LUI      T0, 0x8000              LUI      __, 0x8000
            new MaskPair(0x00000021, 0x03FFF800), // ADDU     T1, T0, T3              ADDU     __, __, __
            new MaskPair(0x2400FFF0, 0x03FF0000), // ADDIU    T1, T1, 0xFFF0          ADDIU    __, __, 0xFFF0
            new MaskPair(0xBC010000, 0x03E00000), // CACHE    (D), T0, 0x0000         CACHE    (D), __, 0x0000
            new MaskPair(0x0000002B, 0x03FFF800), // SLTU     AT, T0, T1              SLTU     __, __, __
            new MaskPair(0x1400FFFD, 0x03E00000), // BNE      R0, 0xFFFFFFF4(AT)      BNE      R0, 0xFFFFFFF4(__)
            new MaskPair(0x24000010, 0x03FF0000), // ADDIU    T0, T0, 0x0010          ADDIU    __, __, 0x0010
            new MaskPair(0x03E00008, 0x00000000), // JR       RA                      JR       RA
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
        };

        static readonly MaskPair[] OsInvalDCache = new MaskPair[]
        {
            new MaskPair(0x00000023, 0x03FFF800), // SUBU     T0, T0, T2              SUBU     __, __, __
            new MaskPair(0xBC150000, 0x03E00000), // CACHE    (D, CacheBarrier), T0, 0x0000 CACHE    (D, CacheBarrier), __, 0x0000
            new MaskPair(0x0000002B, 0x03FFF800), // SLTU     AT, T0, T1              SLTU     __, __, __
            new MaskPair(0x1000000E, 0x03E00000), // BEQ      R0, 0x38(AT)            BEQ      R0, 0x38(__)
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0x24000010, 0x03FF0000), // ADDIU    T0, T0, 0x0010          ADDIU    __, __, 0x0010
            new MaskPair(0x3000000F, 0x03FF0000), // ANDI     T2, T1, 0x000F          ANDI     __, __, 0x000F
            new MaskPair(0x10000006, 0x03E00000), // BEQ      R0, 0x18(T2)            BEQ      R0, 0x18(__)
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0x00000023, 0x03FFF800), // SUBU     T1, T1, T2              SUBU     __, __, __
            new MaskPair(0xBC150010, 0x03E00000), // CACHE    (D, CacheBarrier), T1, 0x0040 CACHE    (D, CacheBarrier), __, 0x0040
            new MaskPair(0x0000002B, 0x03FFF800), // SLTU     AT, T1, T0              SLTU     __, __, __
            new MaskPair(0x14000005, 0x03E00000), // BNE      R0, 0x14(AT)            BNE      R0, 0x14(__)
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0xBC110000, 0x03E00000), // CACHE    (D, IHitInvalidate), T0, 0x0000 CACHE    (D, IHitInvalidate), __, 0x0000
            new MaskPair(0x0000002B, 0x03FFF800), // SLTU     AT, T0, T1              SLTU     __, __, __
            new MaskPair(0x1400FFFD, 0x03E00000), // BNE      R0, 0xFFFFFFF4(AT)      BNE      R0, 0xFFFFFFF4(__)
            new MaskPair(0x24000010, 0x03FF0000), // ADDIU    T0, T0, 0x0010          ADDIU    __, __, 0x0010
            new MaskPair(0x03E00008, 0x00000000), // JR       RA                      JR       RA
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
            new MaskPair(0x3C008000, 0x001F0000), // LUI      T0, 0x8000              LUI      __, 0x8000
            new MaskPair(0x00000021, 0x03FFF800), // ADDU     T1, T0, T3              ADDU     __, __, __
            new MaskPair(0x2400FFF0, 0x03FF0000), // ADDIU    T1, T1, 0xFFF0          ADDIU    __, __, 0xFFF0
            new MaskPair(0xBC010000, 0x03E00000), // CACHE    (D), T0, 0x0000         CACHE    (D), __, 0x0000
            new MaskPair(0x0000002B, 0x03FFF800), // SLTU     AT, T0, T1              SLTU     __, __, __
            new MaskPair(0x1400FFFD, 0x03E00000), // BNE      R0, 0xFFFFFFF4(AT)      BNE      R0, 0xFFFFFFF4(__)
            new MaskPair(0x24000010, 0x03FF0000), // ADDIU    T0, T0, 0x0010          ADDIU    __, __, 0x0010
            new MaskPair(0x03E00008, 0x00000000), // JR       RA                      JR       RA
            new MaskPair(0x00000000, 0x00000000), // NOP                              NOP
        };

        static readonly MaskPair[] GPRSetup = new MaskPair[]
        {
            new MaskPair(0x3c1c0000, 0x0000ffff), // LUI GP, 0x____
            new MaskPair(0x03E00008, 0x00000000), // JR RA
            new MaskPair(0x279c0000, 0x0000ffff), // ADDIU GP, GP, ____
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
            var indices = IndicesOf(mem, data);
            return FindAllJumpsTo(mem, indices);
        }

        static SortedSet<int> FindAllJumpsTo(uint[] mem, MaskPair[] data)
        {
            var indices = IndicesOf(mem, data);
            return FindAllJumpsTo(mem, indices);
        }

        static int CountJumps(uint[] mem, int regionStart, int regionEnd)
        {
            HashSet<uint> jumps = new HashSet<uint>();
            for (int i = regionStart; i <= regionEnd; i++)
            {
                var inst = Decompiler.Decode(mem[i]);
                if (inst.cmd == Cmd.JAL)
                {
                    jumps.Add(inst.jump.Value);
                }
            }

            return jumps.Count();
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

        static (uint, SortedSet<uint>) GetThirdArgumentToJALAndCheckWordStore(uint gp, uint[] mem, uint off)
        {
            uint vaddr = 0x80000000 | (off << 2);
            Interpreter interpreter = new Interpreter(mem);
            const uint InstructionsToInterpretCount = 20;
            const uint BytesToInterpretCount = InstructionsToInterpretCount << 2;
            interpreter.pc = vaddr - BytesToInterpretCount;
            interpreter.gpr[(int)Register.GP] = (int) gp;

            Instruction? inst;

            SortedSet<uint> wordsStored = new SortedSet<uint>();
            for (int i = 0; i < InstructionsToInterpretCount + 2 /*JAL + delay slot*/; i++)
            {
                inst = interpreter.GetInstruction();
                if (inst.HasValue)
                {
                    interpreter.Execute(inst.Value);
                    if (inst.Value.cmd == Cmd.SW)
                    {
                        uint wordStored = (uint)interpreter.gpr[(int)inst.Value.rt.Value];
                        if (0 != wordStored)
                            wordsStored.Add(wordStored);
                    }
                }
            }

            uint a2 = (uint)interpreter.gpr[(int)Register.A2];
            return (a2, wordsStored);
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
            var disableOff = new List<int>();
            foreach (int off in IndicesOf(mem, OsDisableInt))
            {
                disableOff.Add(off);
                // sometimes there is a bit of a prologue before
                // TODO: Verify there are no tiny function in [off-4, off] area
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

            var writebackDCacheOff = new List<int>();
            foreach (int off in IndicesOf(mem, OsWritebackDCache))
            {
                writebackDCacheOff.Add(off - 0xd);
            }
            SortedSet<int> osWritebackDCacheJumps = FindAllJumpsTo(mem, writebackDCacheOff);

            var invalOff = new List<int>();
            foreach (int off in IndicesOf(mem, OsInvalDCache))
            {
                // sometimes there is an extra NOP inserted
                invalOff.Add(off - 0xe);
                invalOff.Add(off - 0xf);
            }
            SortedSet<int> osInvalDCacheJumps = FindAllJumpsTo(mem, invalOff);

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

                    int prologAt = FindProlog(mem, regionStart, 0x20);
                    for (int i = 0; i < 5; i++)
                        osSiRawStartDmas.Add(prologAt - i);
                }
                catch (Exception) { }
            }

            SortedSet<int> osGetTimeJumps = FindAllJumpsTo(mem, osGetTimes);
            SortedSet<int> osSiRawStartDmaJumps = FindAllJumpsTo(mem, osSiRawStartDmas);

            // Discover all osContInit, we do not need the functions themselves but __osContPifRam passed to __osSiRawStartDma
            // We know that 'osContInit' calls to 'osGetTime' and '__osSiRawStartDma' 2 times
            List<int> osContInts = new List<int>();
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

                    int prologAt = FindProlog(mem, regionStart, 0x20);
                    for (int i = 0; i < 5; i++)
                        osContInts.Add(prologAt - i);
                }
                catch (Exception) { }
            }

            var gprSetups = IndicesOf(mem, GPRSetup);
            uint gp = 0;
            if (gprSetups.Count != 0)
            {
                uint gprOff = (uint) gprSetups[0];
                uint gpHi = mem[gprOff] & 0xffff;
                short gpLo = (short) (mem[gprOff + 2] & 0xffff);
                gp = (gpHi << 16) + (uint) gpLo;
            }

            SortedSet<int> osContIntJumps = FindAllJumpsTo(mem, osContInts);
            foreach (int osContIntJump in osContIntJumps) 
            {
                try
                {
                    (var status, var wordStores) = GetThirdArgumentToJALAndCheckWordStore(gp, mem, (uint) osContIntJump);
                    if (wordStores.Count < 2)
                        continue;

                    if (!wordStores.Contains(status))
                        continue;
                    
                    wordStores.Remove(status);
                    uint cont = 0;
                    foreach (var stored in wordStores)
                    {
                        if (cont != 0)
                        {
                            long dist0 = Math.Abs(status - stored);
                            long dist1 = Math.Abs(status - cont);
                            if (dist0 < dist1)
                                cont = stored;
                        }
                        else
                        {
                            cont = stored;
                        }
                    }

                    int regionEnd = osContIntJump;
                    int regionLength = 20;
                    int regionStart = regionEnd - regionLength;
                    var interpretedSegment = new ArraySegment<uint>(mem, regionStart, regionLength);

                    interpretedInstructionsOffset = regionStart << 2;
                    interpretedInstructions = new byte[regionLength << 2];
                    var interpretedInstructionsIdx = 0;
                    foreach (uint num in interpretedSegment)
                    {
                        Array.Copy(BitConverter.GetBytes(num), 0, interpretedInstructions, interpretedInstructionsIdx, 4);
                        interpretedInstructionsIdx += 4;
                    }

                    gControllerPads = (int)cont;
                    return;
                }
                catch { }
            }
        }
    }
}

/*
 */