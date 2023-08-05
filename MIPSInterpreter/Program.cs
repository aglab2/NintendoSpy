using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MIPSInterpreter
{
    class Program
    {
        static void Analyze(string path)
        {
            uint[] mem;
            {
                byte[] bytes = File.ReadAllBytes(path);
                int size = bytes.Count() / 4;
                mem = new uint[size];
                for (int idx = 0; idx < size; idx++)
                {
                    byte[] dataInt = new byte[4];
                    dataInt[0] = bytes[3 + 4 * idx];
                    dataInt[1] = bytes[2 + 4 * idx];
                    dataInt[2] = bytes[1 + 4 * idx];
                    dataInt[3] = bytes[0 + 4 * idx];
                    mem[idx] = BitConverter.ToUInt32(dataInt, 0);
                }
            }

            DecompManager dm = new DecompManager(mem);
            Console.WriteLine($"{path} osContPifRam={dm.osContPifRam:X}");
        }

        struct CleanseResult
        {
            public MaskPair pair;
            public Instruction inst;
            public Instruction cleanedInst;
        };

        static CleanseResult[] Cleanse(ISet<Register> cleanRegisters, uint[] cmds)
        {
            Cleanser cleanser = new Cleanser(cleanRegisters);

            CleanseResult[] cleanedResults = new CleanseResult[cmds.Length];

            int i = 0;
            foreach (uint cmd in cmds) 
            {
                var inst = Decompiler.Decode(cmd);
                // Console.WriteLine($"origi: {i:X2}: {inst, -32} {cmd:X8}");

                var cmdCheck = Converter.ToUInt(inst);
                if (cmdCheck != cmd)
                {
                    var instBroken = Decompiler.Decode(cmdCheck);
                    throw new ArgumentException("Decompiled instruction does not match compiled cmd");
                }

                (Instruction cleanedInst, uint mask) = cleanser.Clean(inst);
                var cleanedCmd = Converter.ToUInt(cleanedInst);

                if (cleanedInst.rs != inst.rs)
                {
                    cleanedInst.rs = Register.__;
                }
                if (cleanedInst.rt != inst.rt)
                {
                    cleanedInst.rt = Register.__;
                }
                if (cleanedInst.rd != inst.rd)
                {
                    cleanedInst.rd = Register.__;
                }
                // Console.WriteLine($"clean: {i:X2}: {cleanedInst, -32} {cleanedCmd:X8} {mask:X8}");

                cleanedResults[i].pair = new MaskPair(cleanedCmd, mask);
                cleanedResults[i].inst = inst;
                cleanedResults[i].cleanedInst = cleanedInst;

                i++;
            }

            return cleanedResults;
        }

        static readonly uint[] OsDisableInt = new uint[]
        {
            0x40086000, 0x2401FFFE, 0x01014824, 0x40896000, 0x31020001, 0x00000000, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsDisableInt2 = new uint[]
        {
            0x40086000, 0x2401FFFE, 0x01014824, 0x40896000, 0x31020001, 0x8D480000, 0x3108FF00, 0x110B000E
        };

        static readonly uint[] OsDisableInt3 = new uint[]
        {
            0x31EFFF00, 0x400C6000, 0x2401FFFE, 0x01816824, 0x408D6000, 0x31820001, 0x8DCC0000
        };

        static readonly uint[] OsRestoreInt = new uint[]
        {
            0x40086000, 0x01044025, 0x40886000, 0x00000000, 0x00000000, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsRestoreInt2 = new uint[]
        {
            0x400C6000, 0x01846025, 0x408C6000, 0x00000000, 0x00000000, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsWritebackDCache = new uint[]
        {
            0x18A00011, 0x00000000, 0x240B2000, 0x00AB082B, 0x1020000F, 0x00000000, 0x00804025, 0x00854821,
            0x0109082B, 0x10200008, 0x00000000, 0x310A000F, 0x2529FFF0, 0x010A4023, 0xBD190000, 0x0109082B,
            0x1420FFFD, 0x25080010, 0x03E00008, 0x00000000, 0x3C088000, 0x010B4821, 0x2529FFF0, 0xBD010000,
            0x0109082B, 0x1420FFFD, 0x25080010, 0x03E00008, 0x00000000
        };

        static readonly uint[] OsWritebackDCache2 = new uint[]
        {
            0x18A00011, 0x00000000, 0x240F2000, 0x00AF082B, 0x1020000F, 0x00000000, 0x00806025, 0x00856821,
            0x018D082B, 0x10200008, 0x00000000, 0x25ADFFF0, 0x318E000F, 0x018E6023, 0xBD990000, 0x018D082B,
            0x1420FFFD, 0x258C0010, 0x03E00008, 0x00000000, 0x3C0C8000, 0x018F6821, 0x25ADFFF0, 0xBD810000,
            0x018D082B, 0x1420FFFD, 0x258C0010, 0x03E00008, 0x00000000
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

        static readonly uint[] OsInvalDCache2 = new uint[]
        {
            0x18A00020, 0x00000000, 0x240F2000, 0x00AF082B, 0x1020001E, 0x00000000, 0x00806025, 0x00856821,
            0x018D082B, 0x10200017, 0x00000000, 0x25ADFFF0, 0x318E000F, 0x11C00007, 0x00000000, 0x018E6023,
            0xBD950000, 0x018D082B, 0x1020000E, 0x00000000, 0x258C0010, 0x31AE000F, 0x11C00006, 0x00000000,
            0x01AE6823, 0xBDB50010, 0x01AC082B, 0x14200005, 0x00000000, 0xBD910000, 0x018D082B, 0x1420FFFD,
            0x258C0010, 0x03E00008, 0x00000000, 0x3C0C8000, 0x018F6821, 0x25ADFFF0, 0xBD810000, 0x018D082B,
            0x1420FFFD, 0x258C0010, 0x03E00008, 0x00000000, 0x18A00011, 0x00000000, 0x240F4000, 0x00AF082B,
            0x1020000F, 0x00000000, 0x00806025, 0x00856821, 0x018D082B, 0x10200008, 0x00000000, 0x25ADFFE0,
            0x318E001F, 0x018E6023, 0xBD900000, 0x018D082B, 0x1420FFFD, 0x258C0020, 0x03E00008, 0x00000000,
            0x3C0C8000, 0x018F6821, 0x25ADFFE0, 0xBD800000, 0x018D082B, 0x1420FFFD, 0x258C0020, 0x03E00008,
            0x00000000
        };


        static void Main(string[] args)
        {
            var safeRegs = new HashSet<Register> { Register.A0, Register.A1, Register.A2, Register.A3, Register.V0, Register.V1, Register.K0, Register.K1, Register.SP, Register.FP, Register.GP, Register.RA };
            Console.WriteLine("OsWritebackDCache");
            foreach (var result in Cleanse(safeRegs, OsWritebackDCache))
            {
                Console.WriteLine($"new MaskPair({result.pair}), // {result.inst,-32} {result.cleanedInst,-32}");
            }
            Console.WriteLine("OsWritebackDCache2");
            foreach (var result in Cleanse(safeRegs, OsWritebackDCache2))
            {
                Console.WriteLine($"new MaskPair({result.pair}), // {result.inst,-32} {result.cleanedInst,-32}");
            }

            foreach (var dir in Directory.EnumerateFiles("D:\\dumps"))
            {
                Analyze(dir);
            }
        }
    }
}
