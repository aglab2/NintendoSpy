using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MIPSInterpreter
{
    public class DecompManager
    {
        public int? interpretedInstructionsOffset;
        public byte[] interpretedInstructions = null;
        public int? gControllerPads = null;

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

        // Vanilla
        static readonly int OsContGetReadData1Offset = 5;
        static readonly uint[] OsContGetReadData1 = new uint[]
        {
            0xAFAE000C, 0x19E00021, 0xAFA00000, 0x8FB9000C, 0x27B80004, 0x8B210000, 0x9B210003, 0xAF010000, 
            0x8B290004, 0x9B290007, 0xAF090004, 0x93AA0006, 0x314B00C0, 0x000B6103
        };

        // MVC
        static readonly int OsContGetReadData2Offset = 6;
        static readonly uint[] OsContGetReadData2 = new uint[]
        {
            0x19C0001A, 0x00001825, 0x27A60004, 0x88410000, 0x98410003, 0xACC10000, 0x88580004, 0x98580007,
            0xACD80004, 0x93B90006, 0x332800C0, 0x00084903, 0x312A00FF, 0x15400007, 0xA0890004, 0x97AB0008,
            0xA48B0000, 0x83AC000A, 0xA08C0002, 0x83AD000B, 0xA08D0003, 0x90AE0000, 0x24630001, 0x24420008,
            0x006E082A, 0x1420FFE9, 0x24840006, 0x03E00008, 0x27BD0010
        };

        // WSA
        static readonly int OsContGetReadData3Offset = 6;
        static readonly uint[] OsContGetReadData3 = new uint[]
        {
            0x90620002, 0x94680004, 0x00021103, 0x3042000C, 0x80670006, 0x80660007,
            0x24A50001, 0x14400004, 0xA0820006, 0xA4880000, 0xA0870002, 0xA0860003
        };

        static uint[][] OsContGetReadData = new uint[][]
        {
            OsContGetReadData1, OsContGetReadData2, OsContGetReadData3
        };
        static int[] OsContGetReadDataOffsets = new int[]
        {
            OsContGetReadData1Offset, OsContGetReadData2Offset, OsContGetReadData3Offset
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

        public DecompManager(uint[] mem)
        {
            List<int> osContGetReadDataPositions = new List<int>();
            for (int i = 0; i < OsContGetReadData.Length; i++)
            {
                List<int> positions = IndicesOf(mem, OsContGetReadData[i]);
                foreach (int pos in positions)
                {
                    osContGetReadDataPositions.Add(pos - OsContGetReadDataOffsets[i]);
                }
            }

            if (osContGetReadDataPositions.Count() == 0)
                throw new ArgumentException("Failed to find osContGetReadData!");

            foreach (int osContGetReadDataPos in osContGetReadDataPositions)
            {
                Instruction jmpInst = new Instruction
                {
                    cmd = Cmd.JAL,
                    jump = (uint)(4 * osContGetReadDataPos)
                };
                uint jmpInstVal = Converter.ToUInt(jmpInst);
                var osContGetReadDataJmpOffsets = FindAll(mem, jmpInstVal);

                foreach (uint osContGetReadDataJmpOffset in osContGetReadDataJmpOffsets)
                {
                    try
                    {
                        uint osContGetReadDataJmpVAddr = 0x80000000 | (osContGetReadDataJmpOffset << 2);
                        Interpreter interpreter = new Interpreter(mem);
                        uint instructionsToInterpretCount = 16;
                        uint bytesToInterpretCount = instructionsToInterpretCount << 2;
                        interpreter.pc = osContGetReadDataJmpVAddr - bytesToInterpretCount;

                        Instruction? inst;
                        for (int i = 0; i < instructionsToInterpretCount + 2 /*JAL + delay slot*/; i++)
                        {
                            inst = interpreter.GetInstruction();
                            if (inst.HasValue)
                                interpreter.Execute(inst.Value);
                        }

                        int addr = interpreter.gpr[(int)Register.A0];
                        if (IsVAddr((uint)addr))
                        {
                            var interpretedInstructionsStart = osContGetReadDataJmpOffset - instructionsToInterpretCount;
                            interpretedInstructionsOffset = (int) (interpretedInstructionsStart << 2);
                            var interpetedSegment = new ArraySegment<uint>(mem, (int)interpretedInstructionsStart, (int)instructionsToInterpretCount);

                            interpretedInstructions = new byte[instructionsToInterpretCount << 2];
                            var interpretedInstructionsIdx = 0;
                            foreach (uint num in interpetedSegment)
                            {
                                Array.Copy(BitConverter.GetBytes(num), 0, interpretedInstructions, interpretedInstructionsIdx, 4);
                                interpretedInstructionsIdx += 4;
                            }

                            gControllerPads = addr;
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Exception happened when parsing PC 0x{osContGetReadDataJmpOffset:X}: {ex}");
                    }
                }
            }
        }
    }
}
