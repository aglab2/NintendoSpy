using LiveSplit.ComponentUtil;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Threading;

namespace NintendoSpy.Readers
{
    sealed public class EmulatorReader : IControllerReader
    {
        enum State
        {
            INIT,
            RUNNING,
            INVALIDATED,
        };

        public event StateEventHandler ControllerStateChanged;
        public event EventHandler ControllerDisconnected;

        const double TIMER_MS = 30;
        State state;
        State _state
        { 
            get{ return state; } 
            set{ if (value != State.RUNNING && state != value) _lastRunningTime = DateTime.Now; state = value; }
        }

        DateTime _lastScanTime;
        DateTime _lastRunningTime = DateTime.Now;
        DispatcherTimer _timer;
        Process _process;
        IntPtr _controllerPadsPtr;
        int _interpretedInstructionsOffset;
        IntPtr _interpretedInstructionsPtr;
        byte[] _interpretedInstructions;
        int _animFrame = 0;
        int _loadingProgress = 0;

        static readonly string[] BUTTONS = {
            "cright", "cleft", "cdown", "cup", "r", "l", null, null,
            "right", "left", "down", "up", "start", "z", "b", "a",
        };

        static unsafe bool ByteArrayCompare(byte[] data1, byte[] data2)
        {
            if (data1 == data2)
                return true;
            if (data1.Length != data2.Length)
                return false;

            fixed (byte* bytes1 = data1, bytes2 = data2)
            {
                int len = data1.Length;
                int rem = len % (sizeof(long) * 16);
                long* b1 = (long*)bytes1;
                long* b2 = (long*)bytes2;
                long* e1 = (long*)(bytes1 + len - rem);

                while (b1 < e1)
                {
                    if (*(b1) != *(b2) || *(b1 + 1) != *(b2 + 1) ||
                        *(b1 + 2) != *(b2 + 2) || *(b1 + 3) != *(b2 + 3) ||
                        *(b1 + 4) != *(b2 + 4) || *(b1 + 5) != *(b2 + 5) ||
                        *(b1 + 6) != *(b2 + 6) || *(b1 + 7) != *(b2 + 7) ||
                        *(b1 + 8) != *(b2 + 8) || *(b1 + 9) != *(b2 + 9) ||
                        *(b1 + 10) != *(b2 + 10) || *(b1 + 11) != *(b2 + 11) ||
                        *(b1 + 12) != *(b2 + 12) || *(b1 + 13) != *(b2 + 13) ||
                        *(b1 + 14) != *(b2 + 14) || *(b1 + 15) != *(b2 + 15))
                        return false;
                    b1 += 16;
                    b2 += 16;
                }

                for (int i = 0; i < rem; i++)
                    if (data1[len - 1 - i] != data2[len - 1 - i])
                        return false;

                return true;
            }
        }

        void Scan()
        {
            _lastScanTime = DateTime.Now;
            try
            {
                _loadingProgress = 0;
                List<int> ramPtrBaseSuggestions = new List<int>();

                var name = _process.ProcessName.ToLower();

                if (name.Contains("project64"))
                {
                    DeepPointer[] ramPtrBaseSuggestionsDPtrs = { 
                        new DeepPointer("Project64.exe", 0xD6A1C),     //1.6
                        new DeepPointer("RSP 1.7.dll", 0x4C054), 
                        new DeepPointer("RSP 1.7.dll", 0x44B5C),        //2.3.2; 2.4
                    };

                    // Time to generate some addesses for magic check
                    foreach (DeepPointer ramSuggestionPtr in ramPtrBaseSuggestionsDPtrs)
                    {
                        int ptr = -1;
                        try
                        {
                            ptr = ramSuggestionPtr.Deref<int>(_process);
                            ramPtrBaseSuggestions.Add(ptr);
                        }
                        catch (Exception)
                        {
                            continue;
                        }
                    }
                }

                if (name.Contains("mupen"))
                {
                    Dictionary<string, int> mupenRAMSuggestions = new Dictionary<string, int>
                    {
                        { "mupen64-rerecording", 0x008EBA80 },
                        { "mupen64-pucrash", 0x00912300 },
                        { "mupen64_lua", 0x00888F60 },
                        { "mupen64-wiivc", 0x00901920 },
                        { "mupen64-RTZ", 0x00901920 },
                        { "mupen64-rrv8-avisplit", 0x008ECBB0 },
                        { "mupen64-rerecording-v2-reset", 0x008ECA90 },
                    };

                    ramPtrBaseSuggestions.Add(mupenRAMSuggestions[name]);
                }

                Dictionary<string, int> offsets = new Dictionary<string, int>
                {
                    { "Project64", 0 },
                    { "Project64d", 0 },
                    { "mupen64-rerecording", 0x20 },
                    { "mupen64-pucrash", 0x20 },
                    { "mupen64_lua", 0x20 },
                    { "mupen64-wiivc", 0x20 },
                    { "mupen64-RTZ", 0x20 },
                    { "mupen64-rrv8-avisplit", 0x20 },
                    { "mupen64-rerecording-v2-reset", 0x20 },
                };

                _loadingProgress++;
                MagicManager mm = new MagicManager(_process, ramPtrBaseSuggestions.ToArray(), offsets[_process.ProcessName], ref _loadingProgress);
                _controllerPadsPtr = new IntPtr(mm.ramPtrBase + mm.controllerPadsOffset);
                _interpretedInstructionsOffset = mm.interpretedInstructionsOffset;
                _interpretedInstructionsPtr = new IntPtr(mm.ramPtrBase + _interpretedInstructionsOffset);
                _interpretedInstructions = mm.interpretedInstructions;

                _state = State.RUNNING;
            }
            catch (Exception)
            {
                _state = State.INVALIDATED;
            }
        }

        void DrawAnimation()
        {
            _animFrame++;

            var outState = new ControllerStateBuilder();
            for (int i = 0; i < _loadingProgress; i++)
            {
                outState.SetButton(BUTTONS[i], true);
            }

            outState.SetAnalog("stick_x", (float) Math.Sin((double)_animFrame / 10.0));
            outState.SetAnalog("stick_y", (float) Math.Cos((double)_animFrame / 10.0));

            ControllerStateChanged?.Invoke(this, outState.Build());
        }

        public EmulatorReader(string spid)
        {
            int pid = int.Parse(spid);
            _process = Process.GetProcessById(pid);
            _timer = new DispatcherTimer();
            _timer.Interval = TimeSpan.FromMilliseconds(TIMER_MS);
            _timer.Tick += Tick;
            _timer.Start();
        }

        void Tick(object sender, EventArgs e)
        {
            if (_process.HasExited)
            {
                ControllerDisconnected?.Invoke(sender, e);
                return;
            }

            if (_state == State.INIT)
            {
                Scan();
            }

            if (_state == State.INVALIDATED)
            {
                var now = DateTime.Now;
                if (now - _lastScanTime > TimeSpan.FromSeconds(1))
                {
                    Scan();
                }

                if (now - _lastRunningTime > TimeSpan.FromSeconds(5))
                {
                    DrawAnimation();
                }
            }

            if (_state != State.RUNNING)
            {
                return;
            }

            // Running...
            try
            {
                byte[] actualInstructions = _process.ReadBytes(_interpretedInstructionsPtr, _interpretedInstructions.Length);
                bool ok = ByteArrayCompare(actualInstructions, _interpretedInstructions);
                if (!ok)
                {
                    throw new ArgumentException("Validation failed!");
                }
            }
            catch (Exception)
            {
                _state = State.INVALIDATED;
                Scan();
                return;
            }

            ushort flags;
            sbyte x;
            sbyte y;
            try
            {
                var value = _process.ReadValue<uint>(_controllerPadsPtr);
                flags = (ushort) (value >> 16);
                x = (sbyte)(value >> 8);
                y = (sbyte)value;
            }
            catch (Exception)
            {
                // this is kind of a weird situation but let's consider this failure temporary...
                return;
            }

            var outState = new ControllerStateBuilder();

            for (int i = 0; i < BUTTONS.Length; ++i)
            {
                if (!(BUTTONS[i] is object)) continue;
                outState.SetButton(BUTTONS[i], 0 != (flags & (1 << i)));
            }

            outState.SetAnalog("stick_x", (float) x / 127.0f);
            outState.SetAnalog("stick_y", (float) y / 127.0f);

            ControllerStateChanged?.Invoke(this, outState.Build());
        }

        public void Finish()
        {
            if (_timer != null)
            {
                _timer.Stop();
                _timer = null;
            }
        }
    }
}
