#include <idc.idc>

#define POPA 0x53

static main() {
    auto addr, seg;
    addr = BeginEA();   //Obtain the entry point address
    seg = SegName(addr);
    while (addr != BADADDR && SegName(addr) == seg) {
        if (Byte(addr) == POPA) {
        //    Warning("%x\n",addr);
            RunTo(addr);
            GetDebuggerEvent(WFNE_SUSP, −1);
            Warning("Program is unpacked!");
            TakeMemorySnapshot(1);
            return;
        }
        addr = FindCode(addr, SEARCH_NEXT | SEARCH_DOWN);
    }
    Warning("Failed to locate popa!");
}

