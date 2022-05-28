# Supporting IDA 7.x. 
from ida_ida import *

start = inf_get_min_ea()
run_to(start)
wait_for_next_event(WFNE_SUSP, -1)
enable_tracing(TRACE_STEP, 1)
code =wait_for_next_event(WFNE_ANY | WFNE_CONT, -1)
while code > 0:
    if get_event_ea() < start: break
    code =wait_for_next_event(WFNE_ANY | WFNE_CONT, -1)
suspend_process()
wait_for_next_event(WFNE_SUSP, -1)
enable_tracing(TRACE_STEP, 0)
create_insn(get_event_ea())
take_memory_snapshot(1)
