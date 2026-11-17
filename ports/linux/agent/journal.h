#pragma once

// Ship the systemd journal: entries of `priority` (0..7) and more severe go
// into the SDK's log ring. On the very first start the last `backlog` lines
// are shipped too; afterwards the follower continues from the cursor it keeps
// in state_dir. A system without journalctl logs one warning and ships none.
void agent_journal_start(const char* state_dir, int priority, int backlog);
void agent_journal_stop(void);
