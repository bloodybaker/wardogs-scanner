# Scanner 0.7.0: scanning while the game is running

The game no longer blocks or cancels a scan. Read-only checks inventory loaded game/Discord modules and their file hashes/signatures, foreign process handles with game-memory access rights, and private executable memory-region metadata in the game. No memory contents are exported, injected or modified. Access denied remains partial coverage; protection is never bypassed.

Synthetic native fixtures verify a running mock game, a separate process holding VM_READ access, module inventory and memory-region inspection. Real WARDOGS/anti-cheat compatibility and detection of the reported cheat have not been verified. Legitimate overlays, protection and JIT code can produce similar observations; these are manual-review signals, not automatic cheating verdicts. Closed handles, kernel/DMA access and hardware macros can remain invisible.
