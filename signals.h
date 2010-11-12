#ifndef NJK_SIGNALS_H_
#define NJK_SIGNALS_H_ 1
void hook_signal(int signum, void (*fn)(int), int flags);
void disable_signal(int signum);
#endif

