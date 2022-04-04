#define _GNU_SOURCE // for REG_RIP

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <ucontext.h>

void on_trap(int sig, siginfo_t *info, void *ucontext) {
  mcontext_t *mc = &(((ucontext_t *)ucontext)->uc_mcontext);
  uintptr_t r_ip = mc->gregs[REG_RIP];
  uintptr_t r_flags = mc->gregs[REG_EFL];
  uint8_t op = ((uint8_t *)r_ip)[0];
  printf("%lx: op=%x ax=%llx zf=%x cf=%x (%lx)\n", r_ip, op, mc->gregs[REG_RAX], (r_flags & 0x40) != 0,
         (r_flags & 0x1) != 0, r_flags);
  if (0 && op == 0xf9) {
    greg_t *r_ip_p = &mc->gregs[REG_RIP];
    (*r_ip_p)++;
    printf("  ip=%lx -> ip=%llx\n", r_ip, *r_ip_p);
  }
}

void callme(void) {
  puts("hello");
  __asm__ volatile("clc");
  __asm__ volatile("sbb %rax,%rax");
  __asm__ volatile("int $0x03");
  __asm__ volatile("stc");
  __asm__ volatile("sbb %rax,%rax");
  __asm__ volatile("int $0x03");
  puts("bye");
}

int main(void) {
  struct sigaction sa;

  // sa.sa_handler = on_trap;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = on_trap;
  sigaction(SIGTRAP, &sa, NULL);
  // signal(SIGTRAP, on_trap);
  callme();
  return 0;
}
