// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
    { "backtrace", "Diaplay a backtrace of the stack", mon_backtrace },
    { "time", "Diaplay running time of command", time_cmd },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

int time_cmd(int args, char **argv, struct Trapframe *tf)
{
    if(args <= 1) {
        cprintf("no arg for time cmd!!!\n");
        return 0;
    }
    const char *cmdstr = argv[1];
    uint64_t st = read_tsc();
    if(strcmp(cmdstr, "kerninfo") == 0) {
        mon_kerninfo(args, argv, tf);
    }else if(strcmp(cmdstr, "help") == 0) {
        mon_help(args, argv, tf);
    }else if(strcmp(cmdstr, "backtrace") == 0) {
        mon_backtrace(args, argv, tf);
    }else {
        cprintf("invalid arg for time cmd!!!\n");
        return 0;
    }
    uint64_t ed = read_tsc();
    // cpu cycles
	cprintf("%s cycles: %llu\n", cmdstr, ed - st);
    return 0;
}
// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

// assign a value from uint16_t to char pointed by char *
// by cprintf("%n")
void assign(uint16_t src, char *pdes)
{
    char fmt[300];
    fmt[0] = '"';
    int idx = 1;
    while(--src > 0) {
        fmt[idx++] = ' ';
    }
    fmt[idx++] = '%';
    fmt[idx++] = 'n';
    fmt[idx++] = '"';
    fmt[idx++] = '\0';
    cprintf(fmt, pdes);
}
void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;
	
    // Your code here.

    // given 256 is not enough, so i double it
    char str[256 * 2] = {};
    int nstr = 0;
    
    char *pret_addr = (char *)read_pretaddr();
    uint32_t ret_addr =(uint32_t)(*((uint32_t *)pret_addr));
    
    char *ebp = pret_addr - 4;
    // instruction
    // push %ebp
    assign(0x55, str);
    // mov %esp, %ebp
    assign(0x89, str + 1);
    assign(0xe5, str + 2);
    // call do_overflow
    assign(0xe8, str + 3);
    uint32_t rela_addr =(uint32_t)(&do_overflow) - (uint32_t)(str + 8);
    assign(rela_addr & 0xff, str + 4);
    assign((rela_addr >> 8) & 0xff, str + 5);
    assign((rela_addr >> 16) & 0xff, str + 6);
    assign((rela_addr >> 24) & 0xff, str + 7);
    // change addr to return to overflow_me func
    // mov &overflow_me, %eax
    assign(0xb8, str + 8);
    assign(ret_addr & 0xff, str + 9);
    assign((ret_addr >> 8) & 0xff, str + 10);
    assign((ret_addr >> 16) & 0xff, str + 11);
    assign((ret_addr >> 24) & 0xff, str + 12);
    // mov %eax, 0x4(%ebp)
    assign(0x89, str + 13);
    assign(0x45, str + 14);
    assign(0x04, str + 15);
    // leave
    assign(0xc9, str + 16);
    // ret
    assign(0xc3, str + 17);
    
    // change return addr to return to instruction
    *((uint32_t*)pret_addr) = (uint32_t)(str);
}

void
overflow_me(void)
{
        start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
    uint32_t *ebp = (uint32_t *)read_ebp();
    uint32_t *peip = NULL;
    // only one arg
    uint32_t *parg = NULL;
    
    cprintf("Stack backtrace:\nStack backtrace:\n");
    
    uint32_t END_FLAG = 0x0;
    while(ebp && ebp != (uint32_t *)END_FLAG) {
        peip = ebp + 1;
        parg = peip + 1;
        //printf eip ebp args
        cprintf("eip %08x ebp %08x args %08x %08x %08x %08x %08x\n", *peip, ebp, *parg, *(parg + 1), 
                *(parg + 2), *(parg + 3), *(parg + 4));

        //printf debug info
        struct Eipdebuginfo eipinfo;
        debuginfo_eip(*peip, &eipinfo);
        uint32_t offset = (uint32_t)((*peip) - eipinfo.eip_fn_addr);
        cprintf("    %s:%d: %s+%x\n", eipinfo.eip_file, eipinfo.eip_line, eipinfo.eip_fn_name, offset);

        ebp = (uint32_t *)(*ebp);
    }
    overflow_me();
    cprintf("Backtrace success\n");
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
