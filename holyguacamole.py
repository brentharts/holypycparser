#!/usr/bin/env python3
# HolyGuacamole : Brent Hartshorn - Aug 20, 2024

import os, sys, subprocess, json
import holypycparser as hpp
import pycparser

tests = [
'''
`0`register a0,a1,a2,a3,a4,a5,a6,a8`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
`register a0,a1,a2,a3,a4,a5,a6,a8`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',


'''
`0
`register a0,a1,a2,a3,a4,a5,a6,a8
`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
// thread
`0
// registers
`a0,a1,a2,a3,a4,a5,a6,a8
`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
`0`a0,a1,a2,a3,a4,a5,a6,a8`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

## threads
'''
`0`a0,a1,a2,a3,a4,a5,a6,a8`U0 ThreadA(I32 x, I32 y) {
	if (x < y) return -1;
	return x + y;
}


`1`s0,s1,s2,s3,s4,s5,s6,s8`U0 ThreadB(I32 x, I32 y) {
	if (x < y) return -1;
	return x + y;
}
''',


]

def parse_holyg(ln):
	ln = ln[ : ln.rindex('`') ].strip()
	thread_id = -1
	regs = {}
	for i, a in enumerate(ln.split('`')):
		if ',' in a:
			for reg in a.split(','):
				reg = reg.strip()
				if reg.startswith('register'):
					reg = reg.split()[-1]
				if reg.startswith('a'):
					regs[ reg ] = reg.replace('a', 's')
				elif reg.startswith('s'):
					regs[ reg ] = reg.replace('s', 'a')
		elif a.strip().isdigit():
			thread_id = int(a.strip())

	return (thread_id,regs)

def c2asm( c, reg_replace_map, spawn_funcs, opt=0, strip_backticks=True ):
	if type(c) is list: c = '\n'.join(c)
	if strip_backticks:
		a = []
		prev = None
		for ln in c.splitlines():
			if ln.startswith('`'):
				assert prev.startswith('//JSON//')
				finfo = json.loads( prev[ len('//JSON//') : ] )
				print(finfo)
				t,r = parse_holyg(ln)
				reg_replace_map[finfo['name']] = r
				if t >= 0:
					finfo['thread'] = t
					spawn_funcs.append(finfo)
				ln = ln.split('`')[-1]

			a.append(ln)
			prev = ln
		c = '\n'.join(a)

	tmp = '/tmp/c2asm.c'
	open(tmp, 'wb').write(c.encode('utf-8'))
	if not opt: opt = '-O0'
	else: opt = '-O%s' % opt
	asm = '/tmp/c2asm.S'
	cmd = [
		'riscv64-unknown-elf-gcc', '-mcmodel=medany', '-fomit-frame-pointer', '-ffunction-sections',
		'-ffreestanding', '-nostdlib', '-nostartfiles', '-nodefaultlibs', '-fno-tree-loop-distribute-patterns', 
		'-fno-optimize-register-move', '-fno-sched-pressure', '-fno-sched-interblock',
		'-ffixed-t0', '-ffixed-t1', '-ffixed-t2', '-ffixed-t3', '-ffixed-t4', '-ffixed-t5', '-ffixed-t6',
		opt, 
		#'-g', 
		'-S', '-o', asm, tmp
	]
	print(cmd)
	subprocess.check_call(cmd)
	return open('/tmp/c2asm.S', 'rb').read().decode('utf-8')

def asm2asm(data, func_reg_replace={}, reg_replace={}, debug=False, skip_calls=False):
	#data = open(path,'rb').read().decode('utf-8')
	if debug: print_asm(data)
	sects = {}
	sect = {}
	label = None
	out = []
	funcs = {}
	func = None
	for ln in data.splitlines():
		if ln.strip().startswith('.'):
			out.append(ln)
			continue
		if ln.strip().startswith('#'): continue
		a = parse_asm(ln)
		if 'label' in a:
			label = a['label']
			sect = {}
			sects[label] = sect
			func = {'lines':[],'ast':[], 'reps':[]}
			funcs[label] = func
			out.append(ln)
			continue

		if 'inst' in a and a['inst']=='call' and skip_calls:
			continue

		if func:
			func['lines'].append(ln)
			func['ast'].append(a)

		if 'regs' in a:
			for b in a['regs']:
				if b not in sect: sect[b] = {'count':0,'asm':[]}

				sect[b]['count'] += 1
				sect[b]['asm'].append('%s :: %s' % (a['inst'],a['ops']))

				if label in func_reg_replace and b in func_reg_replace[label]:
					c = func_reg_replace[label][b]
					ln = ln.replace(b, c)
					reps = func['reps']
					if c not in reps: reps.append(c)
				elif b in reg_replace:
					ln = ln.replace(b, reg_replace[b])

		out.append(ln)

	for fname in funcs:
		for a in funcs[fname]['ast']:
			if 'regs' in a:
				for b in a['regs']:
					if b in funcs[fname]['reps']:
						print(fname)
						print('\n'.join(funcs[fname]['lines']))
						print(func_reg_replace[fname])
						raise SyntaxError('reg replace error: %s %s' % (a,b))

	if debug:
		for ln in out:
			if not ln.strip().startswith('.'):
				print(ln)

	return '\n'.join(out)

def parse_asm(ln, debug=False):
	r = {}
	if ln.strip().startswith('.'):
		r['data'] = ln
		return r
	elif ln.strip().startswith('#'):
		r['comment'] = ln.strip()
		return r
	if debug: print(ln)
	a = ln.strip().split()
	ops = None
	if len(a)==1:
		if a[0].endswith(':'):
			label = a[0][:-1]
			r['label'] = label
		else:
			r['inst']  = a[0]
		return r
	elif len(a)==2:
		inst, ops = a
	else:
		raise RuntimeError(ln)
	if not ops:
		return r

	r['inst'] = inst
	r['ops']  = ops
	r['regs'] = []
	vis = []
	for b in ops.split(','):
		index = None
		if '(' in b:
			index = b.split('(')[0]
			b = b.split('(')[-1][:-1]

		if b in REGS:
			if b not in r['regs']:
				r['regs'].append(b)

			if b in reg_colors:
				b = '\033[%sm%s\033[0m' % (reg_colors[b], b)
			elif b.startswith('s'):
				if b in S_COLORS:
					COLOR_S = '48;5;%s' % S_COLORS[b]
				else:
					COLOR_S = '30;43'
				b = '\033[%sm %s \033[0m' % (COLOR_S, b)
			elif b.startswith('a'):
				if b in A_COLORS:
					COLOR_A = '48;5;%s' % A_COLORS[b]
				else:
					COLOR_A = '30;44'
				b = '\033[%sm %s \033[0m' % (COLOR_A, b)
			elif b.startswith('t'):
				#b = '\033[38;5;%sm %s \033[0m' % (T_COLORS[b], b)  #fg color
				b = '\033[38;5;0;48;5;%sm %s \033[0m' % (T_COLORS[b], b)

		if index is not None:
			vis.append('%s[%s]' %(b,index))
		else:
			vis.append(b)

	vis = tuple(vis)
	if inst in ('sret', 'sbreak'):
		r['vis'] = 'system< %s >' % inst
	elif inst in ('call', 'tail'):
		r['vis'] = '%s(...)' % ops
	elif inst == 'ble':
		r['vis'] = 'if %s <= %s: goto %s' % vis
	elif inst.startswith('sext.'):  ## sign extend
		if inst.endswith('.w'):  ## 32bit word to 64bit
			r['vis'] = '%s =(i64*)%s' % vis
	else:
		map = {'add':'+', 'div':'/',  'sll' : '<<', 'slr' : '>>', 
			'l':'<-', 's':'->', 'neg':'-', 'rem':'%', 'mul':'*',
			'mv':'◀═┅┅',  ## atomic copy from reg to reg
			'j':'goto',
		}
		for tag in map:
			if inst.startswith(tag):
				if len(vis)==1:
					x = vis[0]
					r['vis'] = '%s %s' % (map[tag], x)
				elif len(vis)==2:
					x,y = vis
					if inst.startswith('neg'):
						r['vis'] = '%s = %s%s' % (x, map[tag], y)
					else:
						r['vis'] = '%s %s %s' % (x, map[tag], y)
				else:
					x,y,z = vis
					r['vis'] = '%s = %s %s %s' % (x, y, map[tag], z)
				break

	if 'vis' in r:
		r['vis'] += '\t\t\t %s : %s' %(inst, ops)
		if inst in asm_help:
			r['vis'] += '\t\t\t : %s' % asm_help[inst] 

	return r


def print_asm(asm, *labels):
	if asm.startswith('/') and len(asm) < 128:
		if os.path.isfile(asm): asm = open(asm,'rb').read().decode('utf-8')
	lab = None
	for idx, ln in enumerate(asm.splitlines()):
		#print(ln)
		a = parse_asm(ln)
		if 'label' in a:
			lab = a['label']
		if 'data' in a: continue
		if labels:
			if lab in labels:
				if 'vis' in a: print(a['vis'])
				else: print(a)
		else:
			if 'vis' in a: print(a['vis'])
			else: print(a)

REGS = ['x%s' % i for i in range(32)]
REGS += [
	'zero',
	'ra',  ## return addr
	'sp',  ## stack pointer
	'gp',  ## global pointer
	'tp',  ## thread pointer
	't0', 't1', 't2',
	's0', 'fp',  ## s0 is sometimes fp
	's1'   ## saved reg1
] + ['a%s' % i for i in range(8)] + ['s%s' % i for i in range(2,12)] + ['t%s' % i for i in range(3,7)]
print('RISC-V registers:',REGS)

S_COLORS = { 's0': 22, 's1': 28, 's2': 64, 's3': 34, 's4': 70, 's5': 40, 's6': 76, 's7': 46, 's8': 47, 's9': 48}
A_COLORS = {'a0': 19,'a1': 20, 'a2': 21, 'a3': 57, 'a4': 56, 'a5': 92, 'a6': 93, 'a7': 129, 'a8': 165, 'a9': 201}
T_COLORS = {'t0' : 226,'t1' : 190,'t2' : 227,'t3' : 191,'t4' : 228,'t5' : 192,'t6' : 229}
reg_colors = { 'tp' : '31', 'sp' : '31', 'gp' : '31', 'ra' : '31', 'zero' : '31' }


asm_help = {
	'lw' : 'load word',
	'sw' : 'store word',
	'li' : 'load value',
	'sext.w' : 'convert i32 to i64',
	'mulw' : 'multiply word',
	'subw' : 'subtract word',
	'addw' : 'add word',
}


def asm2o(s, name='asm2o'):
	s += '\n'
	asm = '/tmp/asm2o.s'
	open(asm,'wb').write(s.encode('utf-8'))
	o = '/tmp/%s.o' % name
	cmd = [ 'riscv64-unknown-elf-as', 
		#'-march=rv64g', '-mabi=lp64', 
		'-g', '-o',o, asm]
	print(cmd)
	subprocess.check_call(cmd)
	return o

LIBC = r'''
void *memset(void *s, I32 c, U64 n){
	U8 *p = s;
	while (n--) *p++ = (U8)c;
	return s;
}
void *memcpy(void *dest, const void *src, U64 n){
	U8 *d = dest;
	const U8 *s = src;
	while (n--) *d++ = *s++;
	return dest;
}
#define VRAM ((volatile U8 *)0x50000000)
void putpixel(I32 x, I32 y, U8 c){
	VRAM[y*320 + x] = c;
}
'''


LINKER_SCRIPT = '''
ENTRY(_start)
MEMORY {} /* default */
. = 0x80000000;
SECTIONS {}
'''

ARCH = '''
#define MACHINE_BITS 64
#define BITS_PER_LONG MACHINE_BITS
#define bool _Bool
#define true 1
#define false 0
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long U64;
typedef signed char I8;
typedef signed short I16;
typedef signed int I32;
typedef signed long I64;
typedef U64 size_t;
'''

CPU_H = 'struct cpu {%s} __attribute__((packed));' % '\n'.join(['U64 x%s;' % i for i in range(32)]+['U64 pc;'])

PROC_H = '''
#define PROC_NAME_MAXLEN 64
#define PROC_TOTAL_COUNT 16

enum proc_state {
	PROC_STATE_NONE = 0,
	PROC_STATE_READY,
	PROC_STATE_RUNNING,
};

struct HolyThread {
	enum proc_state state;
	U32 pid;
	U8 name[PROC_NAME_MAXLEN];
	struct cpu cpu;
	U64 hartid;
};
'''


FIRMWARE_MAIN = r'''
extern void trap_entry();
void firmware_main(){
  uart_init();
  kernel_threads_init();
  uart_print("[firmware_main memset proc_list]\n");
  for (int i = %s; i < PROC_TOTAL_COUNT; i++) {
    memset(&__proc_list[i], 0, sizeof(__proc_list[i]));
    __proc_list[i].state = PROC_STATE_NONE;
  }
  active_pid = -1;
  set_timeout(10000); // setup M-mode trap vector
  csrw_mtvec((U64)trap_entry); // enable M-mode timer interrupt  
  csrw_mie(MIE_MTIE);
  csrs_mstatus(MSTAUTS_MIE); // enable MIE in mstatus
  uart_print("[firmware_main waiting...]\n");
  while(1) {
  	uart_putc('<');
  	uart_putc('>');
  }
}
'''

def gen_firmware( spawn_funcs, stack_mb=1 ):
	out = []
	for f in spawn_funcs:
		out.append('extern void %s();' % f['name'])
		out.append('extern void %s();' % f['name'])
		out.append('U8 __stack__%s[%s];' % (f['name'], int(1024*1024*stack_mb) ))

	out += ['void kernel_threads_init(){']
	for p,o in enumerate(spawn_funcs):
		out += [
			'struct HolyThread __proc__%s = {' % o['name'],
			'  .name = "%s",' % o['name'],
			'  .pid = %s,' % (p+0),
			'  .hartid = 0,',  ## cpu core
			'  .state = PROC_STATE_READY,',
			'  .cpu = {',
			'      .pc = (U64)%s,' % o['name'],
			'      .x2 = (U64)__stack__%s,' % o['name'],
			'  }};',
			#'uart_print("[proc_init] proc_list:%s");' % p,
			'__proc_list[%s] = __proc__%s;' % (p, o['name']),
		]
	out.append('}')

	out.append(FIRMWARE_MAIN % len(spawn_funcs))

	return out


TRAP_C = r'''
struct cpu trap_cpu;
U8 trap_stack[1 << 20];
void *trap_stack_top = &trap_stack[sizeof(trap_stack) - 1];
I32 active_pid;
struct HolyThread __proc_list[PROC_NAME_MAXLEN] = {};

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void kernel_trap_handler() {
	U64 mcause = csrr_mcause();
	if (mcause==MCAUSE_INTR_M_TIMER){
		if (active_pid < 0){
			active_pid = 0;
			trap_cpu = __proc_list[0].cpu;
		}
		__proc_list[active_pid].cpu = trap_cpu; // save cpu state for the active process
		__proc_list[active_pid].state = PROC_STATE_READY; // suspend the active process
		for (int ring_index = 1; ring_index <= PROC_TOTAL_COUNT; ring_index++){
			int real_index = (active_pid + ring_index) % PROC_TOTAL_COUNT;
			struct HolyThread *proc = &__proc_list[real_index];
			if (proc->state == PROC_STATE_READY){
				trap_cpu = proc->cpu;
				active_pid = proc->pid;
				break;
			}
		}
		kernel_timeout();
	}
}
'''


TIMER = '''
#define MTIME 0x200bff8
#define MTIMECMP_0 0x2004000
static inline U64 mtime() { return readu64(MTIME); }
static inline U64 mtimecmp_0() { return readu64(MTIMECMP_0); }
static inline U64 set_timeout(U64 timeout) { writeu64(MTIMECMP_0, mtime() + timeout); }
static inline void kernel_timeout(void) { writeu64(MTIMECMP_0, mtime() + 100); }
'''

ARCH_ASM = '''
#define readu8(addr) (*(const U8 *)(addr))
#define readu16(addr) (*(const U16 *)(addr))
#define readu32(addr) (*(const U32 *)(addr))
#define readu64(addr) (*(const U64 *)(addr))
#define writeu8(addr, val) (*(U8 *)(addr) = (val))
#define writeu16(addr, val) (*(U16 *)(addr) = (val))
#define writeu32(addr, val) (*(U32 *)(addr) = (val))
#define writeu64(addr, val) (*(U64 *)(addr) = (val))

//GOTCHA::BREAKS-ASM-PARSER//static inline void csrw_mtvec(const volatile u64 val) { asm volatile("csrw mtvec, %0" :: "r"(val)); } // note the space
static inline void csrw_mtvec(const volatile U64 val) { asm volatile("csrw mtvec,%0" :: "r"(val)); }
static inline void csrw_mie(const volatile U64 val) { asm volatile("csrw mie,%0" :: "r"(val)); }
static inline void csrs_mstatus(const volatile U64 val) { asm volatile("csrs mstatus,%0" :: "r"(val)); }
static inline U64 csrr_mcause(){
  volatile U64 val;
  asm volatile("csrr %0,mcause" : "=r"(val) :);
  return val;
}
'''

INTERRUPTS = '''
#define MSTAUTS_MIE (0x1L << 3)
#define MIE_MTIE (0x1L << 7)
#define MIE_MEIE (0x1L << 11)
#define MCAUSE_INTR_M_TIMER ((0x1L << (MACHINE_BITS - 1)) | 7)
#define MCAUSE_INTR_M_EXTER ((0x1L << (MACHINE_BITS - 1)) | 11)
#define MCAUSE_INNER_M_ILLEAGEL_INSTRUCTION (0x2L)
'''

REMAP_TRAP = {
	'a0' : 't0',  ## t0 is x5
	'a1' : 't1',
	'a2' : 't2',
	'a3' : 't3',
	'a4' : 't4',
	'a5' : 't5',
	'a6' : 't6',
	'a7' : 'gp',
}

def gen_trap_s( ra=True ):
	s = '''
.equ REGSZ, 8
.global trap_entry
trap_entry:
	csrrw sp, mscratch, sp
	la tp, trap_cpu
	#sd ra, (1 * REGSZ)(tp)
	## save program counter
	csrr t0, mepc
	sd t0, (32 * REGSZ)(tp)
	## call trap_handler C function
	la t0, trap_stack_top
	ld sp, 0(t0)
	call kernel_trap_handler
	## restore program counter
	ld t0, (32 * REGSZ)(tp)
	csrw mepc, t0
	csrr sp, mscratch
	#ld ra, (1 * REGSZ)(tp)
	mret
	'''
	if ra: s = s.replace('#sd', 'sd').replace('#ld','ld')
	return s


#.attribute arch, "rv64g"
START_S = '''
.section .text
.global _start
_start:
	bne a0, x0, _start # loop if hartid is not 0
	li sp, 0x80200000 # setup stack pointer
	j firmware_main # jump to c entry
'''

def clean_asm(asm):
	a = []
	for ln in asm.splitlines():
		if ln.strip().startswith(('.file', '.option', '.attribute')): continue
		a.append(ln)
	return '\n'.join(a)

NO_UART = '''
#define uart_putc(...)
#define uart_print(...)
#define uart_init(...)
'''

LIB_UART = '''
#define UART_BASE 0x10000000
#define UART_RBR_OFFSET 0  /* In:  Recieve Buffer Register */
#define UART_THR_OFFSET 0  /* Out: Transmitter Holding Register */
#define UART_DLL_OFFSET 0  /* Out: Divisor Latch Low */
#define UART_IER_OFFSET 1  /* I/O: Interrupt Enable Register */
#define UART_DLM_OFFSET 1  /* Out: Divisor Latch High */
#define UART_FCR_OFFSET 2  /* Out: FIFO Control Register */
#define UART_IIR_OFFSET 2  /* I/O: Interrupt Identification Register */
#define UART_LCR_OFFSET 3  /* Out: Line Control Register */
#define UART_MCR_OFFSET 4  /* Out: Modem Control Register */
#define UART_LSR_OFFSET 5  /* In:  Line Status Register */
#define UART_MSR_OFFSET 6  /* In:  Modem Status Register */
#define UART_SCR_OFFSET 7  /* I/O: Scratch Register */
#define UART_MDR1_OFFSET 8 /* I/O:  Mode Register */
#define PLATFORM_UART_INPUT_FREQ 10000000
#define PLATFORM_UART_BAUDRATE 115200
static U8 *uart_base_addr = (U8 *)UART_BASE;
static void set_reg(U32 offset, U32 val){ writeu8(uart_base_addr + offset, val);}
static U32 get_reg(U32 offset){ return readu8(uart_base_addr + offset);}
static void uart_putc(U8 ch){ set_reg(UART_THR_OFFSET, ch);}
static void uart_print(char *str){ while (*str) uart_putc(*str++);}

static inline void uart_init(){
  U16 bdiv = (PLATFORM_UART_INPUT_FREQ + 8 * PLATFORM_UART_BAUDRATE) / (16 * PLATFORM_UART_BAUDRATE);
  set_reg(UART_IER_OFFSET, 0x00); /* Disable all interrupts */
  set_reg(UART_LCR_OFFSET, 0x80); /* Enable DLAB */
  if (bdiv) {
    set_reg(UART_DLL_OFFSET, bdiv & 0xff); /* Set divisor low byte */
    set_reg(UART_DLM_OFFSET, (bdiv >> 8) & 0xff); /* Set divisor high byte */
  }
  set_reg(UART_LCR_OFFSET, 0x03); /* 8 bits, no parity, one stop bit */
  set_reg(UART_FCR_OFFSET, 0x01); /* Enable FIFO */
  set_reg(UART_MCR_OFFSET, 0x00); /* No modem control DTR RTS */
  get_reg(UART_LSR_OFFSET); /* Clear line status */
  get_reg(UART_RBR_OFFSET); /* Read receive buffer */  
  set_reg(UART_SCR_OFFSET, 0x00); /* Set scratchpad */
}
'''

def make(asm, spawn_funcs, use_uart=True):
	a = c2asm(
		ARCH + ARCH_ASM + CPU_H + PROC_H + INTERRUPTS + TIMER + TRAP_C, 
		{},[],
		opt=1
	)
	a = asm2asm(a, reg_replace=REMAP_TRAP )
	print_asm(a)
	trap_handler = asm2o(a, name='trap_handler')

	s = [START_S, gen_trap_s(), clean_asm(asm)]
	o = asm2o('\n'.join(s))

	c = [
		ARCH, LIBC, CPU_H, 
		PROC_H, INTERRUPTS, ARCH_ASM, TIMER,
	]
	if use_uart:
		c.append(LIB_UART)
	else:
		c.append(NO_UART)

	c += [
		'extern I32 active_pid;',
		'extern struct HolyThread __proc_list[PROC_NAME_MAXLEN];',
	] + gen_firmware(spawn_funcs)

	tmpc = '/tmp/make.c'
	open(tmpc,'wb').write('\n'.join(c).encode('utf-8'))

	tmpld = '/tmp/linker.ld'
	open(tmpld,'wb').write(LINKER_SCRIPT.encode('utf-8'))

	elf = '/tmp/test.elf'
	cmd = [
		'riscv64-unknown-elf-gcc', '-mcmodel=medany', '-ffunction-sections',
		'-ffreestanding', '-nostdlib', '-nostartfiles', '-nodefaultlibs',
		'-Wl,--no-relax', 
		'-T',tmpld, 
		'-O0', '-g', '-o', elf, o, trap_handler, tmpc,
	]
	print(cmd)
	subprocess.check_call(cmd)
	if '--run' in sys.argv:
		cmd = 'riscv64-unknown-elf-objcopy -O binary -S %s /tmp/firmware.bin' % elf
		print(cmd)
		subprocess.check_call(cmd.split())
		cmd = 'qemu-system-riscv64 -machine virt -smp 2 -m 2G -serial stdio -bios /tmp/firmware.bin -s -device VGA'
		print(cmd)
		subprocess.check_call(cmd.split())
	return elf


def run_tests():
	for t in tests:
		print(t)
		print('-'*80)
		c = hpp.holyc_to_c( t )
		print(c)
		print('_'*80)
		func_reg_replace = {}
		spawn_funcs = []
		a = c2asm(c, func_reg_replace, spawn_funcs)
		print('c2asm output:', a)
		print('reg_replace_map:', func_reg_replace)
		a = asm2asm(a, func_reg_replace)
		print('asm2asm output:')
		print_asm(a)
		elf = make(a, spawn_funcs)

def build(files):
	a = [open(f,'rb').read().decode('utf-8') for f in files]
	c = hpp.holyc_to_c( a )
	print(c)
	print('_'*80)
	func_reg_replace = {}
	spawn_funcs = []
	a = c2asm(c, func_reg_replace, spawn_funcs)
	print('c2asm output:', a)
	print('reg_replace_map:', func_reg_replace)
	a = asm2asm(a, func_reg_replace)
	print('asm2asm output:')
	print_asm(a)
	elf = make(a, spawn_funcs)
	return elf


if __name__=='__main__':
	files = []
	for arg in sys.argv:
		if arg.endswith(('.c', '.hc', '.HC')):
			files.append(arg)

	if not files:
		run_tests()
	else:
		build(files)
