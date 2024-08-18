#!/usr/bin/env python3
import os, sys, subprocess, json, ctypes, code
import holypycparser
print(holypycparser)

scope = {}

HOLYC = None
def holyc_compile(hc):
	c = holypycparser.holyc_to_c(hc)
	jit = holypycparser.holyjit(c)
	for name in jit:
		f = jit[name]
		if isinstance(f, holypycparser.holywrapper):
			print('new holyc function:', name, f)
			scope[name] = f

TEST = '''
I32 add(I32 y, I32 z){
    return y+z;
}
'''

holyc_compile(TEST)
for arg in sys.argv:
	if arg.endswith(('.HC', '.hc')):
		holyc_compile(arg)

def pymode():
	global HOLYC
	sys.ps1 = 'python>>>'
	sys.ps2 = '... '
	HOLYC = None

HELP0 = '''
SYNTAX FUNCTION

example - start a new function:
	U0 f(){

(a line ending with "{" starts a new function)

example - end function:
	}

(a line with "}" no white space, ends a function)

'''

HELP1 = '''
SYNTAX `SYSTEM COMMAND`

example - print working directory:
	`pwd`

example - loop over output of ls:
	a = `ls`
	for b in a: print(b)

'''

def help():
	print(HELP0)
	print(HELP1)

com = {
	'help'  : help,
	'holyc' : holyc_compile,
	'python': pymode,
	'exit': pymode,

	## TempleOS
	'Dir': lambda : os.system('ls -lh'),
	'DocClear' : lambda : os.system('clear'),
}
console = code.InteractiveConsole(locals=scope)
__runsource = console.runsource
def run(co, filename=None, symbol=None):
	global HOLYC
	if co.startswith('`') and co.endswith('`'):
		co = co[1:-1]
		print("os.system('%s')" % co)
		os.system(co)
	elif co.count('=')==1 and co.count('`')==2 and co.endswith('`'):
		a,b = co.split('=')
		cmd = b[:-1].split('`')[-1]
		out = subprocess.check_output(cmd.split()).decode('utf-8').splitlines()
		exec('%s = %s' %(a, out), scope, scope)
	elif type(HOLYC) is list:
		if co in ('python', 'exit'):
			print('-'*80)
			print('\n'.join(HOLYC))
			print('-'*80)
			pymode()
		else:
			HOLYC.append(co)
			#print(co)
		if co == '}':
			holyc_compile(HOLYC)
			HOLYC = None

	elif co in com:
		com[co]()
	elif co.endswith('{'):
		if HOLYC is None:
			HOLYC = [co]
	elif co in scope:
		print(scope[co])
	else:
		try:
			#__runsource(co)
			exec(co, scope, scope)
		except NameError as err:
			print(type(err).__name__, err)
			if co in os.listdir('/usr/bin/'):
				print('"%s" is in /usr/bin/ you can run it with backticks `%s`' % (co,co))
	return False

sys.ps1 = 'holysh>>>'
sys.ps2 = '... '

console.runsource = run
console.interact(banner="holysh: press Ctrl+D to exit, type help for examples")
