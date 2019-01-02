
def start():
	return 0x4004d6

def end():
	return [0x4004e9]

def avoid():
	return [0x4004f0]

def do_start(state):
	params = {}
	import claripy
	params['f'] = claripy.Reverse(state.memory.load(state.regs.rsp - 12, 4))
	return params

def do_end(state, params, pg=None):
	s = state.se.any_n_int(params['f'], 5)
	assert len(s) == 1
	assert s[0] == 0x0
	assert len(pg.active) == 0
