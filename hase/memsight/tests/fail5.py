
def start():
	return 0x400526

def end():
	return [0x400558]

def avoid():
	return [0x400571, 0x400572]

def do_start(state):
	params = {}
	params['esi'] = state.regs.esi
	params['edi'] = state.regs.edi
	return params

def do_end(state, params, pg):

	expected_sol = [0, 1]
	o = state.se.Concat(params['edi'], params['esi'])
	sol = state.se.any_n_int(o, 5)
	import ctypes
	esi = []
	edi = []
	for k in range(len(sol)):
		edi.append(ctypes.c_int((sol[k] & (0xFFFFFFFF << 32)) >> 32).value)
		esi.append(ctypes.c_int(sol[k] & 0xFFFFFFFF).value)
		assert edi[-1] == esi[-1]

	assert set(edi) == set(expected_sol)
	assert set(esi) == set(expected_sol)
	print(("EDI: " + str(edi)))
	print(("ESI: " + str(esi)))
