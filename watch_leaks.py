
"""
 (c) Andrei Nigmatulin, 2016

 runtime memory detector, x86_64 only

 to detect memory leaks:
 $ gdb -q --batch -ex 'set python print-stack full' -ex 'source watch_leaks.py' -ex 'watch_leaks 30 je_' -p <pid>
"""

import gdb, time, operator
from collections import defaultdict

def get_stacktrace():

	def get_pc_line(frame):
		info = ' 0x%016x' % frame.pc()
		if frame.name():
			frame_name = frame.name()
			try:
				# try to compute the offset relative to the current function
				value = gdb.parse_and_eval(frame.name()).address
				# it can be None even if it is part of the "stack" (C++)
				if value:
					func_start = value
					offset = frame.pc() - func_start
					frame_name += '+' + str(offset)
			except gdb.error:
				pass  # e.g., @plt
			info += ' in {0} ()'.format(frame_name)
			sal = frame.find_sal()
			if sal.symtab:
				file_name = sal.symtab.filename
				file_line = str(sal.line)
				info += ' at {0}:{1}'.format(file_name, file_line)
		return info

	frame_id = 0
	ret = []
	frame = gdb.newest_frame()
	while frame:
		info = get_pc_line(frame)
		ret.append( '#{0} {1}'.format(frame_id, info) )
		frame_id += 1
		frame = frame.older()

	return str('\n'.join(ret))


def get_args():
	return [
		long(gdb.parse_and_eval("$rdi")),
		long(gdb.parse_and_eval("$rsi")),
		long(gdb.parse_and_eval("$rdx")),
#		long(gdb.parse_and_eval("$rcx")),
#		long(gdb.parse_and_eval("$r8")),
#		long(gdb.parse_and_eval("$r9")),
	]


def get_result():
	return long(gdb.parse_and_eval("$rax"))


def add_call(allocs, free_stats, call_stats, fn_name, fn_args, fn_stacktrace, fn_result):

	if fn_name == 'free':
		addr = fn_args[0]
		if addr != 0:
			if addr in allocs:
				alloc_stacktrace, _ = allocs[addr]
				if alloc_stacktrace not in free_stats:
					free_stats[alloc_stacktrace] = {fn_stacktrace: 1}
				else:
					if fn_stacktrace not in free_stats[alloc_stacktrace]:
						free_stats[alloc_stacktrace][fn_stacktrace] = 1
					else:
						free_stats[alloc_stacktrace][fn_stacktrace] += 1
				del allocs[addr]
				call_stats['free'] += 1

	elif fn_name == 'malloc':
		sz = fn_args[0]
		retaddr = fn_result
		assert retaddr != 0
		assert retaddr not in allocs
		allocs[retaddr] = (fn_stacktrace, sz)
		call_stats['malloc'] += 1
		call_stats['malloc_bytes'] += sz

	elif fn_name == 'calloc':
		sz = fn_args[0] * fn_args[1]
		retaddr = fn_result
		assert retaddr != 0
		assert retaddr not in allocs
		allocs[retaddr] = (fn_stacktrace, sz)
		call_stats['calloc'] += 1
		call_stats['calloc_bytes'] += sz

	elif fn_name == 'realloc':
		sz = fn_args[1]
		retaddr = fn_result
		assert retaddr != 0
		if fn_args[0] == 0:
			assert retaddr not in allocs
			allocs[retaddr] = (fn_stacktrace, sz)
			call_stats['realloc'] += 1
			call_stats['realloc_bytes'] += sz
		else:
			addr = fn_args[0]
			if addr in allocs:
				alloc_stacktrace, _ = allocs[addr]
				if alloc_stacktrace not in free_stats:
					free_stats[alloc_stacktrace] = {fn_stacktrace: 1}
				else:
					if fn_stacktrace not in free_stats[alloc_stacktrace]:
						free_stats[alloc_stacktrace][fn_stacktrace] = 1
					else:
						free_stats[alloc_stacktrace][fn_stacktrace] += 1
				del allocs[addr]
				call_stats['realloc_free'] += 1

				allocs[retaddr] = (fn_stacktrace, sz)
				call_stats['realloc'] += 1
				call_stats['realloc_bytes'] += sz

	elif fn_name == 'posix_memalign':
		assert fn_result == 0
		sz = fn_args[2]
		retaddr = long(gdb.parse_and_eval('*(long*)0x%lx' % fn_args[0]))
		assert retaddr != 0
		assert retaddr not in allocs
		allocs[retaddr] = (fn_stacktrace, sz)
		call_stats['posix_memalign'] += 1
		call_stats['posix_memalign_bytes'] += sz

	else:
		raise Exception(fn_name)


class watch_leaks(gdb.Command):
	def __init__(self):
		super(self.__class__, self).__init__(self.__class__.__name__, gdb.COMMAND_USER)

	def dump_leaks(self, allocs, free_stats):

		if len(allocs) == 0:
			print "no allocations - no leaks"
			return

		combined = {}

		for stacktrace, sz in allocs.values():
			if stacktrace not in combined:
				combined[stacktrace] = (0, 0)
			combined[stacktrace] = ( combined[stacktrace][0] + sz, combined[stacktrace][1] + 1 )

		most = sorted(combined.iteritems(), key=operator.itemgetter(1), reverse=True)

		print
		print "leaks detected:"
		print

		for stacktrace, (sz, chunks) in most:
			print sz, "bytes leak in", chunks, "chunks"
			print "-------"
			print stacktrace
			print "-------"
			print
			if stacktrace in free_stats:
				for k, v in free_stats[stacktrace].items():
					print "\t", v, "times:"
					print "\t", "\n\t".join(k.split('\n'))
					print


	def invoke(self, args, from_tty):
		self.prefix = ''

		allocs = {}
		threads = {}
		call_stats = defaultdict(int)
		free_stats = {}

		args = gdb.string_to_argv(args)

		deadline = time.time() + int(args[0])

		if len(args) > 1:
			self.prefix = args[1]

		class on_enter(gdb.Breakpoint):

			def __init__(self, fn_name, *args, **kw):
				super(self.__class__, self).__init__(*args, **kw)
				self.fn_name = fn_name

			def stop(self):
				if time.time() > deadline:
					return True
				thread_id = int(gdb.selected_thread().num)
				fn_args, fn_stacktrace = get_args(), get_stacktrace()
				assert thread_id not in threads
				if self.fn_name == 'free':
					add_call(allocs, free_stats, call_stats, self.fn_name, fn_args, fn_stacktrace, None)
					return False
				threads[thread_id] = ( self.fn_name, fn_args, fn_stacktrace )
				return False

		class on_result_ready(gdb.Breakpoint):

			def __init__(self, on_enter, *args, **kw):
				super(self.__class__, self).__init__(*args, **kw)
				self.on_enter = on_enter

			def stop(self):
				thread_id = int(gdb.selected_thread().num)
				assert thread_id in threads
				fn_result = get_result()
				fn_name, fn_args, fn_stacktrace = threads[thread_id]
				assert fn_name == self.on_enter.fn_name
				add_call(allocs, free_stats, call_stats, fn_name, fn_args, fn_stacktrace, fn_result)
				del threads[thread_id]
				return False

		def setup(fn_name):
			fn_full_name = self.prefix + fn_name
			print 'setting up breakpoint for', fn_full_name
			on_enter_instance = on_enter(fn_name, fn_full_name)

			# free() does not need a finishing breakpoint, because it returns a void
			# without this the leak detector is unstable, because
			# on some systems je_free() has a bunch of cross jumps somewhere:
			# anight@dura3:~/projects/test> gdb --batch -ex 'disassemble je_free' ./a.out  | grep jmpq | grep -v je_free
			#   0x000000000040554c <+428>:   jmpq   0x42aaa0 <je_tcache_event_hard>
			#   0x00000000004055a3 <+515>:   jmpq   0x40f0a0 <je_arena_dalloc_small>
			#   0x000000000040564e <+686>:   jmpq   0x421240 <je_huge_dalloc>
			#   0x000000000040566a <+714>:   jmpq   0x425aa0 <je_quarantine>
			#   0x00000000004056cb <+811>:   jmpq   0x40f2b0 <je_arena_dalloc_large>
			#
			# Luckily, this does not apply to all other memory functions

			if fn_name == 'free':
				return

			arch = gdb.selected_frame().architecture()
			sym = gdb.lookup_global_symbol(fn_full_name, gdb.SYMBOL_FUNCTIONS_DOMAIN)
			block = gdb.block_for_pc(long(sym.value().address))
			ptr = block.start
			while ptr < block.end:
				da = arch.disassemble(ptr)[0]
				if da['asm'].rstrip().endswith('retq'):
					print 'setting up finish breakpoint for', da
					on_result_ready_instance = on_result_ready(on_enter_instance, '*0x%lx' % da['addr'])
				ptr += da['length']

		setup("malloc")
		setup("calloc")
		setup("realloc")
		setup("posix_memalign")
		setup("free")

		print "breakpoints created, now watching"

		gdb.execute('continue')

		print "done watching"

		for k, v in call_stats.items():
			print k, v

		self.dump_leaks(allocs, free_stats)

watch_leaks()

