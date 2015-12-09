#!/usr/bin/env python

__VERSION__ = '1.0'
import immlib
import getopt
import immutils
import pefile
from immutils import *
from immlib import Debugger, LoadDLLHook

class DLLHook(LoadDLLHook):
	def __init__(self, modulename):
		LoadDLLHook.__init__(self)
		self.imm = Debugger()
		self.modulename = modulename
		self.imm.log('watching for %s %s' % (__VERSION__, self.modulename))

	def run(self, regs):
		if self.modulename in self.imm.getAllModules().keys():
			module = self.imm.getModule(self.modulename)
			base = module.getBase()
			self.imm.log('Hit %s at 0x%x' % (self.modulename, base) )
			pe = pefile.PE(module.getPath())
			for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				if exp.address > 0:
					self.imm.log('Name: %s,RelativeAddress: 0x%x, Ordinal: 0x%x' % (exp.name, exp.address, exp.ordinal))
					self.imm.setBreakpoint(base + exp.address)
			self.disable()
                    	self.UnHook()
	

def main(args):
	for module in args:
		hook = DLLHook(module)
		hook.add('dll_hooker')
