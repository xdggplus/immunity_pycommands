#!/usr/bin/env python

"""
CC-BY: hasherezade, 2015, run via ImmunityDbg
"""
__VERSION__ = '0.1'
__AUTHOR__ = 'hasherezade'

import immlib
import string

ProgAuthor = __AUTHOR__
ProgName    = 'callRegTracer'
ProgVers    = __VERSION__

DESC = "Trace all the functions called via register" #description used by PyCommands GUI
MAX_DUMP = 4
# --------------------------------------------------------------------------
# custom classes
# --------------------------------------------------------------------------
class ModuleInfo:
    def __init__(self, imm):
        self.imm = imm

    def isMyModule(self, address):
        curr_name = self.imm.getDebuggedName()
        module = self.imm.findModule(address)
        if not module:
            return False
        if curr_name == module[0].lower():
            return True
        return False

    def countMyAddresses(self, addresses):
        count = 0
        for addr in addresses:
            if self.isMyModule(addr):
                count += 1
        return count
    
    def fetchRegCalls(self):
      calls_dict = dict()
      regs32 = ["eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi"]
      for reg in regs32:
        data = "call "+ reg
        asm = self.imm.assemble(data)
        results = self.imm.search(asm)
        count = self.countMyAddresses(results)
        self.imm.log("Calls via %s: total: %d in current module: %d" % (reg.upper(), len(results), count), highlight=2)
        for addr in results:
            if self.isMyModule(addr):
              calls_dict[addr] = reg
      return calls_dict
     
# --------------------------------------------------------------------------
# custom functions
# --------------------------------------------------------------------------
# util:
def is_printable(my_string):
    for c in my_string:
        if ord(c) < 0x20 or ord(c) > 0x7e:
            return False
        return True
# --------------------------------------------------------------------------    
def listModules(imm):
    imm.log("Modules:", highlight=2)
    curr_name = imm.getDebuggedName()
    modules = imm.getAllModules()
    for key in modules.keys():
        mark = ""
        if (key == curr_name):
            imm.log("%s" % (key), highlight=1)
        else:
            imm.log("%s" % (key))
    imm.log("")

def getRegValue(imm, reg_name):
    reg_name = reg_name.upper()
    regs = imm.getRegs()
    if not regs:
        return None
    reg_value = regs[reg_name]
    return reg_value

def setBpOnAddresses(imm, addr_set, comment):
  for addr in addr_set:
    imm.setBreakpoint(addr)
    imm.setComment(addr, comment)

def printCallStack(imm, calledAt):
    stacks = imm.callStack()
    if len(stacks) == 0:
        return getParams(imm, calledAt)
    for st_arg in stacks:
        arg_dump = st_arg.getProcedure()
        if "Includes" in arg_dump:
            continue
        imm.log("> %s" % arg_dump)

def getParams(imm, calledAt):
    esp = getRegValue(imm, 'esp')
    count = 0
    while (count < MAX_DUMP):
        dw_param = imm.readLong(esp)
        str_param = imm.readString(dw_param)
        if not str_param:
            str_param = ""
        if not is_printable(str_param):
            str_param = ""
        imm.log("%08x %s" % (dw_param, str_param), calledAt, highlight=1)
        esp += 4 # sizeof(DWORD)
        count += 1

def printFunction(imm, calledAt, address):
    function = imm.getFunction(address)
    if function:
        imm.log("%s" % (function.getName()), calledAt, highlight=2)
        printCallStack(imm, calledAt)
        
# --------------------------------------------------------------------------    
def banner(imm):
    imm.log("--------------------", highlight=1)
    imm.log("%s v%s By %s" % (ProgName, ProgVers, ProgAuthor), highlight=1)
    imm.log("--------------------", highlight=1)
    
# --------------------------------------------------------------------------
# ImmunityDbg API
# --------------------------------------------------------------------------
def main(args):
    imm = immlib.Debugger()
    banner(imm)
    if imm.isFinished():
        imm.log("Process aleady finished!")
        return ".err"

    listModules(imm)

    mInfo = ModuleInfo(imm)
    call_dict = mInfo.fetchRegCalls()
    setBpOnAddresses(imm, call_dict.keys(), "Call via register")
    
    while not imm.isFinished():
        curr_addr = imm.getCurrentAddress()
        reg = call_dict.get(curr_addr)
        if not reg:
            imm.run()
            continue
        imm.log("CALL via: %s" %  reg, curr_addr)
        call_addr = getRegValue(imm, reg)
        if not call_addr:
            break
        imm.stepIn()
        printFunction(imm, curr_addr, call_addr)
        imm.run()
        
    #ret is the string shown at status bar
    return ".ok"

if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"
    