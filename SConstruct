
env = Environment()
#cflags = ['-g', '-O2', '-Wall', '-Werror']
cflags = ['-g', '-Wall', '-Werror']
includes = [
  'PcepSessionLogic/include',
  'PcepSocketComm/include',
  'PcepTimers/include',
  'PcepUtils/include',
  '/home/brady/projects/libPcep/include'
]
env.Append(CPPPATH = includes, CFLAGS = cflags)

#
# PcepUtils library
#
utilsLibTarget = env.Library(source = Glob('PcepUtils/src/*.c'), target = 'scons_build/libPcepUtils')
env.Alias('utilsLib', utilsLibTarget)

#
# PcepMessages library
#
messagesLibTarget = env.Library(source = Glob('PcepMessages/src/*.c'), target = 'scons_build/libPcepMessages')
env.Alias('messagesLib', messagesLibTarget)

#
# PcepSocketComm library
#
socketCommLibTarget = env.Library(source = Glob('PcepSocketComm/src/*.c'), target = 'scons_build/libPcepSocketComm')
env.Alias('socketCommLib', socketCommLibTarget)

#
# PcepTimers Library
#
timersLibTarget = env.Library(source = Glob('PcepTimers/src/*.c'), target = 'scons_build/libPcepTimers')
env.Alias('timersLib', timersLibTarget)

#
# PcepSessionLogic Library
#
sessionLibTarget = env.Library(source = Glob('PcepSessionLogic/src/*.c'), target = 'scons_build/libPcepSessionLogic')
env.Alias('sessionLogicLib', sessionLibTarget)

#
# Setup the libs for the binary
#
libraries = [
    'PcepSessionLogic',
    'PcepSocketComm',
    'PcepTimers',
    'PcepMessages',
    'PcepUtils',
    'pthread'
]
env.Append(LIBS = libraries, LIBPATH = ['scons_build'])

#
# PCC PCEP client
#
pccTarget = env.Program(source = 'PcepPcc/pcep_pcc.c', target = 'scons_build/pcc_pcep')
env.Alias('pcc', pccTarget)
env.Default(pccTarget)

#
# Utils OrderedList test
#
listTestTarget = Program(source = 'PcepUtils/test/PcepUtilsOrderedListTest.c',
                         target = 'scons_build/listTest',
                         CFLAGS = cflags,
                         CPPPATH = 'PcepUtils/include',
                         LIBS = 'PcepUtils',
                         LIBPATH = 'scons_build')

#
# Utils Queue test
#
queueTestTarget = Program(source = 'PcepUtils/test/PcepUtilsQueueTest.c',
                         target = 'scons_build/queueTest',
                         CFLAGS = cflags,
                         CPPPATH = 'PcepUtils/include',
                         LIBS = 'PcepUtils',
                         LIBPATH = 'scons_build')
env.Alias('tests', [listTestTarget, queueTestTarget])

