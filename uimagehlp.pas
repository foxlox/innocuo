unit uimagehlp;


interface


uses
  Classes, SysUtils,windows,
  utils,ntdll,uxor,uadvapi32;

const
  MiniDumpNormal         = $0000;
  {$EXTERNALSYM MiniDumpNormal}
  MiniDumpWithDataSegs   = $0001;
  {$EXTERNALSYM MiniDumpWithDataSegs}
  MiniDumpWithFullMemory = $0002;
  {$EXTERNALSYM MiniDumpWithFullMemory}
  MiniDumpWithHandleData = $0004;
  {$EXTERNALSYM MiniDumpWithHandleData}
  MiniDumpFilterMemory   = $0008;
  {$EXTERNALSYM MiniDumpFilterMemory}
  MiniDumpScanMemory     = $0010;
  {$EXTERNALSYM MiniDumpScanMemory}
  MiniDumpWithUnloadedModules            = $0020;
  {$EXTERNALSYM MiniDumpWithUnloadedModules}
  MiniDumpWithIndirectlyReferencedMemory = $0040;
  {$EXTERNALSYM MiniDumpWithIndirectlyReferencedMemory}
  MiniDumpFilterModulePaths              = $0080;
  {$EXTERNALSYM MiniDumpFilterModulePaths}
  MiniDumpWithProcessThreadData          = $0100;
  {$EXTERNALSYM MiniDumpWithProcessThreadData}
  MiniDumpWithPrivateReadWriteMemory     = $0200;
  {$EXTERNALSYM MiniDumpWithPrivateReadWriteMemory}

  type
  _MINIDUMP_TYPE = DWORD;
  {$EXTERNALSYM _MINIDUMP_TYPE}
  MINIDUMP_TYPE = _MINIDUMP_TYPE;
  {$EXTERNALSYM MINIDUMP_TYPE}
  TMinidumpType = MINIDUMP_TYPE;

  //**************************************************************

   MINIDUMP_CALLBACK_TYPE = (
    ModuleCallback, //0
            ThreadCallback,  //1
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback, //11
            IoWriteAllCallback, //12
            IoFinishCallback,  //13
            ReadMemoryFailureCallback, //14
            SecondaryFlagsCallback, //15
            IsProcessSnapshotCallback, //16
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback);

  PMINIDUMP_THREAD_CALLBACK = ^MINIDUMP_THREAD_CALLBACK;
  {$EXTERNALSYM PMINIDUMP_THREAD_CALLBACK}
  MINIDUMP_THREAD_CALLBACK = record
    ThreadId: ULONG;
    ThreadHandle: HANDLE;
    Context: CONTEXT;
    SizeOfContext: ULONG;
    StackBase: ULONG64;
    StackEnd: ULONG64;
  end;

  PMINIDUMP_THREAD_EX_CALLBACK = ^MINIDUMP_THREAD_EX_CALLBACK;
   {$EXTERNALSYM PMINIDUMP_THREAD_EX_CALLBACK}
   MINIDUMP_THREAD_EX_CALLBACK = record
     ThreadId: ULONG;
     ThreadHandle: HANDLE;
     Context: CONTEXT;
     SizeOfContext: ULONG;
     StackBase: ULONG64;
     StackEnd: ULONG64;
     BackingStoreBase: ULONG64;
     BackingStoreEnd: ULONG64;
   end;

   PMINIDUMP_MODULE_CALLBACK = ^MINIDUMP_MODULE_CALLBACK;
     {$EXTERNALSYM PMINIDUMP_MODULE_CALLBACK}
     MINIDUMP_MODULE_CALLBACK = record
       FullPath: PWCHAR;
       BaseOfImage: ULONG64;
       SizeOfImage: ULONG;
       CheckSum: ULONG;
       TimeDateStamp: ULONG;
       VersionInfo: VS_FIXEDFILEINFO;
       CvRecord: PVOID;
       SizeOfCvRecord: ULONG;
       MiscRecord: PVOID;
       SizeOfMiscRecord: ULONG;
     end;

     PMINIDUMP_INCLUDE_THREAD_CALLBACK = ^MINIDUMP_INCLUDE_THREAD_CALLBACK;
       {$EXTERNALSYM PMINIDUMP_INCLUDE_THREAD_CALLBACK}
       MINIDUMP_INCLUDE_THREAD_CALLBACK = record
         ThreadId: ULONG;
       end;

       PMINIDUMP_INCLUDE_MODULE_CALLBACK = ^MINIDUMP_INCLUDE_MODULE_CALLBACK;
         {$EXTERNALSYM PMINIDUMP_INCLUDE_MODULE_CALLBACK}
         MINIDUMP_INCLUDE_MODULE_CALLBACK = record
           BaseOfImage: ULONG64;
         end;

 type MINIDUMP_IO_CALLBACK =record
   Handle:HANDLE;
   Offset:ULONG64;
   Buffer:PVOID;
   BufferBytes:ULONG;
end;
 PMINIDUMP_IO_CALLBACK=^MINIDUMP_IO_CALLBACK;

 //https://github.com/b4rtik/SharpMiniDump/blob/master/SharpMiniDump/Natives.cs
  MINIDUMP_CALLBACK_INPUT = packed record
      ProcessId: ULONG;
      ProcessHandle: HANDLE;
      CallbackType: ULONG; //4+8
      case Integer of
        0: (Thread: MINIDUMP_THREAD_CALLBACK);
        1: (ThreadEx: MINIDUMP_THREAD_EX_CALLBACK);
        2: (Module: MINIDUMP_MODULE_CALLBACK);
        3: (IncludeThread: MINIDUMP_INCLUDE_THREAD_CALLBACK);
        4: (IncludeModule: MINIDUMP_INCLUDE_MODULE_CALLBACK);
        5: (Io:MINIDUMP_IO_CALLBACK);
    end;
  PMINIDUMP_CALLBACK_INPUT = ^MINIDUMP_CALLBACK_INPUT;

  PMINIDUMP_MEMORY_INFO = ^MINIDUMP_MEMORY_INFO;
  MINIDUMP_MEMORY_INFO =record
     BaseAddress:ULONG64;
     AllocationBase:ULONG64;
     AllocationProtect:ULONG32;
     __alignment1:ULONG32;
     RegionSize:ULONG64;
     State:ULONG32;
     Protect:ULONG32;
     Type_:ULONG32;
     __alignment2:ULONG32;
  end;


  PMINIDUMP_CALLBACK_OUTPUT = ^MINIDUMP_CALLBACK_OUTPUT;

  MINIDUMP_CALLBACK_OUTPUT =record
  Status:HRESULT;
  end;

  MINIDUMP_CALLBACK_ROUTINE = function(CallbackParam: PVOID; CallbackInput: PMINIDUMP_CALLBACK_INPUT;CallbackOutput: PMINIDUMP_CALLBACK_OUTPUT): BOOL; stdcall;

  type MINIDUMP_CALLBACK_INFORMATION =record
  CallbackRoutine:MINIDUMP_CALLBACK_ROUTINE;
  CallbackParam:PVOID;
  end;
  PMINIDUMP_CALLBACK_INFORMATION=^MINIDUMP_CALLBACK_INFORMATION;

{$EXTERNALSYM MiniDumpWriteDump}


function log(s:string):string;

function dumpprocess(pid:dword):boolean;

implementation



[...]


 end.
