program innocuo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  uimagehlp,
  ntdll in 'ntdll.pas',
  uadvapi32 in 'uadvapi32.pas',uxor;

var
key:string;

begin
  try
    if paramstr(1)='xor' then
    begin

     key:='FF';
     if xorfile(paramstr(2),ExtractFileName(paramstr(2))+'.noxor',strtoint('$'+key) )=true
       then writeln('Done!')
       else writeln('Error decoding file');
    end
    else dumpprocess3(strtoint(paramstr(1))) //15156
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
