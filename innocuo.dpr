program innocuo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  uimagehlp,uxor;

var
key:string;

begin
  try
    if LowerCase(paramstr(1))='xor' then
    begin

     key:='FF';
     if xorfile(paramstr(2),ExtractFileName(paramstr(2))+'.noxor',strtoint('$'+key) )=true
       then writeln('Done!')
       else writeln('Error decoding file');
    end
    else
     begin
      dumpprocess(strtoint(paramstr(1))) //15156
     end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
