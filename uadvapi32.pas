unit uadvapi32;

{$Define UsePacked}

interface

uses
  Classes, SysUtils,windows,utils{,jwawincrypt};

const
  LOGON_WITH_PROFILE = $00000001;

  //https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto_system.h
  const
  MD4_DIGEST_LENGTH=	16;
  MD5_DIGEST_LENGTH=	16;
  SHA_DIGEST_LENGTH=	20;

  DES_KEY_LENGTH=	7;
  DES_BLOCK_LENGTH=	8;
  AES_128_KEY_LENGTH=	16;
  AES_256_KEY_LENGTH=	32;

  //https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/mimikatz/modules/kuhl_m_lsadump_struct.h
  SYSKEY_LENGTH	=16;
  SAM_KEY_DATA_SALT_LENGTH=	16 ;
  SAM_KEY_DATA_KEY_LENGTH=	16;

type
 tbyte16__=array[0..15] of byte;

type
   TIntegrityLevel = (UnknownIntegrityLevel=0, LowIntegrityLevel, MediumIntegrityLevel, HighIntegrityLevel, SystemIntegrityLevel);



function ImpersonateAsSystemW_Vista(IntegrityLevel: TIntegrityLevel;pid:cardinal): Boolean;

function impersonatepid(pid:dword):boolean;

[...]

end.

