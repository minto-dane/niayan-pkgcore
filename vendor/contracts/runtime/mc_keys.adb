-- SPDX-License-Identifier: BSD-3-Clause
with MC_FS; with MC_Atomic; with MC_Posix; with Interfaces.C; with System;
package body MC_Keys with SPARK_Mode => Off is
   use Interfaces.C; use type Word;
   function Init return int with Import,Convention=>C,External_Name=>"sodium_init";
   procedure Random(P : System.Address; N : size_t) with Import,Convention=>C,External_Name=>"randombytes_buf";
   function Lock(P : System.Address; N : size_t) return int with Import,Convention=>C,External_Name=>"sodium_mlock";
   function Unlock(P : System.Address; N : size_t) return int with Import,Convention=>C,External_Name=>"sodium_munlock";
   procedure Wipe(P : System.Address; N : size_t) with Import,Convention=>C,External_Name=>"sodium_memzero";
   function Derive(PK,SK,Seed : System.Address) return int with Import,Convention=>C,External_Name=>"crypto_sign_seed_keypair";
   function Detached(Sig,Length,Data : System.Address; N : unsigned_long_long; SK : System.Address) return int
     with Import,Convention=>C,External_Name=>"crypto_sign_detached";
   procedure Generate(Private_Directory : String; Public_Key : out MC_Signatures.Public_Key; Status : out Outcome) is
      R : MC_FS.Root; Seed : aliased Bytes(1..32):=(others=>0); SK : aliased Bytes(1..64):=(others=>0);
      PK : aliased MC_Signatures.Public_Key:=(others=>0); Ignored : int; Locked : Boolean:=False;
      pragma Unreferenced(Ignored);
   begin
      Public_Key:=(others=>0); Status:=Denied; if Init<0 then return; end if;
      if Lock(Seed'Address,32)/=0 then return; end if; Locked:=True;
      if Lock(SK'Address,64)/=0 then Ignored:=Unlock(Seed'Address,32); return; end if;
      MC_FS.Open_Root(Private_Directory,R,Status,Private_Only=>True);
      if Status=OK then
         Random(Seed'Address,32);
         if Derive(PK'Address,SK'Address,Seed'Address)/=0 then Status:=IO_Error;
         else MC_Atomic.Write(R,"key.seed",Seed,True,Status); end if;
         if Status=OK then MC_Atomic.Write(R,"public.key",PK,True,Status); end if;
      end if;
      Wipe(SK'Address,64); Wipe(Seed'Address,32); Ignored:=Unlock(SK'Address,64); Ignored:=Unlock(Seed'Address,32);
      MC_FS.Close(R); if Status=OK then Public_Key:=PK; end if;
   exception when others=>Wipe(SK'Address,64); Wipe(Seed'Address,32);
      if Locked then Ignored:=Unlock(SK'Address,64); Ignored:=Unlock(Seed'Address,32); end if;
      MC_FS.Close(R); Status:=IO_Error;
   end;
   procedure Sign(Private_Directory : String; Message : Bytes;
      Public_Key : out MC_Signatures.Public_Key; Signature : out MC_Signatures.Signature; Status : out Outcome) is
      R : MC_FS.Root; F : MC_FS.File; V : MC_FS.Entry_Info; Used : Natural;
      Seed : aliased Bytes(1..32):=(others=>0); SK : aliased Bytes(1..64):=(others=>0);
      PK : aliased MC_Signatures.Public_Key:=(others=>0); Sig : aliased MC_Signatures.Signature:=(others=>0);
      Ignored : int; Locked : Boolean:=False; pragma Unreferenced(Ignored);
   begin
      Public_Key:=(others=>0); Signature:=(others=>0); Status:=Denied;
      if Message'Length=0 or else Message'Length>16_777_216 or else Init<0 then return; end if;
      if Lock(Seed'Address,32)/=0 then return; end if; Locked:=True;
      if Lock(SK'Address,64)/=0 then Ignored:=Unlock(Seed'Address,32); return; end if;
      MC_FS.Open_Root(Private_Directory,R,Status,Private_Only=>True);
      if Status=OK then MC_FS.Open_Read(R,"key.seed",F,Status); end if;
      if Status=OK then MC_FS.Info(F,V,Status); end if;
      if Status=OK and then (V.Size/=32 or else V.Mode not in 8#400# | 8#600# or else V.UID/=Word(MC_Posix.Euid)) then Status:=Denied; end if;
      if Status=OK then MC_FS.Read_At(F,0,Seed,Used,Status); end if;
      if Status=OK and then Used/=32 then Status:=Corrupt; end if;
      if Status=OK and then Derive(PK'Address,SK'Address,Seed'Address)/=0 then Status:=IO_Error; end if;
      if Status=OK and then Detached(Sig'Address,System.Null_Address,Message(Message'First)'Address,
         unsigned_long_long(Message'Length),SK'Address)/=0 then Status:=IO_Error; end if;
      Wipe(SK'Address,64); Wipe(Seed'Address,32); Ignored:=Unlock(SK'Address,64); Ignored:=Unlock(Seed'Address,32);
      MC_FS.Close(F); MC_FS.Close(R); if Status=OK then Public_Key:=PK; Signature:=Sig; end if;
   exception when others=>Wipe(SK'Address,64); Wipe(Seed'Address,32);
      if Locked then Ignored:=Unlock(SK'Address,64); Ignored:=Unlock(Seed'Address,32); end if;
      MC_FS.Close(F); MC_FS.Close(R); Status:=IO_Error;
   end Sign;
end MC_Keys;
