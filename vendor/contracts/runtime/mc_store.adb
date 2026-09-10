-- SPDX-License-Identifier: BSD-3-Clause
with MC_Hex; with MC_Dirents; with MC_SHA256; with MC_Posix; with Interfaces.C; with System;
package body MC_Store with SPARK_Mode => Off is
   use type MC_FS.Entry_Kind; use type MC_Types.Word; use type MC_FS.Entry_Info; use type Interfaces.C.int;
   function Native_Reservation (S : Store) return Integer is
     (if S.Opened then MC_FS.Native (S.Lock) else -1);
   procedure Random_Bytes (P : System.Address; N : Interfaces.C.size_t)
     with Import, Convention => C, External_Name => "randombytes_buf";
   function Object_Path (D : Digest) return String is
      H : constant String := MC_Hex.Encode(D);
   begin return "objects/" & H(1..2) & "/" & H(3..64); end;
   procedure Need_Directory (S : in out Store; Path : String; Status : out Outcome) is
      V : MC_FS.Entry_Info;
   begin
      MC_FS.Stat(S.Directory,Path,V,Status); if Status/=OK then return; end if;
      if V.Kind=MC_FS.Absent then MC_FS.Make_Directory(S.Directory,Path,Status);
      elsif V.Kind/=MC_FS.Directory or else V.Mode/=8#700# or else V.UID/=Word(MC_Posix.Euid)
      then Status:=Denied; end if;
   end Need_Directory;
   procedure Initialize (Path : String; S : in out Store; Status : out Outcome) is
      Names : MC_Dirents.Listing;
   begin
      Status:=Conflict; if S.Opened then return; end if;
      MC_FS.Open_Root(Path,S.Directory,Status,Private_Only=>True);
      if Status=OK then MC_FS.List_Names(S.Directory,"",Names,Status); end if;
      if Status=OK and then Names.Count/=0 then Status:=Conflict; end if;
      if Status/=OK then Close(S); return; end if;
      -- Exclusive creation wins races with another bootstrap. Never reopen an
      -- existing lock as permission to repair missing persistent directories.
      MC_FS.Create_New(S.Directory,"store.lock",S.Lock,Status);
      if Status=OK and then MC_Posix.Flock(Interfaces.C.int(MC_FS.Native(S.Lock)),MC_Posix.LOCK_EX_NB)/=0
      then Status:=Conflict; end if;
      if Status=OK then MC_FS.Sync(S.Lock,Status); end if;
      if Status=OK then MC_FS.Sync_Parent(S.Directory,"store.lock",Status); end if;
      if Status=OK then MC_FS.Make_Directory(S.Directory,"objects",Status); end if;
      if Status=OK then MC_FS.Make_Directory(S.Directory,"incoming",Status); end if;
      if Status=OK then MC_FS.Make_Directory(S.Directory,"pins",Status); end if;
      if Status/=OK then Close(S); return; end if;
      S.Opened:=True;
   exception when others => Close(S); Status:=Indeterminate;
   end Initialize;
   procedure Open (Path : String; S : in out Store; Status : out Outcome) is
      V : MC_FS.Entry_Info;
   begin
      Status:=Conflict; if S.Opened then return; end if;
      MC_FS.Open_Root(Path,S.Directory,Status,Private_Only=>True);
      if Status/=OK then return; end if;
      MC_FS.Open_Locked(S.Directory,"store.lock",S.Lock,Status,Create_If_Missing=>False);
      if Status/=OK then Close(S); return; end if;
      for I in 1..3 loop
         declare Name : constant String :=
           (case I is when 1=>"objects",when 2=>"incoming",when others=>"pins"); begin
            MC_FS.Stat(S.Directory,Name,V,Status);
            if Status=OK and then V.Kind/=MC_FS.Directory then Status:=Corrupt; end if;
            if Status=OK and then (V.Mode/=8#700# or else V.UID/=Word(MC_Posix.Euid)) then Status:=Denied; end if;
            if Status/=OK then Close(S); return; end if;
         end;
      end loop;
      S.Opened:=True;
   exception when others => Close(S); Status:=Indeterminate;
   end Open;
   procedure Begin_Object (S : in out Store; Name : out Identity; F : in out MC_FS.File;
                           Status : out Outcome) is
   begin
      Status:=Invalid_Input; Name:=Zero_Identity;
      if not S.Opened then return; end if;
      Random_Bytes(Name'Address,Name'Length);
      MC_FS.Create_New(S.Directory,"incoming/" & MC_Hex.Encode(Name),F,Status);
   end Begin_Object;
   procedure Publish (S : in out Store; Name : Identity; F : in out MC_FS.File;
                       D : Digest; Status : out Outcome) is
      V : MC_FS.Entry_Info; Existing : MC_FS.File; E_Digest : Digest; E_Size : Counter;
      H : constant String := MC_Hex.Encode(D);
      Clean_Status : Outcome;
   begin
      MC_FS.Info(F,V,Status); if Status/=OK then return; end if;
      V.Mode:=8#400#; V.UID:=Word(MC_Posix.Euid); V.GID:=Word(MC_Posix.Egid);
      MC_FS.Set_Metadata(F,V,Status); if Status/=OK then return; end if;
      Need_Directory(S,"objects/" & H(1..2),Status); if Status/=OK then return; end if;
      MC_FS.Close(F);
      MC_FS.Rename(S.Directory,"incoming/" & MC_Hex.Encode(Name),Object_Path(D),True,Status);
      if Status=Conflict then
         MC_FS.Open_Read(S.Directory,Object_Path(D),Existing,Status);
         if Status=OK then MC_FS.Hash(Existing,Max_Object_Size,E_Digest,E_Size,Status); end if;
         MC_FS.Close(Existing);
         if Status=OK and then E_Digest/=D then Status:=Corrupt; end if;
         if Status=OK then
            MC_FS.Remove(S.Directory,"incoming/" & MC_Hex.Encode(Name),False,Clean_Status);
            if Clean_Status/=OK then Status:=Clean_Status; end if;
         end if;
      end if;
   end Publish;
   procedure Put (S : in out Store; Data : Bytes; D : out Digest; Status : out Outcome) is
      F : MC_FS.File; Name : Identity;
   begin
      D:=Zero_Digest; Status:=Exhausted;
      if Data'Length>16_777_216 then return; end if;
      Begin_Object(S,Name,F,Status); if Status/=OK then return; end if;
      MC_FS.Write_All(F,Data,Status);
      if Status=OK then
         D:=MC_SHA256.Hash(Data); Publish(S,Name,F,D,Status);
      end if;
      MC_FS.Close(F);
      if Status/=OK then D:=Zero_Digest; end if;
   exception when others => MC_FS.Close(F); D:=Zero_Digest; Status:=Indeterminate;
   end Put;
   procedure Import_File (S : in out Store; Input : MC_FS.File; Limit : Counter;
                          D : out Digest; Status : out Outcome) is
      F : MC_FS.File; Name : Identity; B : Bytes(1..65_536); Used : Natural;
      At_Byte : Counter:=0; C : MC_SHA256.Context:=MC_SHA256.Initialize;
      Before, After : MC_FS.Entry_Info;
      use type MC_FS.Entry_Info;
   begin
      D:=Zero_Digest; Status:=Exhausted;
      if Limit>Max_Object_Size then return; end if;
      MC_FS.Info(Input,Before,Status); if Status/=OK then return; end if;
      if Before.Kind/=MC_FS.Regular or else Before.Size>Limit then Status:=Exhausted; return; end if;
      Begin_Object(S,Name,F,Status); if Status/=OK then return; end if;
      loop
         MC_FS.Read_At(Input,At_Byte,B,Used,Status); exit when Status/=OK or else Used=0;
         if Counter(Used)>Limit-At_Byte then Status:=Exhausted; exit; end if;
         MC_FS.Write_All(F,B(1..Used),Status); exit when Status/=OK;
         MC_SHA256.Update(C,B(1..Used)); At_Byte:=At_Byte+Counter(Used);
      end loop;
      if Status=OK then
         MC_FS.Info(Input,After,Status);
         if Status=OK and then (Before/=After or else At_Byte/=Before.Size) then Status:=Conflict; end if;
      end if;
      if Status=OK then D:=MC_SHA256.Finish(C); Publish(S,Name,F,D,Status); end if;
      MC_FS.Close(F); if Status/=OK then D:=Zero_Digest; end if;
   exception when others => MC_FS.Close(F); D:=Zero_Digest; Status:=Indeterminate;
   end Import_File;
   procedure Open_Object (S : Store; D : Digest; F : in out MC_FS.File; Status : out Outcome) is
      Found : Digest; Length : Counter; V,After : MC_FS.Entry_Info;
   begin
      Status:=Invalid_Input; if not S.Opened or else D=Zero_Digest then return; end if;
      MC_FS.Open_Read(S.Directory,Object_Path(D),F,Status); if Status/=OK then return; end if;
      MC_FS.Info(F,V,Status);
      if Status=OK and then (V.Mode/=8#400# or else V.UID/=Word(MC_Posix.Euid)) then Status:=Denied; end if;
      if Status=OK then MC_FS.Hash(F,Max_Object_Size,Found,Length,Status); end if;
      if Status=OK then MC_FS.Info(F,After,Status); end if;
      if Status=OK and then (Found/=D or else V/=After) then Status:=Corrupt; end if;
      if Status/=OK then MC_FS.Close(F); end if;
   end Open_Object;
   procedure Read_Object (S : Store; D : Digest; Data : out Bytes;
                          Used : out Natural; Status : out Outcome) is
      F : MC_FS.File; V,After : MC_FS.Entry_Info;
   begin
      Data:=(others=>0); Used:=0;
      Open_Object(S,D,F,Status); if Status/=OK then return; end if;
      MC_FS.Info(F,V,Status);
      if Status=OK and then V.Size>Counter(Data'Length) then Status:=Exhausted; end if;
      if Status=OK then MC_FS.Read_At(F,0,Data,Used,Status); end if;
      if Status=OK then MC_FS.Info(F,After,Status); end if;
      if Status=OK and then (Counter(Used)/=V.Size or else V/=After
        or else MC_SHA256.Hash(Data(Data'First..Data'First+Used-1))/=D) then Status:=Corrupt; end if;
      MC_FS.Close(F);
      if Status/=OK then Data:=(others=>0); Used:=0; end if;
   exception when others => MC_FS.Close(F); Data:=(others=>0); Used:=0; Status:=IO_Error;
   end Read_Object;
   procedure Check_Pin (S : Store; ID : Identity; Manifest : Digest; Status : out Outcome) is
      F : MC_FS.File; B : Bytes(1..33); Used : Natural;
   begin
      MC_FS.Open_Read(S.Directory,"pins/" & MC_Hex.Encode(ID),F,Status);
      if Status=OK then MC_FS.Read_At(F,0,B,Used,Status); end if;
      MC_FS.Close(F);
      if Status=OK and then (Used/=32 or else B(1..32)/=Manifest) then Status:=Conflict; end if;
   end Check_Pin;
   procedure Pin (S : in out Store; ID : Identity; Manifest : Digest; Status : out Outcome) is
      F : MC_FS.File; Object : MC_FS.File; Name : Identity;
   begin
      Status:=Invalid_Input; if ID=Zero_Identity then return; end if;
      Open_Object(S,Manifest,Object,Status); MC_FS.Close(Object); if Status/=OK then return; end if;
      -- Publish the pin via fsync(temp), rename(NOREPLACE), fsync(parent).
      Begin_Object(S,Name,F,Status); if Status/=OK then return; end if;
      MC_FS.Write_All(F,Manifest,Status); if Status=OK then MC_FS.Sync(F,Status); end if;
      MC_FS.Close(F); if Status/=OK then return; end if;
      MC_FS.Rename(S.Directory,"incoming/" & MC_Hex.Encode(Name),"pins/" & MC_Hex.Encode(ID),True,Status);
      if Status=Conflict then
         Check_Pin(S,ID,Manifest,Status);
         if Status=OK then
            declare Cleanup : Outcome; begin
               -- EEXIST proves this name was not published. Never delete the
               -- established pin or clean a staging name after uncertain rename.
               MC_FS.Remove(S.Directory,"incoming/" & MC_Hex.Encode(Name),False,Cleanup);
               if Cleanup/=OK then Status:=Cleanup; end if;
            end;
         end if;
      end if;
   exception when others => MC_FS.Close(F); MC_FS.Close(Object); Status:=Indeterminate;
   end Pin;
   procedure Begin_Write(S : in out Store; Expected : Digest; Size : Counter;
                         W : in out Writer; Status : out Outcome) is
   begin
      Status:=Invalid_Input;
      if W.Active or else Expected=Zero_Digest or else Size>Max_Object_Size then return; end if;
      Begin_Object(S,W.Name,W.F,Status); if Status/=OK then return; end if;
      W.Expected:=Expected; W.Size:=Size; W.Written:=0; W.Hash:=MC_SHA256.Initialize; W.Active:=True;
   end;
   procedure Write_Chunk(W : in out Writer; Data : Bytes; Status : out Outcome) is
   begin
      Status:=Invalid_Input;
      if not W.Active or else Counter(Data'Length)>W.Size-W.Written then return; end if;
      MC_FS.Write_All(W.F,Data,Status);
      if Status=OK then MC_SHA256.Update(W.Hash,Data); W.Written:=W.Written+Counter(Data'Length); end if;
   end;
   procedure Finish_Write(S : in out Store; W : in out Writer; Status : out Outcome) is
   begin
      Status:=Corrupt;
      if not W.Active or else W.Written/=W.Size or else MC_SHA256.Finish(W.Hash)/=W.Expected then Abort_Write(W); return; end if;
      Publish(S,W.Name,W.F,W.Expected,Status); MC_FS.Close(W.F); W.Active:=False;
   end;
   procedure Abort_Write(W : in out Writer) is
   begin MC_FS.Close(W.F); W.Active:=False; end;
   procedure Close (S : in out Store) is
   begin MC_FS.Close(S.Lock); MC_FS.Close(S.Directory); S.Opened:=False; end;
end MC_Store;
