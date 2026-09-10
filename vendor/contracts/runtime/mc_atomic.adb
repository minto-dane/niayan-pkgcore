-- SPDX-License-Identifier: BSD-3-Clause
with MC_Hex; with Interfaces.C; with System;
package body MC_Atomic with SPARK_Mode => Off is
   procedure Random(P : System.Address; N : Interfaces.C.size_t)
     with Import, Convention=>C, External_Name=>"randombytes_buf";
   procedure Write(R : MC_FS.Root; Path : String; Data : Bytes;
                   Must_Be_New : Boolean; Status : out Outcome) is
      F : MC_FS.File; ID : Identity; Slash : Natural:=0;
   begin
      Random(ID'Address,ID'Length);
      for J in Path'Range loop if Path(J)='/' then Slash:=J; end if; end loop;
      declare Name : constant String:= (if Slash=0 then "" else Path(Path'First..Slash)) &
         ".mc-tmp-" & MC_Hex.Encode(ID); begin
         MC_FS.Create_New(R,Name,F,Status); if Status/=OK then return; end if;
         MC_FS.Write_All(F,Data,Status); if Status=OK then MC_FS.Sync(F,Status); end if;
         MC_FS.Close(F); if Status/=OK then return; end if;
         MC_FS.Rename(R,Name,Path,Must_Be_New,Status);
         if Status=Conflict then
            -- rename(RENAME_NOREPLACE) definitely did not publish this staging
            -- inode. Do not leak one full temporary file per idempotent retry.
            -- Never clean a target or a staging name after an uncertain rename.
            declare Clean : Outcome; begin
               MC_FS.Remove(R,Name,False,Clean);
               if Clean/=OK then Status:=IO_Error; end if;
            end;
         end if;
      end;
   exception when others => MC_FS.Close(F); Status:=Indeterminate;
   end Write;
   procedure Read(R : MC_FS.Root; Path : String; Data : out Bytes;
                  Used : out Natural; Status : out Outcome) is
      F : MC_FS.File; I, After : MC_FS.Entry_Info;
      use type MC_FS.Entry_Info;
   begin
      Data:=(others=>0); Used:=0;
      MC_FS.Open_Read(R,Path,F,Status); if Status/=OK then return; end if;
      MC_FS.Info(F,I,Status);
      if Status=OK and then I.Size>Counter(Data'Length) then Status:=Exhausted; end if;
      if Status=OK then MC_FS.Read_At(F,0,Data,Used,Status); end if;
      if Status=OK then MC_FS.Info(F,After,Status); end if;
      MC_FS.Close(F);
      if Status=OK and then (Counter(Used)/=I.Size or else I/=After) then
         Status:=Conflict;
      end if;
      if Status/=OK then Used:=0; Data:=(others=>0); end if;
   exception when others => MC_FS.Close(F); Status:=IO_Error;
   end Read;
end MC_Atomic;
