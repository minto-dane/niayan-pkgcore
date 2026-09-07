-- SPDX-License-Identifier: MIT
with MC_Text; with MC_SHA256;
package body Pkg_Image_Inspector with SPARK_Mode=>Off is
   use type MC_FS.Entry_Kind; use type MC_FS.Entry_Info; use type Word;
   procedure Inspect(R : MC_FS.Root; Path : String; Maximum_Bytes : Counter;
      S : out Pkg_File_Plan.Shape; Read_Bytes : out Counter; Status : out Outcome) is
      Before,After,Opened : MC_FS.Entry_Info; F : MC_FS.File;
      X : Bytes(1..MC_FS.Max_Xattr_Bytes); Used : Natural; Target : MC_Text.Value;
   begin
      S:=(others=><>); Read_Bytes:=0;
      MC_FS.Stat(R,Path,Before,Status); if Status/=OK then return; end if;
      if Before.Kind=MC_FS.Absent then Status:=OK; return; end if;
      if Before.Kind=MC_FS.Other or else (Before.Kind=MC_FS.Regular and then Before.Links/=1)
        or else Before.Size>Maximum_Bytes then Status:=Unsupported; return; end if;
      S.Mode:=Before.Mode; S.UID:=Before.UID; S.GID:=Before.GID;
      if Before.Kind=MC_FS.Symbolic_Link then
         S.Node_Kind:=Pkg_File_Plan.Symbolic_Link;
         MC_FS.Read_Link(R,Path,Target,Status); if Status/=OK then return; end if;
         declare Text : constant String:=MC_Text.Image(Target); B : Bytes(1..Text'Length); begin
            for I in Text'Range loop B(I):=Byte(Character'Pos(Text(I))); end loop;
            S.Content:=MC_SHA256.Hash(B); S.Size:=Counter(B'Length); Read_Bytes:=S.Size;
         end;
         MC_FS.Get_Link_Xattrs(R,Path,X,Used,Status);
      else
         MC_FS.Open_Read(R,Path,F,Status); if Status/=OK then return; end if;
         MC_FS.Info(F,Opened,Status);
         if Status/=OK or else Opened/=Before then MC_FS.Close(F); Status:=Conflict; return; end if;
         if Before.Kind=MC_FS.Regular then
            S.Node_Kind:=Pkg_File_Plan.Regular; S.Size:=Before.Size;
            S.Mtime_Sec:=Before.Mtime_Sec; S.Mtime_Nsec:=Before.Mtime_Nsec;
            MC_FS.Hash(F,Maximum_Bytes,S.Content,Read_Bytes,Status);
         else S.Node_Kind:=Pkg_File_Plan.Directory; end if;
         if Status=OK then MC_FS.Get_Xattrs(F,X,Used,Status); end if;
         if Status=OK then
            MC_FS.Info(F,After,Status);
            if Status=OK and then After/=Before then Status:=Conflict; end if;
         end if;
         MC_FS.Close(F);
      end if;
      if Status/=OK then return; end if;
      S.Xattrs:=MC_SHA256.Hash(X(1..Used));
      MC_FS.Stat(R,Path,After,Status);
      if Status=OK and then After/=Before then Status:=Conflict; end if;
      if Status=OK and then not Pkg_File_Plan.Valid(S) then Status:=Unsupported; end if;
   exception when others=>MC_FS.Close(F); Status:=IO_Error;
   end Inspect;
end Pkg_Image_Inspector;
