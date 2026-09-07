-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_CLI; with MC_File_IO; with MC_SHA256; with MC_Hex; with MC_Durable;
with Pkg_RPM; with Pkg_Journal; with Pkg_Journal_IO;
with Pkg_Admin;
procedure Pkgctl with SPARK_Mode => Off is
   use Ada.Command_Line; use Ada.Text_IO;
   Status, Close_Status : Outcome;
begin
   if Pkg_Admin.Handle then return; end if;
   if MC_CLI.Handle_Common then return; end if;
   if Argument_Count=1 and then Argument(1)="status" then
      Put_Line("component=pkgcore production_qualified=false host_effects=AUTHORIZED_WORKER_ONLY");
      Put_Line("ada_build=NOT_RUN gnatprove=NOT_RUN");
   elsif Argument_Count=2 and then Argument(1)="inspect-rpm" then
      declare
         Data : constant Bytes := MC_File_IO.Read_File(Argument(2),67_108_864);
         Info : Pkg_RPM.Metadata;
      begin
         Pkg_RPM.Inspect(Data,Info,Status);
         Put_Line("structural_status=" & Outcome'Image(Status));
         Put_Line("artifact_sha256=" & MC_Hex.Encode(MC_SHA256.Hash(Data)));
         Put_Line("authenticated=false installation_authorized=false");
         if Status=OK then
            Put_Line("header_entries=" & Natural'Image(Info.Entry_Count));
            Put_Line("payload_offset=" & Natural'Image(Info.Payload_Offset));
            Put_Line("signature_tag_present=" & Boolean'Image(Info.Has_Signature_Tag));
            Put_Line("executable_hooks_present=" & Boolean'Image(Info.Has_Executable_Hooks));
         else Set_Exit_Status(Failure); end if;
      end;
   elsif Argument_Count=3 and then Argument(1)="journal-inspect" then
      declare
         Directory : MC_Durable.Directory_Handle;
         File : MC_Durable.File_Handle;
         Root : Identity;
         Head : Pkg_Journal.Head;
      begin
         MC_Hex.Decode(Argument(3),Root,Status);
         if Status=OK then MC_Durable.Open_Private_Directory(Argument(2),Directory,Status); end if;
         if Status=OK then MC_Durable.Open_Readonly(Directory,"journal.mcl",File,Status); end if;
         if Status=OK then Pkg_Journal_IO.Scan(File,Root,Head,Status); end if;
         if Status=OK then
            Put_Line("records=" & Counter'Image(Head.Sequence_Number));
            Put_Line("head_sha256=" & MC_Hex.Encode(Head.Last_Digest));
         end if;
         MC_Durable.Close(File,Close_Status);
         if Close_Status/=OK then Status:=Close_Status; end if;
         MC_Durable.Close(Directory,Close_Status);
         if Close_Status/=OK then Status:=Close_Status; end if;
         Put_Line("structural_status=" & Outcome'Image(Status));
         Put_Line("authenticated_anchor_checked=false recovery_authorized=false");
         if Status/=OK then Set_Exit_Status(Failure); end if;
      end;
   elsif Argument_Count>0 and then
     (Argument(1)="install" or else Argument(1)="apply" or else Argument(1)="recover")
   then
      Put_Line(Standard_Error,"LEGACY_DIRECT_CLI_DISABLED: no host mutation or cluster effect is enabled.");
      Set_Exit_Status(78);
   else
      Put_Line("pkgctl status | inspect-rpm FILE | journal-inspect PRIVATE-DIR ROOT-ID-HEX");
      Put_Line("pkgctl contract-vector | check-header FILE | verify-envelope HEADER BODY SIG KEY");
      Set_Exit_Status(Failure);
   end if;
exception
   when others =>
      Put_Line(Ada.Text_IO.Standard_Error,"operation failed; no host mutation was attempted");
      Ada.Command_Line.Set_Exit_Status(Ada.Command_Line.Failure);
end Pkgctl;
