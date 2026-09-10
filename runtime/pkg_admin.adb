-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO; with Ada.Unchecked_Deallocation;
with MC_Types; use MC_Types; with MC_Runtime; with MC_Hex; with MC_Numbers; with MC_FS; with MC_Store;
with MC_Tools; with MC_File_IO; with MC_Text; with MC_Signatures;
with Pkg_File_Engine; with Pkg_File_Plan; with Pkg_RPM_Auth; with Pkg_RPM; with Pkg_RPM_File;
with Pkg_Payload_Map; with Pkg_Archive; with Pkg_Source;
with Pkg_Plan_Compiler;
package body Pkg_Admin with SPARK_Mode => Off is
   use Ada.Command_Line; use Ada.Text_IO;
   procedure No_Execution(Root_ID,Transaction_ID : Identity; Plan,Evidence : Digest; Epoch,Fence : Counter;
      Phase : String; Status : out Outcome) is
      pragma Unreferenced(Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase);
   begin Status:=Denied; end;
   package Engine is new Pkg_File_Engine(No_Execution);
   function Handle return Boolean is
      S : Outcome; Store : MC_Store.Store; Root : MC_FS.Root; F : MC_FS.File;
      D : Digest; ID : Identity; Deadline : Counter; Tool : MC_Tools.Tool;
      Prefix : Pkg_RPM_File.Buffer; M : Pkg_RPM.Metadata;
      type Map_Access is access Pkg_Payload_Map.Inventory; Map : Map_Access:=null;
      type Plan_Access is access Pkg_File_Plan.Plan; Plan : Plan_Access:=null;
      procedure Free is new Ada.Unchecked_Deallocation(Pkg_Payload_Map.Inventory,Map_Access);
      procedure Free_Plan is new Ada.Unchecked_Deallocation(Pkg_File_Plan.Plan,Plan_Access);
      function Cmd(Name : String; N : Natural) return Boolean is
        (Argument_Count=N and then Argument(1)=Name);
      procedure Finish is
      begin
         Pkg_RPM_File.Free(Prefix); if Map/=null then Free(Map); end if; if Plan/=null then Free_Plan(Plan); end if;
         MC_FS.Close(F); MC_FS.Close(Root); MC_Store.Close(Store);
         Put_Line("package-admin=" & Outcome'Image(S)); if S/=OK then Set_Exit_Status(Failure); end if;
      end;
      procedure Stage(Tools_Dir,Keyring : String) is
      begin
         MC_Tools.Load(Tools_Dir,"rpmkeys",Tool,S); if S/=OK then return; end if;
         Pkg_RPM_Auth.Verify(Tool,Keyring,Store,D,Deadline,S); if S/=OK then return; end if;
         MC_Store.Open_Object(Store,D,F,S); if S/=OK then return; end if;
         Pkg_RPM_File.Read_Headers(F,Prefix,M,S); MC_FS.Close(F); if S/=OK then return; end if;
         Map:=new Pkg_Payload_Map.Inventory; Pkg_Payload_Map.Decode(Prefix.all,M,Map.all,S); if S/=OK then return; end if;
         Pkg_Archive.Stage(Store,D,Map.all,Deadline,S);
         if S=OK then
            Put_Line("rpm=" & MC_Hex.Encode(D)); Put_Line("payload-members=" & Natural'Image(Map.Count));
            Put_Line("arbitrary-scriptlets-executed=false host-files-modified=false");
            Put_Line("rpm-has-hooks=" & Boolean'Image(M.Has_Executable_Hooks));
         end if;
      end;
   begin
      if not (Cmd("provision-store",2) or else Cmd("provision-root",4) or else Cmd("cas-import",3) or else Cmd("check-plan",2)
        or else Cmd("compile-plan",3) or else Cmd("stage-rpm",6) or else Cmd("fetch-rpm",9)) then return False; end if;
      MC_Runtime.Initialize(S); if S/=OK then Finish; return True; end if;
      if Cmd("provision-store",2) then
         if Argument(2)="/" then S:=Denied;
         else MC_Store.Initialize(Argument(2),Store,S); end if;
      elsif Cmd("provision-root",4) then
         if Argument(2)="/" then S:=Denied;
         else MC_Hex.Decode(Argument(4),ID,S); if S=OK then Engine.Provision(Argument(2),Argument(3),ID,S); end if; end if;
      elsif Cmd("cas-import",3) then
         MC_Store.Open(Argument(2),Store,S); if S/=OK then Finish; return True; end if;
         declare Path : constant String:=Argument(3); Split : Natural:=0; begin
            for I in Path'Range loop if Path(I)='/' then Split:=I; end if; end loop;
            if Path'Length<2 or else Path(1)/='/' or else Split=Path'Last then S:=Invalid_Input;
            else
               MC_FS.Open_Root((if Split=1 then "/" else Path(1..Split-1)),Root,S);
               if S=OK then MC_FS.Open_Read(Root,Path(Split+1..Path'Last),F,S); end if;
               if S=OK then MC_Store.Import_File(Store,F,MC_Store.Max_Object_Size,D,S); end if;
            end if;
         end;
         if S=OK then Put_Line("object=" & MC_Hex.Encode(D)); end if;
      elsif Cmd("compile-plan",3) then
         Pkg_Plan_Compiler.Compile(Argument(2),Argument(3),D,S);
         if S=OK then Put_Line("plan-sha256=" & MC_Hex.Encode(D)); end if;
      elsif Cmd("check-plan",2) then
         Plan:=new Pkg_File_Plan.Plan;
         Pkg_File_Plan.Decode(MC_File_IO.Read_File(Argument(2),Pkg_File_Plan.Max_Plan_Bytes),Plan.all,S);
         if S=OK then Put_Line("change-count=" & Natural'Image(Plan.Count)); Put_Line("authorization-checked=false"); end if;
      elsif Cmd("stage-rpm",6) then
         MC_Store.Open(Argument(2),Store,S); if S=OK then MC_Hex.Decode(Argument(3),D,S); end if;
         if S=OK then MC_Numbers.Parse(Argument(6),Deadline,S); end if;
         if S=OK then Stage(Argument(4),Argument(5)); end if;
      else
         MC_Store.Open(Argument(2),Store,S);
         if S=OK then MC_Numbers.Parse(Argument(7),Deadline,S); end if;
         if S=OK then
            declare
               Grant : constant Bytes:=MC_File_IO.Read_File(Argument(5),4_256);
               Signature : constant Bytes:=MC_File_IO.Read_File(Argument(6),64);
            begin
               if Signature'Length/=64 then S:=Invalid_Input;
               else Pkg_Source.Fetch(Argument(3),Argument(4),Grant,MC_Signatures.Signature(Signature),Deadline,Store,D,S); end if;
            end;
         end if;
         if S=OK then Stage(Argument(8),Argument(9)); end if;
      end if;
      Finish; return True;
   exception when others=>S:=Indeterminate; Finish; return True;
   end;
end Pkg_Admin;
