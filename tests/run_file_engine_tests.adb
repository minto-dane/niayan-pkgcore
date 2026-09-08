-- SPDX-License-Identifier: MIT
-- Runtime integration suite. Run ONLY in fresh directories created by the harness.
-- The test authorizer is deliberately not shipped as a runtime site adapter.
with Ada.Command_Line; with Interfaces.C;
with MC_Hex;
with MC_Types; use MC_Types; with MC_Runtime; with MC_FS; with MC_Store; with MC_Text; with MC_SHA256;
with Pkg_File_Plan; with Pkg_File_Engine; with Pkg_Recovery_Audit;
with Test_Support; use Test_Support;
procedure Run_File_Engine_Tests with SPARK_Mode=>Off is
   function Euid return Interfaces.C.unsigned with Import,Convention=>C,External_Name=>"geteuid";
   function Egid return Interfaces.C.unsigned with Import,Convention=>C,External_Name=>"getegid";
   Allowed_Root : constant Identity:=(others=>11);
   procedure Authorize(Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch,Fence : Counter; Phase : String; Status : out Outcome) is
   begin
      Status:=Denied;
      if Root_ID=Allowed_Root and then Transaction_ID/=Zero_Identity and then Plan/=Zero_Digest
        and then Epoch=1 and then Fence=1 and then Phase'Length>0
        and then (Phase not in "commit" | "restore" or else Evidence/=Zero_Digest) then Status:=OK; end if;
   end;
   package Engine is new Pkg_File_Engine(Authorize);
   use type Engine.Actual_Image;
   use type MC_FS.Entry_Kind;
   use type Pkg_Recovery_Audit.Finding;
   C : Engine.Context; Store : MC_Store.Store; S : Outcome; D1,D2,Attrs,Receipt,Plan_Digest : Digest;
   type Plan_Access is access Pkg_File_Plan.Plan;
   P : constant Plan_Access := new Pkg_File_Plan.Plan; Data : Bytes(1..16_384); Used : Natural; Actual : Engine.Actual_Image;
   Audit : Pkg_Recovery_Audit.Report;
   procedure Need(Label_Text : String) is begin Expect(S=OK,Label_Text & Outcome'Image(S)); end;
   procedure Start is
   begin
      Engine.Open(Ada.Command_Line.Argument(1),Ada.Command_Line.Argument(2),Ada.Command_Line.Argument(3),Allowed_Root,C,S); Need("open");
   end;
begin
   Expect(Ada.Command_Line.Argument_Count=3,"three-private-directories"); MC_Runtime.Initialize(S); Need("runtime");
   MC_Store.Initialize(Ada.Command_Line.Argument(3),Store,S); Need("store");
   MC_Store.Put(Store,Bytes'(97,98,99),D1,S); Need("content-one");
   MC_Store.Put(Store,Bytes'(120,121,122),D2,S); Need("content-two");
   MC_Store.Put(Store,Bytes'(0,0),Attrs,S); Need("empty-xattrs");
   MC_Store.Put(Store,Bytes'(9,8,7),Receipt,S); Need("test-only-evidence"); MC_Store.Close(Store);
   Engine.Provision(Ada.Command_Line.Argument(1),Ada.Command_Line.Argument(2),Allowed_Root,S); Need("provision");
   P.Root_ID:=Allowed_Root; P.Transaction_ID:=(others=>1); P.Target_Generation:=1; P.Epoch:=1; P.Fence:=1;
   P.Package_Set:=(others=>2); P.Effect_Contract:=(others=>3); P.Count:=1;
   MC_Text.Set(P.Changes(1).Path,"usr/payload",S); Need("path");
   P.Changes(1).After:=(Node_Kind=>Pkg_File_Plan.Regular,Mode=>8#644#,UID=>Word(Euid),GID=>Word(Egid),
      Size=>3,Content=>D1,Xattrs=>Attrs,others=><>);
   Pkg_File_Plan.Encode(P.all,Data,Used,S); Need("encode"); Plan_Digest:=MC_SHA256.Hash(Data(1..Used));
   Start; Engine.Prepare(C,Data(1..Used),Plan_Digest,S); Need("prepare");
   Engine.Close(C);
   -- A missing lock inode is not a license to create an independent new lock.
   declare State_Root : MC_FS.Root; V : MC_FS.Entry_Info; begin
      MC_FS.Open_Root(Ada.Command_Line.Argument(2),State_Root,S,Private_Only=>True); Need("test state directory");
      MC_FS.Rename(State_Root,"root.lock","retained-root-lock",True,S); Need("preserve lock fixture");
      Engine.Open(Ada.Command_Line.Argument(1),Ada.Command_Line.Argument(2),Ada.Command_Line.Argument(3),Allowed_Root,C,S);
      Expect(S=Corrupt,"missing writer lock refused"); Engine.Close(C);
      MC_FS.Stat(State_Root,"root.lock",V,S); Need("absent lock observation");
      Expect(V.Kind=MC_FS.Absent,"no replacement lock created");
      MC_FS.Rename(State_Root,"retained-root-lock","root.lock",True,S); Need("restore lock fixture");
      MC_FS.Close(State_Root);
   exception when others => MC_FS.Close(State_Root); raise;
   end;
   -- Simulate a missing journal only in this fresh private test workspace.
   -- Neither metadata inspection nor Resume may create an empty replacement.
   declare
      State_Root : MC_FS.Root; Info : MC_FS.Entry_Info;
      Name : constant String := "tx-" & MC_Hex.Encode(P.Transaction_ID) & ".log";
   begin
      MC_FS.Open_Root(Ada.Command_Line.Argument(2),State_Root,S,Private_Only=>True); Need("open test state");
      MC_FS.Rename(State_Root,Name,"retained-test-log",True,S); Need("retain journal fixture");
      Pkg_Recovery_Audit.Inspect(Ada.Command_Line.Argument(2),Ada.Command_Line.Argument(3),Plan_Digest,Audit,S);
      Expect(S=Corrupt and then Audit.Result=Pkg_Recovery_Audit.Missing_Journal,"audit detects missing journal");
      Start; Engine.Resume(C,S); Expect(S=Corrupt,"resume refuses missing journal"); Engine.Close(C);
      MC_FS.Stat(State_Root,Name,Info,S); Need("inspect absence");
      Expect(Info.Kind=MC_FS.Absent,"resume and audit did not create empty journal");
      MC_FS.Rename(State_Root,"retained-test-log",Name,True,S); Need("restore exact test journal");
      MC_FS.Close(State_Root);
   exception when others => MC_FS.Close(State_Root); raise;
   end;
   Start; Engine.Resume(C,S); Need("resume prepared plan");
   Engine.Apply(C,S); Need("apply-real-files"); Engine.Inspect(C,Actual,S); Need("inspect");
   Expect(Actual=Engine.All_After,"observed-postimage"); Engine.Close(C);
   Start; Engine.Resume(C,S); Need("reopen-before-commit"); Engine.Commit(C,Receipt,S); Need("commit");
   Expect(Engine.Generation(C)=1 and then not Engine.Has_Active_Change(C),"generation-one"); Engine.Close(C);
   Pkg_Recovery_Audit.Inspect(Ada.Command_Line.Argument(2),Ada.Command_Line.Argument(3),Plan_Digest,Audit,S);
   Need("read-only recovery audit");
   Expect(not Audit.Physical_Files_Checked and then not Audit.Trust_Checked,"audit cannot certify live recovery");
   -- A lost commit response must be reconciled without applying the plan twice.
   Start; Engine.Resume_Recorded(C,Plan_Digest,S); Need("archived-terminal");
   Engine.Reconcile_Terminal(C,S); Need("lost-response-reconcile"); Engine.Close(C);
   P.Transaction_ID:=(others=>4); P.Base_Generation:=1; P.Target_Generation:=2;
   P.Changes(1).Before:=P.Changes(1).After; P.Changes(1).After.Content:=D2;
   Pkg_File_Plan.Encode(P.all,Data,Used,S); Need("encode-second"); Plan_Digest:=MC_SHA256.Hash(Data(1..Used));
   Start; Engine.Prepare(C,Data(1..Used),Plan_Digest,S); Need("prepare-second"); Engine.Apply(C,S); Need("apply-second");
   Engine.Close(C); Start; Engine.Resume(C,S); Need("reopen-before-restore");
   Engine.Restore(C,Receipt,S); Need("restore-real-preimage");
   Expect(Engine.Generation(C)=1,"restore-does-not-advance-generation"); Engine.Close(C);
   Start; Engine.Resume_Recorded(C,Plan_Digest,S); Need("restored-terminal"); Engine.Inspect(C,Actual,S); Need("restored-inspect");
   Expect(Actual=Engine.All_Before,"restored-content-and-attributes"); Engine.Reconcile_Terminal(C,S); Need("restore-reconcile"); Engine.Close(C);
   Report;
exception when others=>Engine.Close(C); MC_Store.Close(Store); raise;
end Run_File_Engine_Tests;
