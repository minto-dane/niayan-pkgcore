-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Text_IO; with Ada.Unchecked_Deallocation;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Layout; with MC_Text; with MC_Hex; with MC_Protocol; with MC_Requests;
with MC_Request_Files; with MC_Signatures; with MC_Gate; with MC_FS; with MC_Atomic; with MC_SHA256; with MC_Store;
with Pkg_File_Plan; with Pkg_File_Engine;
procedure Pkg_Worker with SPARK_Mode => Off is
   use Ada.Command_Line; use Ada.Text_IO; use type MC_Gate.Admission; use type MC_Requests.Requested_Action;
   Layout : MC_Layout.Layout; Gate : MC_Gate.Session; Header : MC_Protocol.Frame_Header;
   Body_Data : MC_Requests.Request_Bytes; Sig : MC_Signatures.Signature; W : MC_Gate.Witness_Set;
   Request : MC_Requests.Request; H : MC_Protocol.Header; Mode : MC_Gate.Admission;
   Request_ID : Identity; S,Final : Outcome:=Invalid_Input; Spool : MC_FS.Root;
   type Buffer_Access is access Bytes; Data : Buffer_Access:=null;
   type Plan_Access is access Pkg_File_Plan.Plan; P : Plan_Access:=null;
   procedure Free is new Ada.Unchecked_Deallocation(Bytes,Buffer_Access);
   procedure Free_Plan is new Ada.Unchecked_Deallocation(Pkg_File_Plan.Plan,Plan_Access);
   Used : Natural; Store : MC_Store.Store; Digest_Of_Object : Digest;
   Path : MC_Text.Value; Registered : Boolean:=False;
   procedure Authorize(Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome) is
      Fresh_H : MC_Protocol.Frame_Header; Fresh_B : MC_Requests.Request_Bytes; Fresh_Sig : MC_Signatures.Signature;
      Fresh_W : MC_Gate.Witness_Set;
   begin
      -- Fresh witnesses may renew the same bounded grant. The signed request itself
      -- is immutable. A changed envelope cannot be used as a mid-operation shortcut.
      MC_Request_Files.Load(MC_Text.Image(Path),Fresh_H,Fresh_B,Fresh_Sig,Fresh_W,Status);
      if Status/=OK then return; end if;
      if Fresh_H/=Header or else Fresh_B/=Body_Data or else Fresh_Sig/=Sig then Status:=Conflict; return; end if;
      MC_Gate.Refresh_Witnesses(Gate,Fresh_W);
      MC_Gate.Check(Gate,Root_ID,Transaction_ID,Plan,Evidence,Epoch,Fence,Phase,Status);
   end;
   package Engine is new Pkg_File_Engine(Authorize);
   Context : Engine.Context;
   procedure Finish is
   begin
      -- An active transaction plus a failed operation is not known-no-effect.
      -- Preserve the pending receipt until an explicit recovery request resolves it.
      if Registered and then S/=OK and then Engine.Has_Active_Change(Context) then S:=Indeterminate; end if;
      Engine.Close(Context); MC_Store.Close(Store); MC_FS.Close(Spool);
      if Registered then
         MC_Gate.Finish(Gate,S,Final); if Final/=OK then S:=Indeterminate; end if;
      end if;
      MC_Gate.Close(Gate);
      if Data/=null then Free(Data); end if; if P/=null then Free_Plan(P); end if;
      Put_Line("package-worker outcome=" & Outcome'Image(S) & " qualification=NOT_ESTABLISHED");
      if S/=OK then Set_Exit_Status(Failure); end if;
   end;
begin
   if Argument_Count/=2 then Put_Line("pkg_worker POLICY-DIRECTORY REQUEST-ID-HEX"); Set_Exit_Status(Failure); return; end if;
   MC_Runtime.Initialize(S); if S/=OK then Finish; return; end if;
   MC_Hex.Decode(Argument(2),Request_ID,S); if S/=OK or else Request_ID=Zero_Identity then Finish; return; end if;
   MC_Layout.Load(Argument(1),True,Layout,S); if S/=OK then Finish; return; end if;
   MC_Text.Set(Path,MC_Text.Image(Layout.Spool) & "/" & MC_Hex.Encode(Request_ID),S); if S/=OK then Finish; return; end if;
   MC_Request_Files.Load(MC_Text.Image(Path),Header,Body_Data,Sig,W,S); if S/=OK then Finish; return; end if;
   MC_Protocol.Decode(Header,H,S); if S/=OK or else H.Request_ID/=Request_ID then S:=Denied; Finish; return; end if;
   MC_Gate.Begin_Request(Argument(1),MC_Text.Image(Layout.Ledger),Header,Body_Data,Sig,W,Gate,Mode,S);
   if S/=OK then Finish; return; end if;
   if Mode/=MC_Gate.New_Request then
      S:=MC_Gate.Receipt_Result(Gate); Put_Line("replay=" & MC_Gate.Admission'Image(Mode) & " effect_reexecuted=false"); Finish; return;
   end if;
   Registered:=True; Request:=MC_Gate.Request(Gate);
   MC_FS.Open_Root(MC_Text.Image(Path),Spool,S,Private_Only=>True); if S/=OK then Finish; return; end if;
   Data:=new Bytes(1..Pkg_File_Plan.Max_Plan_Bytes);
   MC_Atomic.Read(Spool,"plan.bin",Data.all,Used,S); if S/=OK then Finish; return; end if;
   if MC_SHA256.Hash(Data(1..Used))/=Request.Plan_Digest then S:=Denied; Finish; return; end if;
   P:=new Pkg_File_Plan.Plan; Pkg_File_Plan.Decode(Data(1..Used),P.all,S); if S/=OK then Finish; return; end if;
   if P.Transaction_ID/=Request.Transaction_ID or else P.Root_ID/=H.Resource_ID or else P.Base_Generation/=Request.Base_Generation
      or else (Request.Action in MC_Requests.Prepare | MC_Requests.Apply and then P.Package_Set/=Request.Stage_Set_Digest)
   then S:=Denied; Finish; return; end if;
   if Request.Action in MC_Requests.Commit | MC_Requests.Restore then
      MC_Store.Open(MC_Text.Image(Layout.Store),Store,S); if S/=OK then Finish; return; end if;
      for F in W.Present'Range loop
         if W.Present(F) and then MC_SHA256.Hash(W.Statements(F))=Request.Evidence_Digest then
            MC_Store.Put(Store,W.Statements(F),Digest_Of_Object,S); exit;
         end if;
      end loop;
      MC_Store.Close(Store); if S/=OK then Finish; return; end if;
   end if;
   Engine.Open(MC_Text.Image(Layout.Root),MC_Text.Image(Layout.State),MC_Text.Image(Layout.Store),P.Root_ID,Context,S);
   if S/=OK then Finish; return; end if;
   if Request.Action=MC_Requests.Prepare then Engine.Prepare(Context,Data(1..Used),Request.Plan_Digest,S);
   else
      if Request.Action in MC_Requests.Reconcile | MC_Requests.Inspect then
         Engine.Resume_Recorded(Context,Request.Plan_Digest,S);
      else Engine.Resume(Context,S); end if;
      if S/=OK and then not (S=Indeterminate and then Request.Action=MC_Requests.Repair) then Finish; return; end if;
      if Engine.Loaded_Plan(Context)/=Request.Plan_Digest then S:=Denied; Finish; return; end if;
      case Request.Action is
         when MC_Requests.Apply | MC_Requests.Recover => Engine.Apply(Context,S);
         when MC_Requests.Commit => Engine.Commit(Context,Request.Evidence_Digest,S);
         when MC_Requests.Restore => Engine.Restore(Context,Request.Evidence_Digest,S);
         when MC_Requests.Reconcile => Engine.Reconcile_Terminal(Context,S);
         when MC_Requests.Repair => Engine.Repair_Torn_Journal(Context,S);
         when MC_Requests.Inspect =>
            declare Image : Engine.Actual_Image; begin
               Engine.Inspect(Context,Image,S); Put_Line("managed_image=" & Engine.Actual_Image'Image(Image));
            end;
         when others => S:=Unsupported;
      end case;
   end if;
   Finish;
exception when others=>S:=Indeterminate; Finish;
end Pkg_Worker;
