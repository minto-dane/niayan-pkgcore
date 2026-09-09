-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Atomic; with MC_Clock; with MC_Dirents; with MC_FS; with MC_Posix; with MC_SHA256; with MC_Store;
with Pkg_Catalog_Store; with Pkg_Catalog_Retention; with Pkg_File_Engine; with Pkg_File_Plan; with Pkg_File_Replay;
with Pkg_Generation_Manifest; with Pkg_Generation_Stage; with Pkg_Recovery_Audit; with Pkg_Root_State;
package body Pkg_Generation_Publisher with SPARK_Mode => Off is
   package GD renames Pkg_Generation_Descriptor;
   package GM renames Pkg_Generation_Manifest;
   package Staging is new Pkg_Generation_Stage (Authorize_Stage);
   use type Interfaces.C.unsigned; use type Interfaces.C.int; use type Wide; use type Word;
   use type Pkg_Root_State.State;
   use type GD.Descriptor; use type Pkg_File_Replay.Direction;
   type Plan_Access is access Pkg_File_Plan.Plan;
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_File_Plan.Plan, Plan_Access);
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Read_State (Root, State : MC_FS.Root; Expected_Root : Identity;
      RS : out Pkg_Root_State.State; Status : out Outcome) is
      Frame : Pkg_Root_State.Frame; Marker : Bytes (1 .. 16); Used : Natural;
   begin
      RS := (others => <>); MC_Atomic.Read (Root, ".mission/root.id", Marker, Used, Status);
      if Status = OK and then (Used /= 16 or else Marker /= Expected_Root) then Status := Denied; end if;
      if Status = OK then MC_Atomic.Read (State, "root.state", Frame, Used, Status); end if;
      if Status = OK and then Used /= Frame'Length then Status := Corrupt; end if;
      if Status = OK then Pkg_Root_State.Decode (Frame, RS, Status); end if;
      if Status = OK and then RS.Root_ID /= Expected_Root then Status := Denied; end if;
      if Status = OK and then RS.Generation = 0
        and then (RS.Accepted_Plan /= Zero_Digest or else RS.Package_Set /= Zero_Digest)
      then Status := Corrupt; end if;
   end Read_State;
   procedure Read_Plan (Store : MC_Store.Store; Hash : Digest; P : out Pkg_File_Plan.Plan; Status : out Outcome) is
      B : Buffer_Access := new Bytes (1 .. Pkg_File_Plan.Max_Plan_Bytes); Used : Natural;
   begin
      MC_Store.Read_Object (Store, Hash, B.all, Used, Status);
      if Status = OK then Pkg_File_Plan.Decode (B (1 .. Used), P, Status); end if;
      Free (B);
   exception when others => Free (B); Status := Indeterminate;
   end Read_Plan;
   procedure Read_Manifest (Store : MC_Store.Store; D : GD.Descriptor; M : out GM.Manifest; Status : out Outcome) is
      B : Bytes (1 .. GM.Max_Bytes); Used : Natural;
   begin
      M := (others => <>); MC_Store.Read_Object (Store, D.Manifest, B, Used, Status);
      if Status = OK then GM.Decode (B (1 .. Used), M, Status); end if;
      if Status = OK and then (M.Stage_ID /= D.Stage_ID or else M.Catalog /= D.Catalog) then Status := Conflict; end if;
      if Status = OK then MC_Store.Check_Pin (Store, M.Transaction_ID, D.Manifest, Status); end if;
   end Read_Manifest;
   procedure Provision (Root_Path, State_Path : String; Root_ID : Identity;
      Bootstrap_Grant : Digest; Status : out Outcome) is
      Root, State : MC_FS.Root; Lock : MC_FS.File; Names : MC_Dirents.Listing; A, B : MC_FS.Entry_Info;
      procedure Done is
      begin MC_FS.Close (Lock); MC_FS.Close (State); MC_FS.Close (Root); end Done;
   begin
      Status := Denied;
      if MC_Posix.Euid = 0 or else Root_ID = Zero_Identity or else Bootstrap_Grant = Zero_Digest then return; end if;
      Authorize_Bootstrap (Root_ID, Bootstrap_Grant, Status); if Status /= OK then return; end if;
      MC_FS.Open_Root (Root_Path, Root, Status, Private_Only => True);
      if Status = OK then MC_FS.List_Names (Root, "", Names, Status); end if;
      if Status = OK and then Names.Count /= 0 then Status := Conflict; end if;
      if Status = OK then MC_FS.Open_Root (State_Path, State, Status, Private_Only => True); end if;
      if Status = OK then MC_FS.List_Names (State, "", Names, Status); end if;
      if Status = OK and then Names.Count /= 0 then Status := Conflict; end if;
      if Status = OK then MC_FS.Root_Info (Root, A, Status); end if;
      if Status = OK then MC_FS.Root_Info (State, B, Status); end if;
      if Status = OK and then A.Inode = B.Inode and then A.Mount_ID = B.Mount_ID then Status := Conflict; end if;
      if Status = OK then MC_FS.Create_New (State, "publication.lock", Lock, Status); end if;
      if Status = OK and then MC_Posix.Flock (Interfaces.C.int (MC_FS.Native (Lock)), MC_Posix.LOCK_EX_NB) /= 0 then Status := Conflict; end if;
      if Status = OK then MC_FS.Sync (Lock, Status); end if;
      if Status = OK then MC_FS.Sync_Parent (State, "publication.lock", Status); end if;
      if Status = OK then Authorize_Bootstrap (Root_ID, Bootstrap_Grant, Status); end if;
      if Status = OK then Managed.Engine.Provision (Root_Path, State_Path, Root_ID, Status); end if;
      Done;
   exception when others => Done; Status := Indeterminate;
   end Provision;
   type Observation_Context is limited record
      Root, State : MC_FS.Root;
      Lock, Root_Lock : MC_FS.File;
      Store : MC_Store.Store;
      Accepted : Pkg_Root_State.State;
      Bound : GD.Descriptor := GD.Empty;
      Image : GM.Manifest;
   end record;
   procedure Close_Observation (C : in out Observation_Context) is
   begin
      MC_Store.Close (C.Store); MC_FS.Close (C.Root_Lock); MC_FS.Close (C.Lock);
      MC_FS.Close (C.State); MC_FS.Close (C.Root); C.Bound := GD.Empty; C.Accepted := (others => <>); C.Image := (others => <>);
   end Close_Observation;
   procedure Observe_And_Lock (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      C : in out Observation_Context; Status : out Outcome) is
      Before, After : GD.Descriptor; M : GM.Manifest;
      P : Plan_Access := null; Audit : Pkg_Recovery_Audit.Report;
   begin
      Close_Observation (C); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      MC_FS.Open_Root (State_Path, C.State, Status, Private_Only => True);
      if Status = OK then MC_FS.Open_Locked (C.State, "publication.lock", C.Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then MC_FS.Open_Locked (C.State, "root.lock", C.Root_Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then MC_FS.Open_Root (Root_Path, C.Root, Status, Private_Only => True); end if;
      if Status = OK then Read_State (C.Root, C.State, Root_ID, C.Accepted, Status); end if;
      if Status /= OK then return; end if;
      if C.Accepted.Active_Transaction /= Zero_Identity then Status := Indeterminate; return; end if;
      if C.Accepted.Generation = 0 then Status := Stale; return; end if;
      MC_Store.Open (Store_Path, C.Store, Status); P := new Pkg_File_Plan.Plan;
      if Status = OK then Read_Plan (C.Store, C.Accepted.Accepted_Plan, P.all, Status); end if;
      if Status = OK then GD.Check (C.Store, P.all, Before, After, Status); end if;
      if Status = OK and then (After.Root_ID /= Root_ID or else After.Generation /= C.Accepted.Generation
        or else After.Catalog /= C.Accepted.Package_Set) then Status := Conflict; end if;
      if Status = OK then Read_Manifest (C.Store, After, M, Status); end if;
      if Status = OK and then M.Effect_Contract /= P.Effect_Contract then Status := Conflict; end if;
      if Status = OK then Pkg_Recovery_Audit.Inspect (State_Path, Store_Path, C.Accepted.Accepted_Plan, Audit, Status); end if;
      if Status = OK and then Audit.Log_State.Phase /= Pkg_File_Replay.Forward_Final then Status := Conflict; end if;
      if Status = OK then C.Bound := After; C.Image := M; end if;
      Free (P);
   exception when others => Free (P); C.Bound := GD.Empty; Status := Indeterminate;
   end Observe_And_Lock;
   procedure Read_Current (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Current : out GD.Descriptor; Status : out Outcome) is
      C : Observation_Context;
   begin
      Current := GD.Empty; Observe_And_Lock (Root_Path, State_Path, Store_Path, Root_ID, C, Status);
      if Status = OK then Current := C.Bound; end if;
      Close_Observation (C);
   exception when others => Close_Observation (C); Current := GD.Empty; Status := Indeterminate;
   end Read_Current;
   procedure Read_Current_Catalog (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Deadline : Counter; Current : out GD.Descriptor;
      Value : in out Pkg_Selected_Catalog.Catalog; Payload : in out Pkg_Payload_Index.Index;
      Status : out Outcome) is
      C : Observation_Context; Latest : Pkg_Root_State.State; Now : Counter;
      procedure Clear_Result is
      begin Current := GD.Empty; Pkg_Selected_Catalog.Clear (Value); Pkg_Payload_Index.Clear (Payload); end Clear_Result;
      procedure Check_Time is
      begin
         Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
   begin
      Clear_Result; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Check_Time; if Status /= OK then return; end if;
      Observe_And_Lock (Root_Path, State_Path, Store_Path, Root_ID, C, Status);
      if Status = OK then GM.Check_Retention (C.Store, C.Image, Deadline, Status); end if;
      if Status = OK then Pkg_Catalog_Store.Load (C.Store, C.Bound.Catalog, Deadline, Value, Payload, Status); end if;
      if Status = OK then Read_State (C.Root, C.State, Root_ID, Latest, Status); end if;
      if Status = OK and then Latest /= C.Accepted then Status := Stale; end if;
      if Status = OK then Check_Time; end if;
      if Status = OK then Current := C.Bound; else Clear_Result; end if;
      Close_Observation (C);
   exception when others => Close_Observation (C); Clear_Result; Status := Indeterminate;
   end Read_Current_Catalog;
   procedure Read_Current_Transition
     (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Expected_Current, Target_Catalog, Target_Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Deadline : Counter; Current : out GD.Descriptor;
      Result : in out Pkg_Deb_Transition.Plan; Binding : out Digest;
      Issue : out Pkg_Deb_Transition.Finding; Status : out Outcome) is
      C : Observation_Context; Latest : Pkg_Root_State.State;
      Before, After : Pkg_Selected_Catalog.Catalog; Payload : Pkg_Payload_Index.Index;
      Wire : Bytes (1 .. 136) := (others => 0);
      use type Pkg_Deb_Transition.Failure_Kind;
      procedure Clear_Result is
      begin
         Current := GD.Empty; Pkg_Deb_Transition.Clear (Result); Binding := Zero_Digest;
         if Issue.Kind = Pkg_Deb_Transition.None then Issue := (others => <>); end if;
      end Clear_Result;
      procedure Check_Time is
         Now : Counter;
      begin
         Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
   begin
      Issue := (others => <>); Clear_Result; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Check_Time; if Status /= OK then return; end if;
      if Expected_Current = Zero_Digest or else Target_Catalog = Zero_Digest or else Target_Closure = Zero_Digest
      then Status := Invalid_Input; return; end if;
      Observe_And_Lock (Root_Path, State_Path, Store_Path, Root_ID, C, Status);
      if Status = OK and then MC_SHA256.Hash (GD.Encode (C.Bound)) /= Expected_Current then Status := Stale; end if;
      if Status = OK then GM.Check_Retention (C.Store, C.Image, Deadline, Status); end if;
      if Status = OK then Pkg_Catalog_Retention.Verify (C.Store, Target_Catalog, Target_Closure, Deadline, Status); end if;
      if Status = OK then Pkg_Catalog_Store.Load (C.Store, C.Bound.Catalog, Deadline, Before, Payload, Status); end if;
      if Status = OK then Pkg_Catalog_Store.Load (C.Store, Target_Catalog, Deadline, After, Payload, Status); end if;
      if Status = OK then
         Pkg_Deb_Transition.Build (Before, After, Native_Architecture, Enabled, Deadline, Result, Issue, Status);
      end if;
      if Status = OK then Read_State (C.Root, C.State, Root_ID, Latest, Status); end if;
      if Status = OK and then Latest /= C.Accepted then Status := Stale; end if;
      if Status = OK then Check_Time; end if;
      if Status = OK then
         Wire (1 .. 8) := (78, 73, 65, 85, 80, 68, 48, 49);
         Wire (9 .. 40) := Expected_Current; Wire (41 .. 72) := Target_Catalog;
         Wire (73 .. 104) := Target_Closure; Wire (105 .. 136) := Pkg_Deb_Transition.Fingerprint (Result);
         Binding := MC_SHA256.Hash (Wire); Current := C.Bound;
      else Clear_Result; end if;
      Close_Observation (C);
   exception when others => Close_Observation (C); Issue := (others => <>); Clear_Result; Status := Indeterminate;
   end Read_Current_Transition;
   procedure Publish (Root_Path, State_Path, Store_Path, Generation_Bank : String;
      Expected_Plan, Health_Receipt : Digest; Deadline : Counter; Status : out Outcome) is
      Root, State : MC_FS.Root; Lock, Root_Lock : MC_FS.File; Store : MC_Store.Store;
      RS : Pkg_Root_State.State; Before, After, Prior, Discarded : GD.Descriptor; M : GM.Manifest;
      P, Old_Plan : Plan_Access := null; Encoded : Buffer_Access := null; Used : Natural;
      Hold : Staging.Verified_Generation; Audit : Pkg_Recovery_Audit.Report;
      procedure Time_Left (Result : out Outcome) is
         Now : Counter;
      begin
         Result := Invalid_Input; if Deadline = Counter'Last then return; end if;
         MC_Clock.Boottime_Milliseconds (Now, Result);
         if Result = OK and then Now >= Deadline then Result := Stale; end if;
      end Time_Left;
      procedure Guard (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
         Epoch, Fence : Counter; Phase : String; Result : out Outcome) is
      begin
         Result := Denied;
         if P = null or else not Staging.Held (Hold) or else Staging.Manifest (Hold) /= After.Manifest
           or else Root_ID /= P.Root_ID or else Transaction_ID /= P.Transaction_ID or else Plan /= Expected_Plan
           or else Epoch /= P.Epoch or else Fence /= P.Fence
           or else (Evidence /= Zero_Digest and then Evidence /= Health_Receipt)
           or else Phase in "restore" | "repair-journal" then return; end if;
         Time_Left (Result); if Result /= OK then return; end if;
         Managed.Guard (Root_ID, Transaction_ID, Plan, Evidence, Epoch, Fence, Phase, Result);
         if Result = OK then Time_Left (Result); end if;
      end Guard;
      package Engine is new Pkg_File_Engine (Guard);
      C : Engine.Context;
      procedure Done is
      begin
         Engine.Close (C); Staging.Close (Hold); MC_Store.Close (Store);
         MC_FS.Close (Root_Lock); MC_FS.Close (Lock); MC_FS.Close (Root); MC_FS.Close (State);
         Free (P); Free (Old_Plan); Free (Encoded);
      end Done;
   begin
      Status := Denied;
      if MC_Posix.Euid = 0 or else Expected_Plan = Zero_Digest or else Health_Receipt = Zero_Digest then return; end if;
      Time_Left (Status); if Status /= OK then return; end if;
      MC_FS.Open_Root (State_Path, State, Status, Private_Only => True);
      if Status = OK then MC_FS.Open_Locked (State, "publication.lock", Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then MC_FS.Open_Locked (State, "root.lock", Root_Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then MC_FS.Open_Root (Root_Path, Root, Status, Private_Only => True); end if;
      if Status = OK then MC_Store.Open (Store_Path, Store, Status); end if;
      P := new Pkg_File_Plan.Plan; Old_Plan := new Pkg_File_Plan.Plan;
      if Status = OK then Read_Plan (Store, Expected_Plan, P.all, Status); end if;
      if Status = OK then GD.Check (Store, P.all, Before, After, Status); end if;
      if Status = OK and then (P.Changes (1).After.UID /= Word (MC_Posix.Euid)
        or else P.Changes (1).After.GID /= Word (MC_Posix.Egid)) then Status := Denied; end if;
      if Status = OK then Read_Manifest (Store, After, M, Status); end if;
      if Status = OK then GM.Check_Retention (Store, M, Deadline, Status); end if;
      if Status = OK and then (M.Effect_Contract /= P.Effect_Contract or else M.Epoch /= P.Epoch or else M.Fence /= P.Fence
        or else M.Transaction_ID = P.Transaction_ID) then Status := Denied; end if;
      if Status = OK then Read_State (Root, State, P.Root_ID, RS, Status); end if;
      if Status /= OK then Done; return; end if;
      if RS.Generation = P.Base_Generation then
         if RS.Generation = 0 then Prior := GD.Empty;
         else
            Read_Plan (Store, RS.Accepted_Plan, Old_Plan.all, Status);
            if Status = OK then GD.Check (Store, Old_Plan.all, Discarded, Prior, Status); end if;
            if Status = OK and then RS.Package_Set /= Prior.Catalog then Status := Conflict; end if;
            -- Before admitting a new transaction, the preceding accepted
            -- decision must still have its complete journal. During recovery
            -- the active transaction's journal is checked below instead.
            if Status = OK and then RS.Active_Transaction = Zero_Identity then
               Pkg_Recovery_Audit.Inspect (State_Path, Store_Path, RS.Accepted_Plan, Audit, Status);
               if Status = OK and then Audit.Log_State.Phase /= Pkg_File_Replay.Forward_Final then Status := Conflict; end if;
            end if;
         end if;
         if Status = OK and then Prior /= Before then Status := Stale; end if;
      elsif RS.Generation /= P.Target_Generation or else RS.Accepted_Plan /= Expected_Plan
        or else RS.Package_Set /= After.Catalog then Status := Stale;
      end if;
      if Status = OK and then RS.Active_Transaction /= Zero_Identity
        and then (RS.Active_Transaction /= P.Transaction_ID or else RS.Active_Plan /= Expected_Plan) then Status := Conflict; end if;
      Encoded := new Bytes (1 .. Pkg_File_Plan.Max_Plan_Bytes);
      if Status = OK then Pkg_File_Plan.Encode (P.all, Encoded.all, Used, Status); end if;
      MC_Store.Close (Store); MC_FS.Close (Root_Lock);
      if Status /= OK then Done; return; end if;
      declare Path : constant String := GD.Stage_Path (Generation_Bank, After); begin
         Staging.Verify_And_Hold (Path & "/root", Path & "/state", Store_Path, After.Manifest, Hold, Deadline, Status);
      end;
      if Status = OK then Engine.Open (Root_Path, State_Path, Store_Path, P.Root_ID, C, Status); end if;
      if Status = OK and then (Engine.Generation (C) /= RS.Generation or else Engine.Accepted_Plan (C) /= RS.Accepted_Plan
        or else Engine.Has_Active_Change (C) /= (RS.Active_Transaction /= Zero_Identity)) then Status := Stale; end if;
      if Status /= OK then Done; return; end if;
      if RS.Generation = P.Target_Generation then
         Engine.Resume_Recorded (C, Expected_Plan, Status);
         if Status = OK then Engine.Reconcile_Terminal (C, Status); end if;
      else
         if Engine.Has_Active_Change (C) then Engine.Resume_Recorded (C, Expected_Plan, Status);
         else Engine.Prepare (C, Encoded (1 .. Used), Expected_Plan, Status); end if;
         if Status = OK then Pkg_Recovery_Audit.Inspect (State_Path, Store_Path, Expected_Plan, Audit, Status); end if;
         if Status = OK then
            case Audit.Log_State.Phase is
               when Pkg_File_Replay.Forward | Pkg_File_Replay.Ready_To_Commit => Engine.Apply (C, Status);
               when Pkg_File_Replay.Commit_Pending => null;
               when others => Status := Conflict;
            end case;
         end if;
         if Status = OK then Engine.Commit (C, Health_Receipt, Status); end if;
      end if;
      Done;
   exception when others => Done; Status := Indeterminate;
   end Publish;
end Pkg_Generation_Publisher;
