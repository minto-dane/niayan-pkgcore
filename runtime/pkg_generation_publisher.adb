-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Dirents; with MC_FS; with MC_Posix; with MC_SHA256; with MC_Store;
with Pkg_Catalog_Store; with Pkg_File_Engine; with Pkg_File_Plan; with Pkg_File_Replay;
with Pkg_Generation_Manifest; with Pkg_Generation_Stage; with Pkg_Generation_Intent;
with Pkg_Generation_Storage; with Pkg_Generation_Reader;
with Pkg_Recovery_Audit; with Pkg_Root_State; with Pkg_Supply_Map;
package body Pkg_Generation_Publisher with SPARK_Mode => Off is
   use Pkg_Generation_Storage;
   package GD renames Pkg_Generation_Descriptor;
   package GM renames Pkg_Generation_Manifest;
   package Staging is new Pkg_Generation_Stage (Authorize_Stage, Observe_Configuration_Source);
   use type Interfaces.C.unsigned; use type Interfaces.C.int; use type Wide; use type Word;
   use type Pkg_Root_State.State;
   use type Pkg_Supply_Map.Authorities;
   use type GD.Descriptor; use type GM.Format_Kind; use type Pkg_File_Replay.Direction;
   type Plan_Access is access Pkg_File_Plan.Plan;
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_File_Plan.Plan, Plan_Access);
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
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
   procedure Read_Current (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Current : out GD.Descriptor; Status : out Outcome)
      renames Pkg_Generation_Reader.Read_Current;
   procedure Read_Current_Catalog (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Deadline : Counter; Current : out GD.Descriptor;
      Value : in out Pkg_Selected_Catalog.Catalog; Payload : in out Pkg_Payload_Index.Index;
      Status : out Outcome) renames Pkg_Generation_Reader.Read_Current_Catalog;
   procedure Read_Current_Transition
     (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Expected_Current, Target_Catalog, Target_Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Deadline : Counter; Current : out GD.Descriptor;
      Result : in out Pkg_Deb_Transition.Plan; Binding : out Digest;
      Issue : out Pkg_Deb_Transition.Finding; Status : out Outcome)
      renames Pkg_Generation_Reader.Read_Current_Transition;
   procedure Publish (Root_Path, State_Path, Store_Path, Generation_Bank : String;
      Expected_Plan, Health_Receipt : Digest; Deadline : Counter; Status : out Outcome) is
      Root, State : MC_FS.Root; Lock, Root_Lock : MC_FS.File; Store : MC_Store.Store;
      RS : Pkg_Root_State.State; Before, After, Prior, Discarded : GD.Descriptor; M, Baseline : GM.Manifest;
      Before_Closure, Native_Binding : Digest := Zero_Digest;
      Supply_Target : Pkg_Supply_Map.Context;
      Supply_Value : Pkg_Supply_Policy.Snapshot;
      Supply_Until, Last_Supply_Now : Counter := 0;
      Recorded, Supply_Checked, Accepted_Terminal, Source_Checked : Boolean := False;
      P, Old_Plan : Plan_Access := null; Encoded : Buffer_Access := null; Used : Natural;
      Saved_Hold : Staging.Retained_Generation;
      Hold : Staging.Verified_Generation; Audit : Pkg_Recovery_Audit.Report;
      procedure Time_Left (Result : out Outcome) is
         Now : Counter;
      begin
         Result := Invalid_Input; if Deadline = Counter'Last then return; end if;
         MC_Clock.Boottime_Milliseconds (Now, Result);
         if Result = OK and then Now >= Deadline then Result := Stale; end if;
      end Time_Left;
      procedure Check_Supply_Policy (Value : out Pkg_Supply_Policy.Snapshot; Result : out Outcome) is
         Started, Finished, Elapsed, Current : Counter;
      begin
         MC_Clock.Boottime_Milliseconds (Started, Result); if Result /= OK then return; end if;
         Observe_Supply (P.Root_ID, P.Transaction_ID, Expected_Plan, M.Supply_Policy, Value, Result);
         if Result /= OK then return; end if;
         if Value.Map /= Supply_Value.Map or else Value.Count /= Supply_Value.Count
           or else Value.Trusted (1 .. Value.Count) /= Supply_Value.Trusted (1 .. Supply_Value.Count)
         then Result := Denied; return; end if;
         if Value.Observed_At not in 1 .. 2 ** 53 - 1 or else Value.Observed_At < Last_Supply_Now
           or else Value.Observed_At < Supply_Value.Observed_At then Result := Stale; return; end if;
         MC_Clock.Boottime_Milliseconds (Finished, Result); if Result /= OK then return; end if;
         if Finished < Started then Result := Stale; return; end if;
         Elapsed := (Finished - Started) / 1_000;
         if (Finished - Started) mod 1_000 /= 0 then Elapsed := Elapsed + 1; end if;
         if Elapsed > 2 ** 53 - 1 - Value.Observed_At then Result := Stale; return; end if;
         Current := Value.Observed_At + Elapsed;
         if not Recorded and then Supply_Until /= 0 and then Current >= Supply_Until then Result := Stale; return; end if;
         Last_Supply_Now := Value.Observed_At; Value.Observed_At := Current; Time_Left (Result);
      end Check_Supply_Policy;
      function Stage_Held return Boolean is
        (if M.Format = GM.Configured_V6 and then Accepted_Terminal then
           Staging.Retained_Held (Saved_Hold) and then Staging.Retained_Manifest (Saved_Hold) = After.Manifest
         else Staging.Held (Hold) and then Staging.Manifest (Hold) = After.Manifest);
      procedure Guard (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
         Epoch, Fence : Counter; Phase : String; Result : out Outcome) is
         Current_Policy : Pkg_Supply_Policy.Snapshot;
      begin
         Result := Denied;
         if P = null or else Native_Binding = Zero_Digest or else not Supply_Checked
           or else not Stage_Held
           or else (M.Format = GM.Configured_V6 and then
             (if Accepted_Terminal then Phase /= "finish-terminal" else not Source_Checked))
           or else Root_ID /= P.Root_ID or else Transaction_ID /= P.Transaction_ID or else Plan /= Expected_Plan
           or else Epoch /= P.Epoch or else Fence /= P.Fence
           or else (Evidence /= Zero_Digest and then Evidence /= Health_Receipt)
           or else Phase in "restore" | "repair-journal" then return; end if;
         Time_Left (Result); if Result /= OK then return; end if;
         Check_Supply_Policy (Current_Policy, Result); if Result /= OK then return; end if;
         Managed.Guard (Root_ID, Transaction_ID, Plan, Evidence, Epoch, Fence, Phase, Result);
         if Result = OK then Check_Supply_Policy (Current_Policy, Result); end if;
      end Guard;
      package Engine is new Pkg_File_Engine (Guard);
      C : Engine.Context;
      procedure Validate_Inputs (Locked_Store : in out MC_Store.Store; Result : out Outcome) is
         Latest : Pkg_Root_State.State; Checked_Before, Checked_After : GD.Descriptor;
         Checked_Image : GM.Manifest; Current_Policy : Pkg_Supply_Policy.Snapshot;
         Source_FD : Integer := -1;
      begin
         Native_Binding := Zero_Digest; Supply_Checked := False; Source_Checked := False;
         Read_State (Root, State, P.Root_ID, Latest, Result);
         if Result = OK and then Latest /= RS then Result := Stale; end if;
         if Result = OK then GD.Check (Locked_Store, P.all, Checked_Before, Checked_After, Result); end if;
         if Result = OK and then (Checked_Before /= Before or else Checked_After /= After) then Result := Conflict; end if;
         if Result = OK then Read_Manifest (Locked_Store, After, Checked_Image, Result); end if;
         if Result = OK then GM.Check_Retention (Locked_Store, Checked_Image, Deadline, Result); end if;
         if Result = OK and then Before /= GD.Empty then
            Read_Manifest (Locked_Store, Before, Checked_Image, Result);
            if Result = OK then GM.Check_Retention (Locked_Store, Checked_Image, Deadline, Result); end if;
         end if;
         if Result = OK then
            Pkg_Generation_Intent.Verify (Locked_Store, M.Intent, P.Root_ID, Before, Before_Closure,
               M.Catalog, M.Catalog_Closure, Deadline, Native_Binding, Result);
         end if;
         if Result = OK and then Recorded then
            -- An orphan Prepared log is not an admitted transaction. Historical
            -- policy is considered only for the exact actual active/accepted
            -- root state, after checking the complete journal under this lock.
            Pkg_Recovery_Audit.Inspect (State_Path, Store_Path, Expected_Plan, Audit, Result);
         end if;
         if Result = OK and then M.Format = GM.Configured_V6 then
            if Accepted_Terminal then
               -- Actual accepted state was rechecked above under engine locks;
               -- the complete exact publication journal must still qualify it.
               if not Recorded or else Latest.Generation /= P.Target_Generation
                 or else Latest.Accepted_Plan /= Expected_Plan or else Latest.Package_Set /= After.Catalog
                 or else Audit.Log_State.Phase not in Pkg_File_Replay.Commit_Pending | Pkg_File_Replay.Forward_Final
               then Result := Conflict; end if;
            else
               Observe_Configuration_Source (After.Manifest, P.Root_ID, M.Transaction_ID, M.Intent,
                  "publication:configuration", Source_FD, Result);
               if Result = OK then
                  Pkg_Generation_Configuration.Check_Current (Locked_Store, M, Source_FD, Deadline, Result);
               end if;
               Source_Checked := Result = OK;
            end if;
         end if;
         if Result = OK then
            Supply_Target := (P.Root_ID, Before, Before_Closure, M.Catalog, M.Catalog_Closure);
            Pkg_Supply_Policy.Load (Locked_Store, M.Supply_Policy, Deadline, Supply_Value, Result);
         end if;
         if Result = OK then Check_Supply_Policy (Current_Policy, Result); end if;
         if Result = OK then
            if Recorded then
               Pkg_Supply_Policy.Recheck_Recorded (Locked_Store, M.Supply_Policy, Supply_Target,
                  Current_Policy.Trusted (1 .. Current_Policy.Count), Current_Policy.Observed_At, Deadline, Result);
            else
               Pkg_Supply_Policy.Verify_New (Locked_Store, M.Supply_Policy, Supply_Target,
                  Current_Policy.Trusted (1 .. Current_Policy.Count), Current_Policy.Observed_At, Deadline, Supply_Until, Result);
            end if;
         end if;
         if Result = OK then Check_Supply_Policy (Current_Policy, Result); end if;
         Supply_Checked := Result = OK;
      end Validate_Inputs;
      procedure Revalidate is new Engine.Check_Inputs (Validate_Inputs);
      procedure Done is
      begin
         Engine.Close (C); Staging.Close (Hold); Staging.Close (Saved_Hold); MC_Store.Close (Store);
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
      if Status = OK and then M.Format not in GM.Supply_V4 | GM.Root_V5 | GM.Configured_V6 then Status := Unsupported; end if;
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
      if Status = OK and then Before /= GD.Empty then
         Read_Manifest (Store, Before, Baseline, Status);
         if Status = OK then GM.Check_Retention (Store, Baseline, Deadline, Status); end if;
         if Status = OK then Before_Closure := Baseline.Catalog_Closure; end if;
      end if;
      Accepted_Terminal := RS.Generation = P.Target_Generation and then RS.Accepted_Plan = Expected_Plan
        and then RS.Package_Set = After.Catalog;
      Recorded := RS.Active_Transaction = P.Transaction_ID or else
        (RS.Generation = P.Target_Generation and then RS.Accepted_Plan = Expected_Plan);
      Encoded := new Bytes (1 .. Pkg_File_Plan.Max_Plan_Bytes);
      if Status = OK then Pkg_File_Plan.Encode (P.all, Encoded.all, Used, Status); end if;
      MC_Store.Close (Store); MC_FS.Close (Root_Lock);
      if Status /= OK then Done; return; end if;
      declare Path : constant String := GD.Stage_Path (Generation_Bank, After); begin
         if M.Format = GM.Configured_V6 and then Accepted_Terminal then
            Staging.Verify_Retained_And_Hold (Path & "/root", Path & "/state", Store_Path,
               After.Manifest, Saved_Hold, Deadline, Status);
         else
            Staging.Verify_And_Hold (Path & "/root", Path & "/state", Store_Path, After.Manifest, Hold, Deadline, Status);
         end if;
      end;
      if Status = OK then Engine.Open (Root_Path, State_Path, Store_Path, P.Root_ID, C, Status); end if;
      if Status = OK and then (Engine.Generation (C) /= RS.Generation or else Engine.Accepted_Plan (C) /= RS.Accepted_Plan
        or else Engine.Has_Active_Change (C) /= (RS.Active_Transaction /= Zero_Identity)) then Status := Stale; end if;
      if Status = OK then Revalidate (C, Status); end if;
      if Status /= OK then Done; return; end if;
      if RS.Generation = P.Target_Generation then
         Engine.Resume_Recorded (C, Expected_Plan, Status);
         if Status = OK then Engine.Reconcile_Terminal (C, Status); end if;
      else
         if Engine.Has_Active_Change (C) then Engine.Resume_Recorded (C, Expected_Plan, Status);
         else
            Engine.Prepare (C, Encoded (1 .. Used), Expected_Plan, Status);
            -- The engine has now durably admitted this exact plan. Later work
            -- uses current managed policy while preserving the admitted supply
            -- observation; expiry alone does not turn recovery into new work.
            if Status = OK then Recorded := True; end if;
         end if;
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
      -- A durable decision may already exist when the deadline is exceeded.
      -- Never return a timely success for late I/O; callers must inspect/resume
      -- the recorded plan, not infer that a non-OK result means no effects.
      if Status = OK then Time_Left (Status); end if;
   exception when others => Done; Status := Indeterminate;
   end Publish;
end Pkg_Generation_Publisher;
