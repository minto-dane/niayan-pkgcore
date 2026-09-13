-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation; with Interfaces.C; with MC_Clock; with MC_FS; with MC_Posix;
with MC_SHA256; with MC_Store;
with Pkg_Catalog_Store; with Pkg_Catalog_Retention; with Pkg_File_Plan; with Pkg_File_Replay;
with Pkg_Generation_Manifest; with Pkg_Generation_Intent; with Pkg_Generation_Storage;
with Pkg_Recovery_Audit; with Pkg_Root_State;
package body Pkg_Generation_Reader with SPARK_Mode => Off is
   package GD renames Pkg_Generation_Descriptor;
   package GM renames Pkg_Generation_Manifest;
   use Pkg_Generation_Storage;
   use type Interfaces.C.unsigned;
   use type Pkg_Root_State.State; use type Pkg_File_Replay.Direction;
   type Plan_Access is access Pkg_File_Plan.Plan;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_File_Plan.Plan, Plan_Access);
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
         Binding := Pkg_Generation_Intent.Update_Binding
           (Expected_Current, Target_Catalog, Target_Closure, Pkg_Deb_Transition.Fingerprint (Result));
         Current := C.Bound;
      else Clear_Result; end if;
      Close_Observation (C);
   exception when others => Close_Observation (C); Issue := (others => <>); Clear_Result; Status := Indeterminate;
   end Read_Current_Transition;
   procedure With_Current (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Deadline : Counter; Status : out Outcome) is
      C : Observation_Context; Latest : Pkg_Root_State.State;
      procedure Check_Time is
         Now : Counter;
      begin
         Status := Invalid_Input;
         if Deadline in 0 | Counter'Last then return; end if;
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
   begin
      Check_Time; if Status /= OK then return; end if;
      Observe_And_Lock (Root_Path, State_Path, Store_Path, Root_ID, C, Status);
      if Status = OK then GM.Check_Retention (C.Store, C.Image, Deadline, Status); end if;
      if Status = OK then Check_Time; end if;
      if Status = OK then Process (C.Store, C.Bound, C.Image, Status); end if;
      if Status = OK then Read_State (C.Root, C.State, Root_ID, Latest, Status); end if;
      if Status = OK and then Latest /= C.Accepted then Status := Stale; end if;
      if Status = OK then Check_Time; end if;
      Close_Observation (C);
   exception when others => Close_Observation (C); Status := Indeterminate;
   end With_Current;
end Pkg_Generation_Reader;
