-- SPDX-License-Identifier: BSD-3-Clause
with MC_Clock; with MC_Posix; with MC_SHA256;
with Pkg_Generation_Manifest;
package body Pkg_Generation_Execution with SPARK_Mode => Off is
   package GM renames Pkg_Generation_Manifest;
   use type Interfaces.C.int; use type Interfaces.C.unsigned;
   use type GM.Format_Kind; use type Pkg_Root_Identity.Root_Identity;
   function Process_ID return Interfaces.C.int
     with Import, Convention => C, External_Name => "getpid";

   procedure Current (C : Execution; Status : out Outcome) is
      Now : Counter;
   begin
      Status := Denied;
      if C.Current in New_Execution | Failed | Closed or else C.Owner /= Process_ID
        or else MC_Posix.Euid = 0 then return; end if;
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then (Now >= C.Deadline or else C.Deadline - Now > 120_000)
      then Status := Stale; end if;
   end Current;

   procedure Boundary (C : Execution; Name : String; Status : out Outcome) is
   begin
      Current (C, Status);
      if Status = OK then Check_Lifetime (C.Generation, C.Stage, C.Deadline, Name, Status); end if;
      if Status = OK then Current (C, Status); end if;
   end Boundary;

   procedure Poison (C : in out Execution; Status : in out Outcome) is
   begin
      C.Current := Failed;
      if C.Mutation_Attempted then Status := Indeterminate; end if;
   end Poison;

   procedure Start
     (C : in out Execution; Root_Path, State_Path, Store_Path : String;
      Encoded_Manifest : Bytes; Expected_Manifest, Expected_Worker : Digest;
      Prepare_Channel, Reinspect_Channel : Integer; Deadline : Counter;
      Status : out Outcome) is
      M : GM.Manifest;
      Progress : Natural := 0;
      procedure Prepare
        (Generation, Root_Manifest, Archive, Worker : Digest; Stage : Identity;
         Size, Entries, Limit : Counter; Archive_FD, Reservation_FD : Integer;
         Result : out Outcome) is
      begin
         Boundary (C, "execution:prepare-root", Result);
         if Result = OK and then (Generation /= C.Generation or else Worker /= C.Worker
           or else Stage /= C.Stage or else Limit /= C.Deadline) then Result := Denied; end if;
         if Result = OK then
            Pkg_Root_Handoff.Prepare (C.Preparation, Generation, Root_Manifest, Archive,
               Worker, Stage, Size, Entries, Limit, Archive_FD, Reservation_FD, Result);
         end if;
         if Result = OK then Boundary (C, "execution:root-prepared", Result); end if;
      end Prepare;
      procedure Reinspect
        (Generation, Root_Manifest, Archive, Worker : Digest; Stage : Identity;
         Size, Entries, Original_Deadline, Limit : Counter;
         Expected_Root : Pkg_Root_Identity.Root_Identity;
         Archive_FD, Reservation_FD : Integer; Result : out Outcome) is
      begin
         Boundary (C, "execution:reinspect-root", Result);
         if Result = OK and then (Generation /= C.Generation or else Worker /= C.Worker
           or else Stage /= C.Stage or else Limit /= C.Deadline
           or else Original_Deadline /= C.Deadline) then Result := Denied; end if;
         if Result = OK then
            Pkg_Root_Handoff.Reinspect (C.Reinspection, Generation, Root_Manifest, Archive,
               Worker, Stage, Size, Entries, Original_Deadline, Limit, Expected_Root,
               Archive_FD, Reservation_FD, Result);
         end if;
         if Result = OK then Boundary (C, "execution:root-reinspected", Result); end if;
      end Reinspect;
      procedure Prepare_Physical is new Staging.Prepare_Root (Prepare);
      procedure Reinspect_Physical is new Staging.Reinspect_Root_And_Hold (Observe_Root, Reinspect);
   begin
      Status := Conflict;
      if C.Current /= New_Execution then return; end if;
      C.Owner := Process_ID; C.Current := Binding;
      C.Generation := Expected_Manifest; C.Worker := Expected_Worker; C.Deadline := Deadline;
      Status := Invalid_Input;
      if MC_Posix.Euid = 0 or else Expected_Manifest = Zero_Digest or else Expected_Worker = Zero_Digest
        or else Prepare_Channel < 3 or else Reinspect_Channel < 3 or else Prepare_Channel = Reinspect_Channel
        or else Deadline = 0 or else Deadline = Counter'Last
        or else Encoded_Manifest'Length < GM.Root_Header_Size or else Encoded_Manifest'Length > GM.Max_Bytes
      then Poison (C, Status); return; end if;
      if MC_SHA256.Hash (Encoded_Manifest) /= Expected_Manifest then
         Status := Denied; Poison (C, Status); return;
      end if;
      GM.Decode (Encoded_Manifest, M, Status);
      if Status = OK and then M.Format not in GM.Root_V5 | GM.Configured_V6 then Status := Unsupported; end if;
      if Status /= OK then Poison (C, Status); return; end if;
      C.Stage := M.Stage_ID;
      Boundary (C, "execution:bind", Status);
      if Status = OK then Pkg_Root_Handoff.Open (C.Preparation, Prepare_Channel, Deadline, Status); end if;
      if Status = OK then Pkg_Root_Handoff.Open (C.Reinspection, Reinspect_Channel, Deadline, Status); end if;
      if Status /= OK then Poison (C, Status); return; end if;

      C.Current := Provisioning; C.Mutation_Attempted := True;
      Staging.Provision (Root_Path, State_Path, Store_Path, Encoded_Manifest, Expected_Manifest, Deadline, Status);
      if Status /= OK then Poison (C, Status); return; end if;
      C.Current := Advancing;
      for Index in 1 .. M.Count loop
         Boundary (C, "execution:advance", Status);
         if Status = OK then
            Staging.Advance (Root_Path, State_Path, Store_Path, Expected_Manifest, Progress, Deadline, Status);
         end if;
         -- A fresh execution advances one batch exactly. A replay/skip or a
         -- success without progress is not a reason to spin or retry.
         if Status = OK and then Progress /= Index then Status := Corrupt; end if;
         if Status /= OK then Poison (C, Status); return; end if;
         C.Completed := Progress;
      end loop;
      C.Current := Preparing;
      Prepare_Physical (Root_Path, State_Path, Store_Path, Expected_Manifest, Expected_Worker, Deadline, Status);
      if Status /= OK then Poison (C, Status); return; end if;
      C.Current := Reinspecting;
      Reinspect_Physical (Root_Path, State_Path, Store_Path, Expected_Manifest, Expected_Worker,
                         C.Physical, Deadline, Status);
      if Status /= OK then Poison (C, Status); return; end if;
      C.Current := Holding;
      Check (C, Status);
   exception
      when others => Status := Indeterminate; Poison (C, Status);
   end Start;

   function Held (C : Execution) return Boolean is
      Status : Outcome;
   begin
      if C.Current /= Holding then return False; end if;
      Current (C, Status);
      return Status = OK and then Staging.Held (C.Physical);
   end Held;

   function Observation (C : Execution) return Pkg_Root_Identity.Root_Identity is
   begin
      if Held (C) then return Staging.Root_Observation (C.Physical); end if;
      return (others => <>);
   end Observation;

   function Completed_Batches (C : Execution) return Natural is (C.Completed);

   procedure Check (C : in out Execution; Status : out Outcome) is
      Root : Pkg_Root_Identity.Root_Identity;
      Original : Counter;
   begin
      Status := Conflict;
      if C.Current /= Holding then return; end if;
      Status := Denied;
      if not Held (C) then Poison (C, Status); return; end if;
      Boundary (C, "execution:held", Status);
      if Status = OK then
         Observe_Root (C.Generation, C.Stage, "execution:held", Original, Root, Status);
      end if;
      if Status = OK and then (Original /= C.Deadline or else Root /= Staging.Root_Observation (C.Physical))
      then Status := Stale; end if;
      if Status = OK then Boundary (C, "execution:held-observed", Status); end if;
      if Status = OK and then not Held (C) then Status := Stale; end if;
      if Status /= OK then Poison (C, Status); end if;
   exception
      when others => Status := Indeterminate; Poison (C, Status);
   end Check;

   procedure Close (C : in out Execution) is
   begin
      C.Current := Closed;
      -- Native reservations end before the handoff duplicates. The launcher
      -- retains its original channels and root authority until after this call.
      Staging.Close (C.Physical);
      Pkg_Root_Handoff.Close (C.Reinspection);
      Pkg_Root_Handoff.Close (C.Preparation);
      C.Generation := Zero_Digest; C.Worker := Zero_Digest;
      C.Stage := Zero_Identity; C.Deadline := 0;
   end Close;

   overriding procedure Finalize (C : in out Execution) is
   begin
      Close (C);
   end Finalize;
end Pkg_Generation_Execution;
