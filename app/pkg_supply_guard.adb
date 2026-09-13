-- SPDX-License-Identifier: BSD-3-Clause
-- Private nonroot observer. No store reservation, writes or execution grant.
with Ada.Command_Line;
with Interfaces.C; with MC_Posix;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Hex; with MC_Clock; with MC_Codec; with MC_SHA256;
with Pkg_Site_Supply;
procedure Pkg_Supply_Guard with SPARK_Mode => Off is
   use Ada.Command_Line; use type Wide;
   use type Interfaces.C.int; use type Interfaces.C.long; use type Interfaces.C.unsigned;
   Context : Pkg_Site_Supply.Session;
   Generation, Plan, Retained_Policy, Map, Policy_Hash, Floor_Hash : Digest := Zero_Digest;
   Root_ID, Transaction_ID : Identity := Zero_Identity;
   Actual_Policy, Actual_Floor, Binding : Digest := Zero_Digest;
   Minimum_UTC, Observed_UTC, Last_UTC, Deadline, Before, After : Counter := 0;
   Status : Outcome := Invalid_Input;
   Sequence : Natural range 0 .. 1_200 := 0;
   Bound : Bytes (1 .. 248) := (others => 0);
   Input : aliased Bytes (1 .. 8) := (others => 0);
   Output : aliased Bytes (1 .. 72) := (others => 0);
   Count : Interfaces.C.long;
   procedure Nonblocking (FD : MC_Posix.FD) is
      Flags : constant Interfaces.C.int := MC_Posix.Dup (FD, 3, 0);
   begin
      if Flags < 0 or else MC_Posix.Dup (FD, 4, Interfaces.C.int
         (Interfaces.C.unsigned (Flags) or Interfaces.C.unsigned (MC_Posix.O_NONBLOCK))) /= 0
      then raise Program_Error; end if;
   end Nonblocking;
   procedure Observe is
   begin
      Pkg_Site_Supply.Observe_Inputs (Context, Actual_Policy, Actual_Floor, Observed_UTC, Status);
      if Status = OK and then (Actual_Policy /= Policy_Hash or else Actual_Floor /= Floor_Hash
        or else Observed_UTC < Minimum_UTC or else Observed_UTC < Last_UTC) then Status := Stale; end if;
      if Status = OK then Last_UTC := Observed_UTC; end if;
   end Observe;
begin
   if Argument_Count /= 10 then Set_Exit_Status (64); return; end if;
   MC_Runtime.Initialize (Status);
   if Status = OK then MC_Hex.Decode (Argument (1), Generation, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (2), Root_ID, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (3), Transaction_ID, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (4), Plan, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (5), Retained_Policy, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (6), Map, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (7), Policy_Hash, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (8), Floor_Hash, Status); end if;
   Minimum_UTC := Counter'Value (Argument (9)); Deadline := Counter'Value (Argument (10));
   if Status = OK then MC_Clock.Boottime_Milliseconds (Before, Status); end if;
   if Status /= OK or else Generation = Zero_Digest or else Root_ID = Zero_Identity
     or else Transaction_ID = Zero_Identity or else Plan = Zero_Digest or else Retained_Policy = Zero_Digest
     or else Map = Zero_Digest or else Policy_Hash = Zero_Digest or else Floor_Hash = Zero_Digest
     or else Minimum_UTC not in 1 .. 2 ** 53 - 1 or else Deadline >= Counter'Last
     or else Deadline <= Before or else Deadline - Before > 120_000 then
      Set_Exit_Status (2); return;
   end if;
   -- The generation/map/plan are caller bindings, not independently authorized
   -- by this observer. The managed native publisher must still validate them.
   Bound (1 .. 8) := (78, 73, 65, 83, 85, 80, 66, 49); -- NIASUPB1
   Bound (9 .. 40) := Generation; Bound (41 .. 56) := Root_ID;
   Bound (57 .. 72) := Transaction_ID; Bound (73 .. 104) := Plan;
   Bound (105 .. 136) := Retained_Policy; Bound (137 .. 168) := Map;
   Bound (169 .. 200) := Policy_Hash; Bound (201 .. 232) := Floor_Hash;
   MC_Codec.Put64 (Bound, 233, Wide (Minimum_UTC)); MC_Codec.Put64 (Bound, 241, Wide (Deadline));
   Binding := MC_SHA256.Hash (Bound);
   Pkg_Site_Supply.Open ("/etc/niaos/supply", "/var/lib/niaos/trust", Root_ID,
      Transaction_ID, Plan, Retained_Policy, Map, Deadline, Context, Status);
   if Status = OK then Observe; end if;
   if Status /= OK then Pkg_Site_Supply.Close (Context); Set_Exit_Status (2); return; end if;
   Nonblocking (0); Nonblocking (1);
   for Attempt in 1 .. 12_000 loop
      MC_Clock.Boottime_Milliseconds (Before, Status);
      exit when Status /= OK or else Before >= Deadline;
      Count := MC_Posix.Read (0, Input'Address, 8);
      if Count = -1 and then MC_Posix.Errno_Location.all = MC_Posix.EAGAIN then
         delay 0.01;
      else
         exit when Count /= 8 or else Sequence = 1_200;
         exit when MC_Codec.U64 (Input, 1) /= Wide (Sequence + 1);
         Sequence := Sequence + 1;
         MC_Clock.Boottime_Milliseconds (Before, Status);
         exit when Status /= OK or else Before >= Deadline;
         Observe;
         exit when Status /= OK;
         MC_Clock.Boottime_Milliseconds (After, Status);
         exit when Status /= OK or else After < Before or else After >= Deadline;
         Output (1 .. 8) := (78, 73, 65, 83, 85, 80, 48, 49); -- NIASUP01
         MC_Codec.Put64 (Output, 9, Wide (Sequence));
         MC_Codec.Put64 (Output, 17, Wide (Before)); MC_Codec.Put64 (Output, 25, Wide (After));
         Output (33 .. 64) := Binding; MC_Codec.Put64 (Output, 65, Wide (Observed_UTC));
         exit when MC_Posix.Write (1, Output'Address, 72) /= 72;
      end if;
   end loop;
   Pkg_Site_Supply.Close (Context);
   Set_Exit_Status (2); -- Termination is not a positive supply observation.
exception when others =>
   Pkg_Site_Supply.Close (Context); Set_Exit_Status (2);
end Pkg_Supply_Guard;
