-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Retry_Budget with SPARK_Mode, Pure is
   Capacity : constant := 64;
   subtype Slot is Positive range 1 .. Capacity;
   type Time_Array is array (Slot) of Counter;
   type Policy is record
      Maximum_In_Window : Positive range 1 .. Capacity := 3;
      Maximum_Consecutive : Positive range 1 .. Capacity := 5;
      Maximum_Total : Positive range 1 .. 1_000_000 := 100;
      Window_Ms : Counter := 3_600_000;
      Initial_Backoff_Ms : Counter := 5_000;
      Maximum_Backoff_Ms : Counter := 300_000;
   end record;
   type State is record
      Boot_ID : Identity := Zero_Identity;
      Count : Natural range 0 .. Capacity := 0;
      Attempts : Time_Array := (others => 0);
      Consecutive : Natural range 0 .. Capacity := 0;
      Total : Natural range 0 .. 1_000_000 := 0;
      Last_Now, Not_Before : Counter := 0;
   end record;
   function Valid (P : Policy) return Boolean with Global => null;
   function Valid (S : State) return Boolean with Global => null;
   function Backoff (P : Policy; Consecutive : Natural) return Counter
     with Pre => Valid(P), Global => null,
       Post => Backoff'Result <= P.Maximum_Backoff_Ms;
   procedure Reserve (S : in out State; P : Policy; Boot : Identity;
      Now : Counter; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old)
         and then (if Status = OK then Valid(S) and then S.Total = S'Old.Total + 1
           and then S.Boot_ID = Boot and then S.Count <= P.Maximum_In_Window);
   procedure Confirm_Stable (S : in out State; Now : Counter; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old)
         and then S.Total = S'Old.Total and then S.Count = S'Old.Count;
   procedure Rebind_Boot (S : in out State; P : Policy; New_Boot : Identity;
      Now : Counter; Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old)
         and then S.Total = S'Old.Total and then S.Count = S'Old.Count
         and then S.Consecutive = S'Old.Consecutive;
   -- Durable state. Reboot moves outstanding window debt to the NEW clock's
   -- present; it never refills a budget. No automatic lifetime reset exists.
   -- Caller may only Confirm_Stable after independent stable-health evidence.
end MC_Retry_Budget;
