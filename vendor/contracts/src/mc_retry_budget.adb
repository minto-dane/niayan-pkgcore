-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Retry_Budget with SPARK_Mode is
   function Valid (P : Policy) return Boolean is
     (P.Window_Ms > 0 and then P.Window_Ms <= 86_400_000
      and then P.Initial_Backoff_Ms > 0
      and then P.Initial_Backoff_Ms <= P.Maximum_Backoff_Ms
      and then P.Maximum_Backoff_Ms <= P.Window_Ms);
   function Valid (S : State) return Boolean is
     (S.Boot_ID/=Zero_Identity and then S.Total>=S.Count and then S.Total>=S.Consecutive
      and then (for all I in Slot =>
        (if I<=S.Count then S.Attempts(I)<=S.Last_Now
          and then (I=1 or else S.Attempts(I)>=S.Attempts(I-1))
         else S.Attempts(I)=0)));
   function Backoff (P : Policy; Consecutive : Natural) return Counter is
      Delay_Ms : Counter := P.Initial_Backoff_Ms;
   begin
      -- Bounded loop even for a hostile Natural'Last argument.
      for I in 2 .. Natural'Min(Consecutive, Capacity) loop
         if Delay_Ms > P.Maximum_Backoff_Ms / 2 then
            return P.Maximum_Backoff_Ms;
         end if;
         Delay_Ms := Delay_Ms * 2;
      end loop;
      return Counter'Min(Delay_Ms, P.Maximum_Backoff_Ms);
   end Backoff;
   procedure Reserve (S : in out State; P : Policy; Boot : Identity;
      Now : Counter; Status : out Outcome) is
      N : State := S;
      Kept : Natural range 0 .. Capacity := 0;
      Times : Time_Array := (others => 0);
      Delay_Ms : Counter;
   begin
      Status := Invalid_Input;
      if not Valid(P) or else not Valid(S) then return; end if;
      if Boot /= S.Boot_ID or else Now < S.Last_Now then Status := Stale; return; end if;
      if Now < S.Not_Before then Status := Denied; return; end if;
      if S.Total >= P.Maximum_Total or else S.Consecutive >= P.Maximum_Consecutive
      then Status := Exhausted; return; end if;
      for I in 1 .. S.Count loop
         if Now - S.Attempts(I) < P.Window_Ms then
            Kept := Kept + 1; Times(Kept) := S.Attempts(I);
         end if;
         pragma Loop_Invariant(Kept<=I);
         pragma Loop_Invariant(for all J in 1 .. Kept => Times(J)<=S.Attempts(I));
         pragma Loop_Invariant(for all J in 1 .. Kept => Times(J)<=Now);
         pragma Loop_Invariant(for all J in 2 .. Kept => Times(J)>=Times(J-1));
         pragma Loop_Invariant(for all J in Kept+1 .. Capacity => Times(J)=0);
      end loop;
      if Kept >= P.Maximum_In_Window then Status := Denied; return; end if;
      Delay_Ms := Backoff(P, S.Consecutive + 1);
      if Now >= Counter'Last - Delay_Ms then Status := Exhausted; return; end if;
      Kept := Kept + 1; Times(Kept) := Now;
      N.Count := Kept; N.Attempts := Times; N.Last_Now := Now;
      N.Consecutive := N.Consecutive + 1; N.Total := N.Total + 1;
      N.Not_Before := Now + Delay_Ms;
      S := N; Status := OK;
   end Reserve;
   procedure Confirm_Stable (S : in out State; Now : Counter; Status : out Outcome) is
   begin
      Status := Invalid_Input;
      if not Valid(S) then return; end if;
      if Now < S.Last_Now then Status := Stale; return; end if;
      S.Consecutive := 0; S.Last_Now := Now;
      -- Do not remove window debt or shorten the cooldown.
      Status := OK;
   end Confirm_Stable;
   procedure Rebind_Boot (S : in out State; P : Policy; New_Boot : Identity;
      Now : Counter; Status : out Outcome) is
   begin
      Status := Invalid_Input;
      if not Valid(P) or else not Valid(S) or else New_Boot = Zero_Identity
        or else New_Boot = S.Boot_ID then return; end if;
      if Now >= Counter'Last - P.Maximum_Backoff_Ms then Status := Exhausted; return; end if;
      S.Boot_ID := New_Boot; S.Last_Now := Now;
      for I in 1 .. S.Count loop
         S.Attempts(I) := Now;
         pragma Loop_Invariant(for all J in 1..I => S.Attempts(J)=Now);
      end loop;
      S.Not_Before := Now + P.Maximum_Backoff_Ms;
      Status := OK;
   end Rebind_Boot;
end MC_Retry_Budget;
