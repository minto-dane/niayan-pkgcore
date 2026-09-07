-- SPDX-License-Identifier: MIT
package body Resolver_Proof with SPARK_Mode is
   type Assignment is array (Positive range 1 .. Max_Variables) of Integer range -1 .. 1;
   type Marks is array (Positive range 1 .. Max_Variables) of Integer range -1 .. 1;
   type Polarity_Marks is array (Positive range 1 .. Max_Variables) of Boolean;
   function Sign (L : Literal) return Integer is (if L < 0 then -1 else 1);
   procedure Spend (Fuel : in out Natural; Status : in out Outcome) is
   begin
      if Status /= OK then return; end if;
      if Fuel = 0 then Status := Exhausted; else Fuel := Fuel - 1; end if;
   end Spend;
   procedure Normalize (C : Literals; Variables : Natural; N : out Literals;
      Used : out Natural; Tautology : out Boolean; Status : out Outcome;
      Fuel : in out Natural) is
      Positive_Seen, Negative_Seen : Polarity_Marks := (others => False); V : Natural;
   begin
      N := (others => 0); Used := 0; Tautology := False; Status := OK;
      if C'Length > 2 * Variables or else N'Length < C'Length or else N'First /= 1 then Status := Invalid_Input; return; end if;
      for L of C loop
         Spend (Fuel, Status); if Status /= OK then return; end if;
         V := abs L;
         if V = 0 or else V > Variables then Status := Invalid_Input; return; end if;
         if L > 0 then
            Tautology := Tautology or Negative_Seen (V);
            if not Positive_Seen (V) then Used := Used + 1; N (Used) := L; end if;
            Positive_Seen (V) := True;
         else
            Tautology := Tautology or Positive_Seen (V);
            if not Negative_Seen (V) then Used := Used + 1; N (Used) := L; end if;
            Negative_Seen (V) := True;
         end if;
      end loop;
   end Normalize;
   procedure Append (D : in out Database; ID : Counter; C : Literals; Status : out Outcome) is
   begin
      Status := Exhausted;
      if D.Used = Max_Entries or else C'Length > Max_Literals - D.End_Data then return; end if;
      D.Used := D.Used + 1;
      D.Clauses (D.Used) := (ID => ID, Offset => D.End_Data, Length => C'Length, Active => True);
      for L of C loop D.End_Data := D.End_Data + 1; D.Data (D.End_Data) := L; end loop;
      D.Maximum_ID := ID;
      if C'Length = 0 then D.Empty_Derived := True; end if;
      Status := OK;
   end Append;
   procedure Initialize (F : Resolver_CNF.Formula; D : out Database;
      Status : out Outcome; Fuel : in out Natural) is
      Input, N : Literals (1 .. 3) := (others => 0); Count : Natural; Taut : Boolean;
   begin
      D.Used := 0; D.End_Data := 0; D.Maximum_ID := 0; D.Empty_Derived := False;
      D.Initialized := False; D.Variables := F.Variables; Status := Invalid_Input;
      -- Entries and arena outside Used/End_Data are inaccessible, including on
      -- failed initialization. No uninitialized storage is a live clause.
      for I in 1 .. F.Count loop
         for J in 1 .. F.Clauses (I).Count loop Input (J) := F.Clauses (I).Terms (J); end loop;
         Normalize (Input (1 .. F.Clauses (I).Count), F.Variables, N, Count, Taut, Status, Fuel);
         if Status /= OK then return; end if;
         Append (D, Counter (I), N (1 .. Count), Status); if Status /= OK then return; end if;
      end loop;
      D.Initialized := True; Status := OK;
   end Initialize;
   procedure RUP (D : Database; C : Literals; Yes : out Boolean;
      Status : out Outcome; Fuel : in out Natural) is
      A : Assignment := (others => 0); V : Natural; Changed, Satisfied : Boolean;
      Unassigned : Natural; Unit_Literal : Literal := 0;
   begin
      Yes := False; Status := OK;
      for L of C loop
         Spend (Fuel, Status); if Status /= OK then return; end if;
         V := abs L;
         if V = 0 or else V > D.Variables then Status := Invalid_Input; return; end if;
         if A (V) = Sign (L) then Yes := True; return; end if;
         A (V) := -Sign (L);
      end loop;
      for Round in 0 .. D.Variables loop
         Changed := False;
         for I in 1 .. D.Used loop
            Spend (Fuel, Status); if Status /= OK then return; end if;
            if D.Clauses (I).Active then
               Satisfied := False; Unassigned := 0;
               for J in 1 .. D.Clauses (I).Length loop
                  Spend (Fuel, Status); if Status /= OK then return; end if;
                  declare L : constant Literal := D.Data (D.Clauses (I).Offset + J); begin
                     V := abs L;
                     if A (V) = Sign (L) then Satisfied := True; exit; end if;
                     if A (V) = 0 then Unassigned := Unassigned + 1; Unit_Literal := L; end if;
                  end;
               end loop;
               if not Satisfied then
                  if Unassigned = 0 then Yes := True; return;
                  elsif Unassigned = 1 then
                     A (abs Unit_Literal) := Sign (Unit_Literal); Changed := True;
                  end if;
               end if;
            end if;
         end loop;
         if not Changed then return; end if;
      end loop;
      -- Each useful round assigns a previously unassigned variable; reaching
      -- this point signals an unsupported resource/model condition, not proof.
      Status := Indeterminate;
   end RUP;
   procedure Add (D : in out Database; ID : Counter; Clause : Literals;
      Status : out Outcome; Fuel : in out Natural) is
      N, Resolvent : Literals (1 .. 2 * Max_Variables) := (others => 0);
      Count, RC : Natural; Taut, Yes, Found, RT : Boolean; Pivot : Literal;
      Seen : Marks := (others => 0);
      procedure Insert (L : Literal) is
         V : constant Positive := abs L;
      begin
         if Seen (V) = -Sign (L) then RT := True; end if;
         if Seen (V) = 0 then RC := RC + 1; Resolvent (RC) := L; end if;
         Seen (V) := Sign (L);
      end Insert;
   begin
      Status := Invalid_Input;
      if not D.Initialized or else ID <= D.Maximum_ID then return; end if;
      Normalize (Clause, D.Variables, N, Count, Taut, Status, Fuel); if Status /= OK then return; end if;
      if Taut then Append (D, ID, N (1 .. Count), Status); return; end if;
      RUP (D, N (1 .. Count), Yes, Status, Fuel); if Status /= OK then return; end if;
      if Yes then Append (D, ID, N (1 .. Count), Status); return; end if;
      if Count = 0 then Status := Denied; return; end if;
      Pivot := N (1);
      -- Full RAT test on the first (original) literal. No hint can omit an
      -- opposing clause; every active clause with the opposite pivot is checked.
      for I in 1 .. D.Used loop
         Spend (Fuel, Status); if Status /= OK then return; end if;
         if D.Clauses (I).Active then
            Found := False;
            for J in 1 .. D.Clauses (I).Length loop
               Spend (Fuel, Status); if Status /= OK then return; end if;
               if D.Data (D.Clauses (I).Offset + J) = -Pivot then Found := True; exit; end if;
            end loop;
            if Found then
               RC := 0; RT := False; Seen := (others => 0);
               for J in 2 .. Count loop Insert (N (J)); end loop;
               for J in 1 .. D.Clauses (I).Length loop
                  Spend (Fuel, Status); if Status /= OK then return; end if;
                  declare L : constant Literal := D.Data (D.Clauses (I).Offset + J); begin
                     if L /= -Pivot then Insert (L); end if;
                  end;
               end loop;
               if not RT then
                  RUP (D, Resolvent (1 .. RC), Yes, Status, Fuel); if Status /= OK then return; end if;
                  if not Yes then Status := Denied; return; end if;
               end if;
            end if;
         end if;
      end loop;
      Append (D, ID, N (1 .. Count), Status);
   end Add;
   procedure Delete (D : in out Database; ID : Counter;
      Status : out Outcome; Fuel : in out Natural) is
      L : Natural := 1; R : Natural := D.Used; M : Natural;
   begin
      Status := Invalid_Input; if not D.Initialized or else ID = 0 then return; end if;
      Status := OK;
      while L <= R loop
         Spend (Fuel, Status); if Status /= OK then return; end if;
         M := L + (R - L) / 2;
         if D.Clauses (M).ID = ID then
            if not D.Clauses (M).Active then Status := Invalid_Input; return; end if;
            D.Clauses (M).Active := False; return;
         elsif D.Clauses (M).ID < ID then L := M + 1; else R := M - 1; end if;
      end loop;
      Status := Invalid_Input;
   end Delete;
   function Refuted (D : Database) return Boolean is (D.Initialized and then D.Empty_Derived);
   function Last_ID (D : Database) return Counter is (D.Maximum_ID);
end Resolver_Proof;
