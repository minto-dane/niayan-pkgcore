-- SPDX-License-Identifier: BSD-3-Clause
package body Resolver_CNF with SPARK_Mode is
   procedure Compile (U : Universe; F : out Formula; Status : out Outcome;
      Fuel : in out Natural) is
      Failed : Boolean := False;
      procedure Emit (A : Literal; B : Literal := 0; C : Literal := 0) is
      begin
         if Failed then return; end if;
         if Fuel = 0 or else F.Count = Max_Clauses then Failed := True; return; end if;
         Fuel := Fuel - 1; F.Count := F.Count + 1;
         F.Clauses (F.Count) := (Count => (if C /= 0 then 3 elsif B /= 0 then 2 else 1), Terms => (A, B, C));
      end Emit;
      Z, A, B : Literal;
   begin
      F := (others => <>); Status := Invalid_Input; if not Well_Formed (U) then return; end if;
      F.Variables := U.Item_Count + U.Node_Count;
      for I in 1 .. U.Item_Count loop
         if not U.Items (I).Permitted then Emit (-I); end if;
         case U.Items (I).Pin is
            when Unpinned => null;
            when Keep_State => Emit ((if U.Items (I).Initially_Present then I else -I));
            when Require_Present => Emit (I);
            when Require_Absent => Emit (-I);
         end case;
         if U.Items (I).Reinstall_Requested then Emit (I); end if;
      end loop;
      for I in 1 .. U.Node_Count loop
         Z := U.Item_Count + I;
         A := U.Item_Count + U.Nodes (I).Left; B := U.Item_Count + U.Nodes (I).Right;
         case U.Nodes (I).Op is
            when Constant_False => Emit (-Z);
            when Constant_True => Emit (Z);
            when Present => Emit (-Z, U.Nodes (I).Subject); Emit (Z, -U.Nodes (I).Subject);
            when Not_Op => Emit (-Z, -A); Emit (Z, A);
            when And_Op => Emit (-Z, A); Emit (-Z, B); Emit (Z, -A, -B);
            when Or_Op => Emit (Z, -A); Emit (Z, -B); Emit (-Z, A, B);
         end case;
      end loop;
      for I in 1 .. U.Rule_Count loop Emit (U.Item_Count + U.Rules (I).Predicate); end loop;
      for I in 1 .. U.Claim_Count loop
         for J in I + 1 .. U.Claim_Count loop
            if Fuel = 0 then Failed := True; exit; end if; Fuel := Fuel - 1;
            exit when U.Claims (I).Resource /= U.Claims (J).Resource;
            if not Claims_Compatible (U.Claims (I), U.Claims (J)) then
               Emit (-U.Claims (I).Owner, -U.Claims (J).Owner);
            end if;
         end loop;
         exit when Failed;
      end loop;
      if Failed then F := (others => <>); Status := Exhausted; else Status := OK; end if;
   end Compile;
   procedure Model (U : Universe; S : Selection; Values : out Truth_Array;
      F : Formula; Valid : out Boolean) is
      function Val (L : Literal) return Boolean is
         Index : constant Natural := abs L;
         V : Boolean;
      begin
         if Index = 0 or else Index > F.Variables then return False; end if;
         if Index <= U.Item_Count then V := S (Index); else V := Values (Index - U.Item_Count); end if;
         return (if L < 0 then not V else V);
      end Val;
      Met : Boolean;
   begin
      Valid := False; Values := (others => False);
      if not Well_Formed (U) or else not Canonical_Selection (U, S)
        or else F.Variables /= U.Item_Count + U.Node_Count then return; end if;
      Evaluate (U, S, Values);
      for I in 1 .. F.Count loop
         Met := False;
         for J in 1 .. F.Clauses (I).Count loop Met := Met or Val (F.Clauses (I).Terms (J)); end loop;
         if not Met then return; end if;
      end loop;
      Valid := True;
   end Model;
end Resolver_CNF;
