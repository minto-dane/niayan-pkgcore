-- SPDX-License-Identifier: MIT
package body Resolver_Verify with SPARK_Mode is
   procedure Spend (Fuel : in out Natural; OK : out Boolean) is
   begin OK := Fuel > 0; if OK then Fuel := Fuel - 1; end if; end Spend;
   procedure Check_State (U : Universe; S : Selection; Final : Boolean;
      R : out Report; Fuel : in out Natural) is
      V : Truth_Array; Enough : Boolean;
   begin
      R := (Code => Valid_Selection, others => <>);
      if not Canonical_Selection (U, S) then R.Code := Noncanonical_Tail; return; end if;
      for I in 1 .. U.Item_Count loop
         Spend (Fuel, Enough); if not Enough then R.Code := Limit_Reached; return; end if;
         if (S (I) and then not U.Items (I).Permitted
             and then (Final or else not U.Items (I).Initially_Present))
           or else (U.Items (I).Pin = Keep_State and then S (I) /= U.Items (I).Initially_Present)
           or else (Final and then U.Items (I).Pin = Require_Present and then not S (I))
           or else (Final and then U.Items (I).Pin = Require_Absent and then S (I))
         then R.Code := Policy_Violation; R.Item_Index := I; return; end if;
      end loop;
      if Fuel < U.Node_Count then R.Code := Limit_Reached; return; end if;
      Fuel := Fuel - U.Node_Count; Evaluate (U, S, V);
      for I in 1 .. U.Rule_Count loop
         Spend (Fuel, Enough); if not Enough then R.Code := Limit_Reached; return; end if;
         if (Final or else U.Rules (I).Scope = Every_Boundary)
           and then not V (U.Rules (I).Predicate)
         then R.Code := Constraint_Violation; R.Rule_Index := I; return; end if;
      end loop;
      -- Claims are canonically grouped, so distinct resource groups are not
      -- scanned quadratically. Very large groups consume the common work budget.
      for I in 1 .. U.Claim_Count loop
         if S (U.Claims (I).Owner) then
            for J in I + 1 .. U.Claim_Count loop
               Spend (Fuel, Enough); if not Enough then R.Code := Limit_Reached; return; end if;
               exit when U.Claims (J).Resource /= U.Claims (I).Resource;
               if S (U.Claims (J).Owner) and then not Claims_Compatible (U.Claims (I), U.Claims (J))
               then R.Code := Ownership_Conflict; R.Claim_Index := J; return; end if;
            end loop;
         end if;
      end loop;
   end Check_State;
   procedure Check_Selection (U : Universe; S : Selection;
      R : out Report; Fuel : in out Natural) is
      Total : Counter := 0; Changes : Natural := 0;
   begin
      R := (others => <>);
      if not Well_Formed (U) then return; end if;
      Check_State (U, S, True, R, Fuel); if R.Code /= Valid_Selection then return; end if;
      for I in 1 .. U.Item_Count loop
         if S (I) /= U.Items (I).Initially_Present or else U.Items (I).Reinstall_Requested then
            Changes := Changes + 1;
         end if;
         if U.Items (I).Reinstall_Requested and then not S (I) then
            R.Code := Policy_Violation; R.Item_Index := I; return;
         end if;
         if S (I) and then (not U.Items (I).Initially_Present or else U.Items (I).Reinstall_Requested) then
            if U.Items (I).Transfer_Bytes > U.Maximum_Transfer - Total then
               R.Code := Budget_Exceeded; return;
            end if;
            Total := Total + U.Items (I).Transfer_Bytes;
         end if;
      end loop;
      R.Transfer_Bytes := Total;
      if Changes > U.Maximum_Changes then R.Code := Budget_Exceeded; end if;
   end Check_Selection;
   procedure Check_Schedule (U : Universe; Expected_Hash : Digest;
      P : Proposal; R : out Report; Fuel : in out Natural) is
      S, Seen : Selection := (others => False);
      V : Truth_Array; Pre_ID, Post_ID : Node_ID; Total : Counter;
   begin
      R := (others => <>);
      if Is_Zero (Expected_Hash) or else P.Universe_Hash /= Expected_Hash then
         R.Code := Stale_Universe; return;
      end if;
      Check_Selection (U, P.Selected, R, Fuel);
      if R.Code /= Valid_Selection then return; end if;
      Total := R.Transfer_Bytes;
      if P.Count > U.Maximum_Changes then R.Code := Budget_Exceeded; return; end if;
      S := Initial (U); Check_State (U, S, False, R, Fuel);
      if R.Code /= Valid_Selection then return; end if;
      for I in 1 .. P.Count loop
         declare A : Action renames P.Steps (I); begin
            R.Step_Index := I;
            if A.Subject = 0 or else A.Subject > U.Item_Count or else Seen (A.Subject) then
               R.Code := Invalid_Action; return;
            end if;
            Seen (A.Subject) := True;
            if U.Items (A.Subject).Pin = Keep_State then R.Code := Policy_Violation; return; end if;
            if Fuel < U.Node_Count then R.Code := Limit_Reached; return; end if;
            Fuel := Fuel - U.Node_Count; Evaluate (U, S, V);
            case A.Kind is
               when Add_Item =>
                  if S (A.Subject) or else not P.Selected (A.Subject) then R.Code := Invalid_Action; return; end if;
                  Pre_ID := U.Items (A.Subject).Add_Pre; Post_ID := U.Items (A.Subject).Add_Post;
               when Remove_Item =>
                  if not S (A.Subject) or else P.Selected (A.Subject) then R.Code := Invalid_Action; return; end if;
                  Pre_ID := U.Items (A.Subject).Remove_Pre; Post_ID := U.Items (A.Subject).Remove_Post;
               when Reinstall_Item =>
                  if not S (A.Subject) or else not P.Selected (A.Subject)
                    or else not U.Items (A.Subject).Reinstall_Requested then R.Code := Invalid_Action; return; end if;
                  Pre_ID := U.Items (A.Subject).Add_Pre; Post_ID := U.Items (A.Subject).Add_Post;
            end case;
            if not Predicate_Holds (Pre_ID, V) then R.Code := Precondition_Failed; return; end if;
            S (A.Subject) := A.Kind /= Remove_Item;
            if Fuel < U.Node_Count then R.Code := Limit_Reached; return; end if;
            Fuel := Fuel - U.Node_Count; Evaluate (U, S, V);
            if not Predicate_Holds (Post_ID, V) then R.Code := Postcondition_Failed; return; end if;
            Check_State (U, S, False, R, Fuel); R.Step_Index := I;
            if R.Code /= Valid_Selection then return; end if;
         end;
      end loop;
      if S /= P.Selected then R.Code := Final_Mismatch; return; end if;
      for I in 1 .. U.Item_Count loop
         if U.Items (I).Reinstall_Requested and then not Seen (I) then
            R.Code := Final_Mismatch; R.Item_Index := I; return;
         end if;
      end loop;
      R := (Code => Valid_Schedule, Transfer_Bytes => Total, others => <>);
   end Check_Schedule;
end Resolver_Verify;
