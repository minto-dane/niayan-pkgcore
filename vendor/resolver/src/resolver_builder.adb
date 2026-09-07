-- SPDX-License-Identifier: MIT
package body Resolver_Builder with SPARK_Mode is
   procedure Append (U : in out Universe; N : Expression_Node; ID : out Node_ID; Status : out Outcome) is
   begin
      ID := 0; Status := Exhausted; if U.Node_Count = Max_Nodes then return; end if;
      U.Node_Count := U.Node_Count + 1; U.Nodes (U.Node_Count) := N; ID := U.Node_Count; Status := OK;
   end Append;
   procedure Boolean_Constant (U : in out Universe; Value : Boolean; ID : out Node_ID; Status : out Outcome) is
   begin Append (U, (Op => (if Value then Constant_True else Constant_False), others => <>), ID, Status); end;
   procedure Presence (U : in out Universe; Item : Item_ID; ID : out Node_ID; Status : out Outcome) is
   begin
      ID := 0; Status := Invalid_Input; if Item = 0 or else Item > U.Item_Count then return; end if;
      Append (U, (Op => Present, Subject => Item, others => <>), ID, Status);
   end;
   procedure Negate (U : in out Universe; A : Node_ID; ID : out Node_ID; Status : out Outcome) is
   begin
      ID := 0; Status := Invalid_Input; if A = 0 or else A > U.Node_Count then return; end if;
      Append (U, (Op => Not_Op, Left => A, others => <>), ID, Status);
   end;
   procedure Combine (U : in out Universe; Op : Operator; A, B : Node_ID;
      ID : out Node_ID; Status : out Outcome) is
   begin
      ID := 0; Status := Invalid_Input;
      if Op not in And_Op | Or_Op or else A = 0 or else B = 0 or else A > U.Node_Count or else B > U.Node_Count then return; end if;
      Append (U, (Op => Op, Left => A, Right => B, others => <>), ID, Status);
   end;
   procedure Require (U : in out Universe; Predicate : Node_ID; Scope : Rule_Scope;
      Origin : Digest; Status : out Outcome) is
   begin
      Status := Invalid_Input;
      if Predicate = 0 or else Predicate > U.Node_Count or else Is_Zero (Origin) then return; end if;
      Status := Exhausted; if U.Rule_Count = Max_Rules then return; end if;
      U.Rule_Count := U.Rule_Count + 1; U.Rules (U.Rule_Count) := (Predicate, Scope, Origin); Status := OK;
   end;
end Resolver_Builder;
