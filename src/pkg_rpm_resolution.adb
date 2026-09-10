-- SPDX-License-Identifier: BSD-3-Clause
with Pkg_EVR; with Pkg_Versions; with Resolver_Builder;
package body Pkg_RPM_Resolution with SPARK_Mode is
   use Pkg_Dependency; use type Pkg_Versions.Ordering;
   use type Resolver_Model.Node_ID; use type Resolver_Model.Item_ID;
   subtype Version_Relation is Relation range LT..GT;
   subtype Boolean_Operator is Operator range And_Op..Unless_Op;
   type Matching is array (Positive range 1 .. Resolver_Model.Max_Items) of Boolean with Pack;
   type Match_Table is array (Positive range 1 .. Pkg_Dependency.Max_Nodes) of Matching;
   procedure Spend (Fuel : in out Natural; Status : in out Outcome) is
   begin if Status = OK then if Fuel = 0 then Status := Exhausted; else Fuel := Fuel - 1; end if; end if; end;
   function Supported (E : Expression) return Boolean is
      Has_If, Has_Unless : array (Positive range 1 .. Pkg_Dependency.Max_Nodes) of Boolean := (others => False);
   begin
      if not Well_Formed (E) then return False; end if;
      for I in 1 .. E.Count loop
         declare N : Node renames E.Nodes (I); begin
            if N.Op /= Capability then
               Has_If (I) := N.Op = If_Op or Has_If (N.Left) or Has_If (N.Right);
               Has_Unless (I) := N.Op = Unless_Op or Has_Unless (N.Left) or Has_Unless (N.Right);
               if N.Alternative /= 0 then
                  Has_If (I) := Has_If (I) or Has_If (N.Alternative);
                  Has_Unless (I) := Has_Unless (I) or Has_Unless (N.Alternative);
               end if;
               if (N.Op = Or_Op and then Has_If (I)) or else
                  (N.Op = And_Op and then Has_Unless (I)) or else
                  (N.Op in With_Op | Without_Op and then (Has_If (I) or Has_Unless (I)))
               then return False; end if;
            end if;
         end;
      end loop;
      return True;
   end Supported;
   procedure Build_Matches (E : Expression; Facts : Providers; Item_Count : Resolver_Model.Item_ID;
      T : out Match_Table; Status : out Outcome; Fuel : in out Natural) with
     Post => (if Status=OK then Well_Formed(E))
   is
      AV, BV : Pkg_EVR.EVR; Ordering : Pkg_Versions.Ordering; Hit : Boolean;
   begin
      T := (others => (others => False)); Status := Invalid_Input;
      if not Well_Formed (E) or else Item_Count = 0 or else Facts'Length > Max_Provider_Facts then return; end if;
      if not Supported (E) then Status := Unsupported; return; end if;
      -- Validate every fact, not only selected or matching facts. Dormant
      -- malformed facts must not become a second semantics after a plan change.
      Status := OK;
      for K in Facts'Range loop
         pragma Loop_Invariant(for all J in Facts'First..K-1 => Facts(J).Owner in 1..Item_Count);
         declare F : Provider renames Facts(K); begin
         Spend (Fuel, Status); if Status /= OK then return; end if;
         if F.Owner = 0 or else F.Owner > Item_Count or else MC_Text.Length (F.Name) = 0 then Status := Invalid_Input; return; end if;
         if F.Versioned then
            Pkg_EVR.Parse (MC_Text.Image (F.Version), AV, Status); if Status /= OK then return; end if;
            if MC_Text.Length(AV.Version)=0 then Status:=Invalid_Input; return; end if;
         elsif MC_Text.Length (F.Version) /= 0 then Status := Invalid_Input; return; end if;
         end;
      end loop;
      Status := OK;
      for I in 1 .. E.Count loop
         declare N : Node renames E.Nodes (I); begin
            if N.Op = Capability then
               if N.Comparison /= Any_Version then Pkg_EVR.Parse (MC_Text.Image (N.Version), BV, Status); if Status /= OK then return; end if; end if;
               for F of Facts loop
                  Spend (Fuel, Status); if Status /= OK then return; end if;
                  if MC_Text.Equal (F.Name, N.Name) then
                     Hit := N.Comparison = Any_Version;
                     if N.Comparison /= Any_Version and then F.Versioned then
                        Pkg_EVR.Parse (MC_Text.Image (F.Version), AV, Status); if Status /= OK then return; end if;
                        Ordering := Pkg_EVR.Compare (AV, BV, Dependency_Match => True);
                        case Version_Relation(N.Comparison) is
                           when LT => Hit := Ordering = Pkg_Versions.Older;
                           when LE => Hit := Ordering /= Pkg_Versions.Newer;
                           when EQ => Hit := Ordering = Pkg_Versions.Equal;
                           when GE => Hit := Ordering /= Pkg_Versions.Older;
                           when GT => Hit := Ordering = Pkg_Versions.Newer;
                        end case;
                     end if;
                     T (I) (F.Owner) := T (I) (F.Owner) or Hit;
                  end if;
               end loop;
            else
               for J in 1 .. Item_Count loop
                  Spend (Fuel, Status); if Status /= OK then return; end if;
                  case Boolean_Operator(N.Op) is
                     when And_Op | With_Op => T (I) (J) := T (N.Left) (J) and T (N.Right) (J);
                     when Or_Op => T (I) (J) := T (N.Left) (J) or T (N.Right) (J);
                     when Without_Op => T (I) (J) := T (N.Left) (J) and not T (N.Right) (J);
                     when If_Op =>
                        T (I) (J) := (if T (N.Right) (J) then T (N.Left) (J)
                          elsif N.Alternative = 0 then True else T (N.Alternative) (J));
                     when Unless_Op =>
                        T (I) (J) := (if not T (N.Right) (J) then T (N.Left) (J)
                          elsif N.Alternative = 0 then True else T (N.Alternative) (J));
                  end case;
               end loop;
            end if;
         end;
      end loop;
   end Build_Matches;
   procedure Check_Native (E : Expression; Facts : Providers;
      Item_Count : Resolver_Model.Item_ID; Selected : Resolver_Model.Selection;
      Satisfied : out Boolean; Status : out Outcome; Fuel : in out Natural) is
      T : Match_Table; V : array (Positive range 1 .. Pkg_Dependency.Max_Nodes) of Boolean := (others => False);
   begin
      Satisfied := False; Build_Matches (E, Facts, Item_Count, T, Status, Fuel); if Status /= OK then return; end if;
      for J in Item_Count + 1 .. Resolver_Model.Max_Items loop
         if Selected (J) then Status := Invalid_Input; return; end if;
      end loop;
      for I in 1 .. E.Count loop
         declare N : Node renames E.Nodes (I); begin
            case N.Op is
               when Capability | With_Op | Without_Op =>
                  for J in 1 .. Item_Count loop
                     Spend (Fuel, Status); if Status /= OK then return; end if;
                     V (I) := V (I) or (T (I) (J) and Selected (J));
                  end loop;
               when And_Op => V (I) := V (N.Left) and V (N.Right);
               when Or_Op => V (I) := V (N.Left) or V (N.Right);
               when If_Op => V (I) := (if V (N.Right) then V (N.Left) elsif N.Alternative = 0 then True else V (N.Alternative));
               when Unless_Op => V (I) := (if not V (N.Right) then V (N.Left) elsif N.Alternative = 0 then True else V (N.Alternative));
            end case;
         end;
      end loop;
      Satisfied := V (E.Root);
   end Check_Native;
   procedure Lower (E : Expression; Facts : Providers;
      U : in out Resolver_Model.Universe; Root : out Resolver_Model.Node_ID;
      Status : out Outcome; Fuel : in out Natural) is
      T : Match_Table;
      V : array (Positive range 1 .. Pkg_Dependency.Max_Nodes) of Resolver_Model.Node_ID := (others => 0);
      Original_Count : constant Resolver_Model.Node_ID := U.Node_Count;
      A, B, C, Y, Z : Resolver_Model.Node_ID; X : Resolver_Model.Node_ID := 0;
      procedure Join (Op : Resolver_Model.Operator; L, R : Resolver_Model.Node_ID; Result : out Resolver_Model.Node_ID) is
      begin
         Result := 0; if Status /= OK then return; end if;
         Resolver_Builder.Combine (U, Op, L, R, Result, Status);
      end;
   begin
      Root := 0;
      Build_Matches (E, Facts, U.Item_Count, T, Status, Fuel); if Status /= OK then return; end if;
      for I in 1 .. E.Count loop
         declare N : Node renames E.Nodes (I); begin
            case N.Op is
               when Capability | With_Op | Without_Op =>
                  Resolver_Builder.Boolean_Constant (U, False, A, Status);
                  for J in 1 .. U.Item_Count loop
                     Spend (Fuel, Status); exit when Status /= OK;
                     if T (I) (J) then
                        Resolver_Builder.Presence (U, J, B, Status); exit when Status /= OK;
                        Join (Resolver_Model.Or_Op, A, B, C); exit when Status /= OK; A := C;
                     end if;
                  end loop;
                  V (I) := A;
               when And_Op => Join (Resolver_Model.And_Op, V (N.Left), V (N.Right), V (I));
               when Or_Op => Join (Resolver_Model.Or_Op, V (N.Left), V (N.Right), V (I));
               when If_Op | Unless_Op =>
                  B := V (N.Right);
                  if N.Op = Unless_Op then
                     Resolver_Builder.Negate (U, B, C, Status); if Status = OK then B := C; end if;
                  end if;
                  if Status = OK then Resolver_Builder.Negate (U, B, X, Status); end if;
                  if N.Alternative = 0 then
                     Join (Resolver_Model.Or_Op, X, V (N.Left), V (I));
                  else
                     Join (Resolver_Model.And_Op, B, V (N.Left), Y);
                     Join (Resolver_Model.And_Op, X, V (N.Alternative), Z);
                     Join (Resolver_Model.Or_Op, Y, Z, V (I));
                  end if;
            end case;
         end;
         if Status /= OK then
            -- No partial projection is published. Unused storage is not encoded.
            U.Node_Count := Original_Count; return;
         end if;
      end loop;
      Root := V (E.Root);
   end Lower;
   procedure Check_Rule (Owner : Resolver_Model.Item_ID; Kind : Dependency_Kind;
      E : Expression; Facts : Providers; Item_Count : Resolver_Model.Item_ID;
      Selected : Resolver_Model.Selection; Satisfied : out Boolean;
      Status : out Outcome; Fuel : in out Natural) is
      Value : Boolean;
   begin
      Satisfied := False; Status := Invalid_Input;
      if Owner = 0 or else Owner > Item_Count then return; end if;
      -- Reject the unsupported native conflict-if context even for an absent
      -- owner. Raw input is not allowed to hide malformed dormant constraints.
      if Kind = Conflicting_Dependency then
         for I in 1 .. E.Count loop
            if E.Nodes (I).Op = If_Op then Status := Unsupported; return; end if;
         end loop;
      end if;
      Check_Native (E, Facts, Item_Count, Selected, Value, Status, Fuel);
      if Status = OK then
         Satisfied := not Selected (Owner) or else
           (if Kind = Required_Dependency then Value else not Value);
      end if;
   end Check_Rule;
   procedure Add_Rule (Owner : Resolver_Model.Item_ID; Kind : Dependency_Kind;
      E : Expression; Facts : Providers; Scope : Resolver_Model.Rule_Scope;
      Origin : Digest; U : in out Resolver_Model.Universe;
      Status : out Outcome; Fuel : in out Natural) is
      Old_Count : constant Resolver_Model.Node_ID := U.Node_Count;
      R, Condition : Resolver_Model.Node_ID; P, Not_P, Both : Resolver_Model.Node_ID := 0;
   begin
      Status := Invalid_Input;
      if Owner = 0 or else Owner > U.Item_Count or else Is_Zero (Origin) then return; end if;
      if Kind = Conflicting_Dependency then
         for I in 1 .. E.Count loop
            if E.Nodes (I).Op = If_Op then Status := Unsupported; return; end if;
         end loop;
      end if;
      Lower (E, Facts, U, R, Status, Fuel); if Status /= OK then return; end if;
      Condition := R;
      if Kind = Conflicting_Dependency then Resolver_Builder.Negate (U, R, Condition, Status); end if;
      if Status = OK then Resolver_Builder.Presence (U, Owner, P, Status); end if;
      if Status = OK then Resolver_Builder.Negate (U, P, Not_P, Status); end if;
      if Status = OK then Resolver_Builder.Combine (U, Resolver_Model.Or_Op, Not_P, Condition, Both, Status); end if;
      if Status = OK then Resolver_Builder.Require (U, Both, Scope, Origin, Status); end if;
      if Status /= OK then U.Node_Count := Old_Count; end if;
   end Add_Rule;
end Pkg_RPM_Resolution;
