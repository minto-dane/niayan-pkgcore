-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Text; with Pkg_Dependency;
with Pkg_RPM_Resolution; with Resolver_Model; with Test_Support; use Test_Support;
procedure Run_Pkg_Resolution_Tests with SPARK_Mode => Off is
   type UA is access Resolver_Model.Universe;
   U : constant UA := new Resolver_Model.Universe;
   Facts : Pkg_RPM_Resolution.Providers (1 .. 4);
   Selected : Resolver_Model.Selection := (others => False);
   E : Pkg_Dependency.Expression; S : Outcome; Fuel : Natural; Native : Boolean;
   Root : Resolver_Model.Node_ID; V : Resolver_Model.Truth_Array;
   procedure Field (Target : out MC_Text.Value; Text : String) is
   begin MC_Text.Set (Target, Text, S); Expect (S = OK, "set"); end;
   procedure Compare (Text : String; Want : Boolean) is
   begin
      Pkg_Dependency.Parse (Text, E, S); Expect (S = OK, "parse " & Text);
      Fuel := 10_000_000;
      Pkg_RPM_Resolution.Check_Native (E, Facts, 3, Selected, Native, S, Fuel);
      Expect (S = OK and then Native = Want, "native " & Text);
      U.Node_Count := 0; Fuel := 10_000_000;
      Pkg_RPM_Resolution.Lower (E, Facts, U.all, Root, S, Fuel);
      Expect (S = OK and then Resolver_Model.Well_Formed (U.all), "lower " & Text);
      Resolver_Model.Evaluate (U.all, Selected, V);
      Expect (V (Root) = Native, "dual-interpretation " & Text);
   end;
begin
   U.Subject := (Root => (others => 1), Boot => (others => 2), Snapshot => (others => 3),
      Policy => (others => 4), Adapter_Set => (others => 5), Native_Inventory => (others => 6),
      Configuration => (others => 7), Effect_Contracts => (others => 8), Generation => 1);
   U.Item_Count := 3; U.Maximum_Changes := 3;
   for I in 1 .. 3 loop
      U.Items (I) := (Object_Hash => (others => Byte (I)), Metadata_Hash => (others => 30),
         Adapter_Hash => (others => 31), Permitted => True, others => <>);
   end loop;
   Facts (1).Owner := 1; Field (Facts (1).Name, "a");
   Facts (2).Owner := 2; Field (Facts (2).Name, "b");
   Facts (3).Owner := 3; Field (Facts (3).Name, "a");
   Facts (4).Owner := 3; Field (Facts (4).Name, "b");
   Selected (1) := True; Selected (2) := True;
   Compare ("(a and b)", True); Compare ("(a with b)", False);
   Compare ("(a without b)", True); Compare ("(a if b)", True);
   Selected (1) := False; Selected (2) := False; Selected (3) := True;
   Compare ("(a with b)", True); Compare ("(a without b)", False);
   Selected := (others => False); Compare ("(a if b)", True);
   Compare ("(a unless b)", False);
   Selected (1) := True; Facts (1).Versioned := True; Field (Facts (1).Version, "2:1.0-4");
   Compare ("a >= 1:99.0", True); Compare ("a = 2:1.0", True);
   Compare ("a > 2:1.0-4", False);
   -- Dependency constraints are conditional on owning artifact selection;
   -- a repository package that is not selected imposes no positive dependency.
   Pkg_Dependency.Parse ("b", E, S); Expect (S = OK, "owner-expression");
   Selected := (others => False); Selected (1) := True;
   U.Node_Count := 0; U.Rule_Count := 0; Fuel := 10_000_000;
   Pkg_RPM_Resolution.Add_Rule (1, Pkg_RPM_Resolution.Required_Dependency,
      E, Facts, Resolver_Model.Final_State, (others => 20), U.all, S, Fuel);
   Expect (S = OK and then U.Rule_Count = 1, "owner-guarded-rule");
   Resolver_Model.Evaluate (U.all, Selected, V);
   Expect (not V (U.Rules (1).Predicate), "selected-owner-missing-dependency");
   Selected (1) := False; Resolver_Model.Evaluate (U.all, Selected, V);
   Expect (V (U.Rules (1).Predicate), "unselected-owner-no-obligation");
   Fuel := 10_000_000;
   Pkg_RPM_Resolution.Check_Rule (1, Pkg_RPM_Resolution.Required_Dependency,
      E, Facts, 3, Selected, Native, S, Fuel);
   Expect (S = OK and then Native, "native-owner-guard");
   Pkg_Dependency.Parse ("(a if b)", E, S); Expect (S = OK, "conflict-parse");
   Fuel := 10_000_000;
   Pkg_RPM_Resolution.Check_Rule (1, Pkg_RPM_Resolution.Conflicting_Dependency,
      E, Facts, 3, Selected, Native, S, Fuel);
   Expect (S /= OK, "RPM-conflict-if-refused-even-dormant");
   Facts (4).Owner := 0; Fuel := 10_000_000;
   Pkg_RPM_Resolution.Check_Native (E, Facts, 3, Selected, Native, S, Fuel);
   Expect (S /= OK, "unselected-malformed-provider-refused");
end Run_Pkg_Resolution_Tests;
