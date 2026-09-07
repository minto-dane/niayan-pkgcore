-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Text;
with Pkg_Dependency; with Resolver_Model;
package Pkg_RPM_Resolution with SPARK_Mode is
   type Dependency_Kind is (Required_Dependency, Conflicting_Dependency);
   type Provider is record
      Owner : Resolver_Model.Item_ID := 0;
      Name, Version : MC_Text.Value;
      Versioned : Boolean := False;
   end record;
   type Providers is array (Positive range <>) of Provider;
   Max_Provider_Facts : constant := 131_072;
   procedure Lower (E : Pkg_Dependency.Expression; Facts : Providers;
      U : in out Resolver_Model.Universe; Root : out Resolver_Model.Node_ID;
      Status : out Outcome; Fuel : in out Natural) with Global => null;
   procedure Check_Native (E : Pkg_Dependency.Expression; Facts : Providers;
      Item_Count : Resolver_Model.Item_ID; Selected : Resolver_Model.Selection;
      Satisfied : out Boolean; Status : out Outcome; Fuel : in out Natural) with Global => null;
   procedure Add_Rule (Owner : Resolver_Model.Item_ID; Kind : Dependency_Kind;
      E : Pkg_Dependency.Expression; Facts : Providers;
      Scope : Resolver_Model.Rule_Scope; Origin : Digest;
      U : in out Resolver_Model.Universe; Status : out Outcome; Fuel : in out Natural)
      with Global => null;
   procedure Check_Rule (Owner : Resolver_Model.Item_ID; Kind : Dependency_Kind;
      E : Pkg_Dependency.Expression; Facts : Providers;
      Item_Count : Resolver_Model.Item_ID; Selected : Resolver_Model.Selection;
      Satisfied : out Boolean; Status : out Outcome; Fuel : in out Natural)
      with Global => null;
   -- Lower and Check_Native use the independent native EVR parser/comparator,
   -- NEVER libsolv's version/matching/selection data. All facts must be derived
   -- from authenticated RPM headers + complete file ownership inventory.
   -- Boolean Provides / versioned non-equality Provides are not represented by
   -- this profile and must be refused by the source adapter, not flattened.
end Pkg_RPM_Resolution;
