-- SPDX-License-Identifier: BSD-3-Clause
with MC_Text; with MC_Types; use MC_Types;
package Pkg_Deb_Semantics with SPARK_Mode is
   type Relation is (Any_Version, Less_Than, At_Most, Exactly, At_Least, Greater_Than);
   type Qualifier is (Unqualified, Native, AMD64, Any_Architecture);
   type Architecture is (Native_AMD64, Independent_All, Unsupported_Architecture);
   type Multi_Arch is (No, Same, Foreign, Allowed);
   type Requirement is record
      Name, Version : MC_Text.Value;
      Operator : Relation := Any_Version;
      Arch : Qualifier := Unqualified;
   end record;
   type Capability is record
      Name, Version : MC_Text.Value;
      Versioned : Boolean := False;
      Arch : Architecture := Native_AMD64;
      Multi : Multi_Arch := No;
   end record;
   procedure Matches (Need : Requirement; Fact : Capability;
      Satisfied : out Boolean; Status : out Outcome) with Global => null;
   type Relation_Kind is (Depends, Pre_Depends, Breaks, Conflicts, Replaces,
      Recommends, Suggests, Enhances, Built_Using, Static_Built_Using);
   type Boundary is (Before_Unpack, Before_Configure, Ready_Endpoint, Removal, Source_Retention);
   function Requires_Check (Kind : Relation_Kind; At_Point : Boundary) return Boolean
      with Global => null;
   -- State semantics are deliberately not flattened into Resolver_Model's
   -- two-state Installed bit. Pre-Depends/configured-version exceptions and
   -- cycles require a full phased adapter. No execution permission is returned.
   -- Replaces permits neither dependency satisfaction nor an unreviewed overwrite.
end Pkg_Deb_Semantics;
