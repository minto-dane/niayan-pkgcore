-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Incorporation with SPARK_Mode, Pure is
   Max_Members : constant := 256;
   subtype Member_Index is Positive range 1 .. Max_Members;
   type Member is record
      Name, EVR, Package_Digest : Digest := Zero_Digest;
      Required : Boolean := True;
   end record;
   type Members is array (Member_Index) of Member;
   type Incorporation is record
      ID, Policy, Repository : Digest := Zero_Digest;
      Epoch : Counter := 0;
      Count : Natural range 0 .. Max_Members := 0;
      Items : Members;
   end record;
   type Inventory_Entry is record
      Name, EVR, Package_Digest : Digest := Zero_Digest;
   end record;
   type Inventory is array (Member_Index) of Inventory_Entry;
   function Valid (I : Incorporation) return Boolean with Global => null;
   function Satisfied (I : Incorporation; Installed : Inventory; Installed_Count : Natural) return Boolean
     with Global => null;
   -- A release incorporation expresses a tested system composition, not merely
   -- pairwise dependencies. It intentionally refuses unknown substitutions.
end Pkg_Incorporation;
