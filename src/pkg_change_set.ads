-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Pkg_Advisory;
package Pkg_Change_Set with SPARK_Mode, Pure is
   Max_Items : constant := 256;
   subtype Item_Index is Positive range 1 .. Max_Items;
   type Change_Kind is (Install, Upgrade, Downgrade, Remove, Reinstall);
   type Item is record
      Package_ID, From_Build, To_Build, Contract : Digest := Zero_Digest;
      Kind : Change_Kind := Install;
      Activation : Pkg_Advisory.Activation := Pkg_Advisory.Immediate;
      Is_Protected : Boolean := False;
   end record;
   type Items is array (Item_Index) of Item;
   type Set is record
      ID, Repository, Incorporation, Policy : Digest := Zero_Digest;
      Base_Generation : Counter := 0;
      Count : Natural range 0 .. Max_Items := 0;
      Changes : Items;
   end record;
   function Valid (S : Set) return Boolean with Global => null;
   function Maximum_Activation (S : Set) return Pkg_Advisory.Activation with Global => null;
   -- All installs/removes/upgrades in one operator request are solved and admitted as
   -- one immutable set. Partial success is never a new accepted baseline.
end Pkg_Change_Set;
