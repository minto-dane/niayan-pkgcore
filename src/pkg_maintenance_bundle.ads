-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_Maintenance_Bundle with SPARK_Mode, Pure is
   Capacity : constant := 128;
   subtype Item_Index is Positive range 1..Capacity;
   type Item is record
      Package_ID, Required_Build, Advisory : Digest := Zero_Digest;
      Required : Boolean := False;
   end record;
   type Items is array(Item_Index) of Item;
   type Bundle is record
      ID, Repository, Policy, Baseline : Digest := Zero_Digest;
      Epoch, Security_Epoch : Counter := 0;
      Count : Natural range 0..Capacity := 0;
      Content : Items;
      Cumulative, Signed, Withdrawn : Boolean := False;
   end record;
   type Inventory_Item is record Package_ID, Build : Digest := Zero_Digest; end record;
   type Inventory is array(Item_Index) of Inventory_Item;
   function Valid (B : Bundle) return Boolean with Global=>null;
   function Satisfied (B : Bundle; I : Inventory; Count : Natural) return Boolean with Global=>null;
end Pkg_Maintenance_Bundle;
