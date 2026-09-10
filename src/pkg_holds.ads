-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Maintenance;
package Pkg_Holds with SPARK_Mode, Pure is
   Max_Holds : constant := 64;
   subtype Hold_Index is Positive range 1 .. Max_Holds;
   type Hold_Array is array (Hold_Index) of MC_Maintenance.Hold;
   type Catalog is record
      Repository, Policy : Digest := Zero_Digest;
      Epoch : Counter := 0;
      Count : Natural range 0 .. Max_Holds := 0;
      Items : Hold_Array;
   end record;
   type Operation is (Apply, Accept_Change, Commit);
   function Valid (C : Catalog) return Boolean with Global => null;
   function Blocked (C : Catalog; Subject : Digest; Op : Operation; Now : Counter) return Boolean
     with Global => null;
   -- Holds are authenticated repository/site metadata. A bypass is not represented
   -- here; emergency exceptions must be a separately authorized change contract.
end Pkg_Holds;
