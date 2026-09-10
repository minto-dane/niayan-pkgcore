-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with Resolver_Model; use Resolver_Model;
package Resolver_Admission with SPARK_Mode, Pure is
   -- Format-independent coverage dimensions, NOT native-format feature flags.
   -- Source_Mark is computed by the independently authenticated reader. Each
   -- Coverage record must be obtained outside the untrusted proposer process.
   type Dimension is (Identity, Compatibility, Selection_Rules, Ownership,
      Phase_Order, Configuration, Side_Effects, Generated_State, Recovery);
   type Marks is array (Dimension) of Digest;
   type Coverage is record
      Artifact, Adapter, Source_Mark, Evidence : Digest := Zero_Digest;
      Observed, Interpreted : Marks := (others => Zero_Digest);
      Unsupported_Count : Natural := 0;
   end record;
   type Coverage_Array is array (Positive range 1 .. Max_Items) of Coverage;
   type Admission is record
      Subject : Binding;
      Native_Source, Universe_Hash, Physical_Plan, Reservation : Digest := Zero_Digest;
      Expires, Trust_Floor : Counter := 0;
      Count : Item_ID := 0;
      Items : Coverage_Array;
   end record;
   procedure Check (U : Universe; A : Admission; Expected : Binding;
      Expected_Universe, Expected_Source, Expected_Plan, Expected_Reservation : Digest;
      Now, Required_Floor : Counter; Status : out Outcome) with Global => null;
   -- This compares coverage; it does NOT establish that a reader is correct,
   -- a declaration is true, a signature is valid or a native equivalence theorem
   -- exists. Those are mandatory external admission obligations, never solver data.
end Resolver_Admission;
