-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Supply_Map;
package Pkg_Supply_Policy with SPARK_Mode => Off is
   Header_Size : constant := 56;
   Entry_Size : constant := 80;
   Max_Bytes : constant := Header_Size + Entry_Size * Pkg_Supply_Map.Max_Authorities;
   type Snapshot is record
      Map : Digest := Zero_Digest;
      Observed_At : Counter := 0;
      Count : Natural range 0 .. Pkg_Supply_Map.Max_Authorities := 0;
      Trusted : Pkg_Supply_Map.Authorities (1 .. Pkg_Supply_Map.Max_Authorities);
   end record;
   procedure Prepare (Store : in out MC_Store.Store; Map : Digest; Target : Pkg_Supply_Map.Context;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter;
      Address : out Digest; Valid_Until : out Counter; Status : out Outcome);
   procedure Load (Store : MC_Store.Store; Address : Digest; Deadline : Counter;
      Value : out Snapshot; Status : out Outcome);
   procedure Verify_New (Store : in out MC_Store.Store; Address : Digest; Target : Pkg_Supply_Map.Context;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter;
      Valid_Until : out Counter; Status : out Outcome);
   procedure Recheck_Recorded (Store : in out MC_Store.Store; Address : Digest; Target : Pkg_Supply_Map.Context;
      Trusted : Pkg_Supply_Map.Authorities; Now, Deadline : Counter; Status : out Outcome);
   -- Requires the independent policy to STILL match. Only receipt freshness is
   -- evaluated at the retained observation. The publisher must first prove the
   -- exact transaction is active/accepted with an intact journal. This API alone
   -- establishes no such fact and must never replace Verify_New for admission.
   procedure Check_Retention (Store : MC_Store.Store; Address, Catalog, Closure : Digest;
      Deadline : Counter; Status : out Outcome);
   -- NIASPOL1 retains a map, observation UTC second and strictly scope-sorted
   -- independent authority snapshot. It is an input, never a self-issued grant.
   -- Verify_New compares the complete snapshot to independently provided current
   -- policy and verifies all receipts over the interval [Observed_At, Now].
   -- The publisher must bind this object through its authenticated physical plan
   -- and establish actual admitted root.state/journal before historical recheck.
   -- Load/Check_Retention alone do not authenticate policy or observation time.
   -- No installed database, sidecar, second pin or clock modification is added.
   -- Every operation refuses UID0 and requires a finite live I/O deadline.
end Pkg_Supply_Policy;
