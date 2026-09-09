-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Store; with MC_Text; with Pkg_Generation_Descriptor; with Pkg_Deb_Final_Set;
package Pkg_Generation_Intent with SPARK_Mode => Off is
   Header_Size : constant := 192;
   -- The existing native architecture policy bounds apply to the wire too.
   Max_Bytes : constant := Header_Size + MC_Text.Max_Length
     + (4 + MC_Text.Max_Length) * Pkg_Deb_Final_Set.Max_Architectures;
   procedure Prepare (Store : in out MC_Store.Store; Root_ID : Identity;
      Before : Pkg_Generation_Descriptor.Descriptor; Before_Closure, Catalog, Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Deadline : Counter; Address, Binding : out Digest; Status : out Outcome);
   procedure Verify (Store : in out MC_Store.Store; Address : Digest; Root_ID : Identity;
      Before : Pkg_Generation_Descriptor.Descriptor; Before_Closure, Catalog, Closure : Digest;
      Deadline : Counter; Binding : out Digest; Status : out Outcome);
   procedure Check_Target (Store : MC_Store.Store; Address, Catalog, Closure : Digest;
      Deadline : Counter; Status : out Outcome);
   function Update_Binding (Before, Catalog, Closure, Transition : Digest) return Digest;
   -- NIAGINT1 records the exact root/predecessor, target catalog/closure,
   -- explicit canonical architecture policy, native result and binding. It is
   -- a retained input to the authenticated publication plan, not a grant itself.
   -- Prepare/Verify reobserve originals and both catalog closures. Verify uses
   -- the policy from the stored object and must receive the actual predecessor
   -- under the caller's writer reservation. No callback can replace the check.
   -- An empty predecessor denotes initial construction only: the candidate's
   -- final set is still checked. The publisher must prove the actual initial
   -- root state; this is not an override for protection loss or ordinary repair.
   -- Check_Target validates framing and target linkage only, not native meaning.
   -- Every API refuses UID 0 and requires a finite live deadline. Failure clears
   -- successful outputs. No installed state, pin, authority or boot is changed.
   -- A failed/expired Prepare may have saved an unreferenced immutable object;
   -- retry the same inputs instead of treating a cleared output as no CAS write.
   -- Existing manifest pins retain this object; a GC must traverse its typed
   -- predecessor/catalog references. The caller retains the open CAS reservation.
end Pkg_Generation_Intent;
