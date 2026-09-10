-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Archive_Supply; with Pkg_Generation_Descriptor;
with Pkg_Selected_Catalog;
package Pkg_Supply_Map with SPARK_Mode => Off is
   Header_Size : constant := 160;
   Entry_Size : constant := 96;
   Max_Entries : constant := Pkg_Selected_Catalog.Max_Packages;
   Max_Bytes : constant := Header_Size + Entry_Size * Max_Entries;
   Max_Authorities : constant := 256;
   type Context is record
      Root_ID : Identity := Zero_Identity;
      Before : Pkg_Generation_Descriptor.Descriptor := Pkg_Generation_Descriptor.Empty;
      Before_Closure, Catalog, Closure : Digest := Zero_Digest;
   end record;
   type Source is record
      Original, Control, Receipt : Digest := Zero_Digest;
   end record;
   type Sources is array (Positive range <>) of Source;
   type Authorities is array (Positive range <>) of Pkg_Archive_Supply.Authority;
   procedure Prepare (Store : in out MC_Store.Store; Target : Context; Items : Sources;
      Trusted : Authorities; Now, Deadline : Counter;
      Address : out Digest; Valid_Until : out Counter; Status : out Outcome);
   procedure Verify (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Now, Deadline : Counter; Valid_Until : out Counter; Status : out Outcome);
   procedure Verify_Interval (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Observed_At, Now, Deadline : Counter;
      Valid_Until : out Counter; Status : out Outcome);
   -- Fresh verification additionally proves every receipt was valid at the
   -- proposed retained observation. Observed_At <= independently sampled Now.
   procedure Recheck_At (Store : in out MC_Store.Store; Address : Digest; Target : Context;
      Trusted : Authorities; Observed_At, Deadline : Counter; Status : out Outcome);
   -- Historical signature/native verification with a live I/O deadline. Policy
   -- and observation must come from an authenticated, already admitted plan.
   -- This never grants new admission and does not sample or change the OS clock.
   procedure Check_Retention (Store : MC_Store.Store; Address, Catalog, Closure : Digest;
      Deadline : Counter; Status : out Outcome);
   -- NIASMAP1 binds root, exact predecessor hash/closure and target catalog/closure
   -- to strictly original-sorted (original, control, supply receipt) rows.
   -- Rows must equal target originals minus predecessor originals, with exact
   -- native control hashes. No omission, extra row or same-name substitution.
   -- All catalogs/closures are independently reobserved under the same CAS lock.
   -- Prepare/Verify require independent scoped keys, floors, current UTC seconds
   -- and a finite BOOTTIME deadline. Elapsed time is included throughout and on
   -- return. Valid_Until is exclusive UTC; zero on failure or a successful empty
   -- difference (then only Deadline applies). Status must always be checked.
   -- Check_Retention checks canonical objects and all referenced receipt inputs
   -- without reconstruction, freshness or site trust. Historical retention is
   -- not fresh admission. It never grants deletion, execution or publication.
   -- Before is a caller assertion: the publication authority must prove it is
   -- the actual accepted descriptor under its writer reservation. This SDK does
   -- not read root.state, execute DEB effects, pin a generation or change its
   -- manifest. The v4 publisher supplies admission/recovery binding; typed
   -- whole-root GC and production policy/time providers remain.
   -- UID0 is refused. A failed Prepare may leave an unreferenced CAS object.
end Pkg_Supply_Map;
