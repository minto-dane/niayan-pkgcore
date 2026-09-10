-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Selected_Catalog; with Pkg_Payload_Index;
with Pkg_Deb_Control;
package Pkg_Catalog_Retention with SPARK_Mode => Off is
   Header_Size : constant := 80;
   Max_Objects : constant := 1 + Pkg_Selected_Catalog.Max_Packages *
     (4 + Pkg_Deb_Control.Max_Entries) + 3 * Pkg_Payload_Index.Max_Claims;
   Max_Bytes : constant := Header_Size + 32 * Max_Objects;
   procedure Prepare (Store : in out MC_Store.Store; Catalog : Digest;
                      Deadline : Counter; Address : out Digest; Status : out Outcome);
   procedure Verify (Store : in out MC_Store.Store; Catalog, Address : Digest;
                     Deadline : Counter; Status : out Outcome);
   procedure Pin (Store : in out MC_Store.Store; ID : Identity; Catalog : Digest;
                  Deadline : Counter; Address : out Digest; Status : out Outcome);
   procedure Verify_Pin (Store : in out MC_Store.Store; ID : Identity;
                         Catalog, Address : Digest; Deadline : Counter; Status : out Outcome);
   -- NIACLOS1: tag[8], catalog[32], payload fingerprint[32], count[u64 BE],
   -- strictly ascending unique object digests[32]. The manifest itself is the
   -- pin target, not a self-reference. Members include the catalog, every original
   -- DEB, compressed control/data, expanded data tar, every regular control file,
   -- and payload content/link text/xattrs/ACLs. Empty packages remain represented.
   -- Original DEBs retain version and extension members; unused separately staged
   -- members and transient decoder buffers are not part of this closure profile.
   -- Prepare reobserves the catalog from originals and may reconstruct caches.
   -- Verify first checks every listed object without reconstruction, then compares
   -- against the independently reobserved exact closure; omissions/extras fail.
   -- Pins use the existing immutable CAS namespace; choose an unused identity,
   -- never a stage/publication transaction identity already pinned to another type.
   -- All calls refuse UID 0; failed Prepare/Pin clear Address. An uncertain or
   -- expired Pin may already exist: retry the same identity/catalog and verify it.
   -- Caller retains the open store's reservation throughout. Outer process time
   -- and memory limits remain required around synchronous hashing/decompression.
   -- This is catalog-derived retention, not whole-generation reachability, a GC
   -- deletion grant, supply authentication, root binding or execution authority.
   -- Generation plans/receipts, effects, trust and recovery roots need their own
   -- closures. No objects or pins are removed here; no second installed DB.
end Pkg_Catalog_Retention;
