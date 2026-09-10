-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Payload_Index; with Pkg_Selected_Catalog;
package Pkg_Catalog_Store with SPARK_Mode => Off is
   Header_Size : constant := 56;
   Entry_Size : constant := 96;
   Max_Bytes : constant := Header_Size + Entry_Size * Pkg_Selected_Catalog.Max_Packages;
   procedure Save (Store : in out MC_Store.Store; Value : Pkg_Selected_Catalog.Catalog;
                   Deadline : Counter; Address : out Digest; Status : out Outcome);
   procedure Load (Store : in out MC_Store.Store; Address : Digest; Deadline : Counter;
                   Value : in out Pkg_Selected_Catalog.Catalog;
                   Payload : in out Pkg_Payload_Index.Index; Status : out Outcome);
   -- NIACSEL1 is the existing catalog fingerprint preimage, stored in the same
   -- immutable CAS. Save returns that fingerprint, not a second catalog ID.
   -- Load rejects noncanonical framing/order and reobserves every original DEB,
   -- all control metadata and payload claims before exposing either output.
   -- Missing originals cannot be replaced by cached metadata or an empty set.
   -- All Load failures clear both previous and partial outputs; Save never
   -- changes its input and returns a zero address on failure.
   -- Both calls refuse UID 0. Load may populate derived objects in the same CAS;
   -- failed/expired work may leave unreferenced objects, never accepted state.
   -- Deadlines surround synchronous CAS operations; an outer process deadline
   -- and resource scope remain required for whole-object hashing and library IO.
   -- This stores candidate data, not an installed-state pointer or authority.
   -- Accepted-generation binding, writer reservation, supply authentication,
   -- dependency/phase/effect validation, CAS pins and root/boot remain mandatory.
end Pkg_Catalog_Store;
