-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Root_Configuration; with Pkg_Root_Archive;
with Pkg_Catalog_Retention;
package Pkg_Configured_Root with SPARK_Mode => Off is
   Header_Size : constant := 320;
   Retention_Header_Size : constant := 48;
   Max_Objects : constant := Pkg_Catalog_Retention.Max_Objects +
      40 * Pkg_Root_Configuration.Max_Choices + 8;
   procedure Build (Store : in out MC_Store.Store; Base_Manifest, Catalog, Catalog_Closure : Digest;
      Root_ID, Transaction : Identity; Context : Digest; Native_Architecture : String;
      Selected : Pkg_Root_Configuration.Choices; Limit, Deadline : Counter;
      Manifest, Archive, Retained : out Digest; Status : out Outcome);
   procedure Verify (Store : in out MC_Store.Store; Manifest, Retained : Digest;
      Base_Manifest, Catalog, Catalog_Closure : Digest; Root_ID, Transaction : Identity;
      Context : Digest; Native_Architecture : String; Selected : Pkg_Root_Configuration.Choices;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome);
   -- Build a complete tar from a freshly verified configuration layout. Original
   -- base spans remain byte-exact; regular configuration entries use retained
   -- attributes/content. Root/parents and hardlink targets precede dependents.
   -- At most Pkg_Root_Archive.Max_Entries entries, Limit <= CAS object bound.
   -- NIACRT01 binds base/catalog/ownership, root/transaction/context, architecture,
   -- exact output and all ordered choices, including absent targets, plus each
   -- generated prefix/content. NIACRC01 contains the exact sorted transitive
   -- union of catalog/choice closures, base/root/manifest and generated objects.
   -- No second DB, pin, extraction, boot or admission. Choices are borrowed only
   -- during the call and live-rechecked before returning, never authenticated
   -- here. The same open Store reservation is required throughout.
   -- Verify checks retained objects before rebuilding/comparing, so valid saved
   -- references cannot be silently repaired from surviving sources. It requires
   -- live proposals; this is not a durable recovery loader or GC authority.
   -- Failed calls clear outputs; unreferenced completed CAS blobs may remain.
   -- UID0, infinite deadlines and unsupported configuration effects are refused.
end Pkg_Configured_Root;
