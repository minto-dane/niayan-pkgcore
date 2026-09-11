-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Payload_Index;
package Pkg_Root_Archive with SPARK_Mode => Off is
   Max_Entries : constant := Pkg_Payload_Index.Max_Claims;
   Header_Size : constant := 152;
   Max_Manifest_Bytes : constant := Header_Size + 8 * Max_Entries;
   type Selection is array (Positive range <>) of Positive;
   procedure Build (Store : in out MC_Store.Store; Catalog, Closure : Digest;
      Chosen : Selection; Limit, Deadline : Counter;
      Manifest, Archive : out Digest; Status : out Outcome);
   procedure Verify (Store : in out MC_Store.Store; Manifest : Digest;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome);
   procedure Verify_Target (Store : in out MC_Store.Store; Manifest, Catalog, Closure : Digest;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome);
   procedure Verify_Ownership (Store : in out MC_Store.Store; Manifest, Catalog, Closure : Digest;
      Native_Architecture : String; Limit, Deadline : Counter;
      Archive, Ownership_Binding : out Digest; Status : out Outcome);
   -- Adds native shared-file/Replaces validation using the enclosing intent's
   -- architecture. This still does not grant site/effect or extraction authority.
   -- Additionally requires the exact enclosing generation's catalog and closure.
   -- Assemble real payload tar records into one root archive in the existing
   -- CAS. Every canonical path needs one explicit claim index, in path order.
   -- Shared-path choices are recorded, not inferred from package input order.
   -- Root and every parent must be selected directories. Each selected hardlink
   -- must retain its direct target from the same original. Directories precede
   -- other entries, and hardlink targets precede their dependents.
   -- Local extension headers, names, clocks, flags, ACLs, xattrs and payload
   -- bytes are copied intact from independently reobserved original tar spans.
   -- No conversion to the narrower control-state file-plan attribute profile.
   -- NIAROOT2 emits directories in canonical raw path order, root first and
   -- parents before children. All other entries retain source order except
   -- required hardlink dependencies. Legacy NIAROOT1 bytes remain verifiable;
   -- Verify_Ownership additionally refuses legacy archives whose ordering is
   -- unsuitable for physical staging. No implicit migration or publication.
   -- The manifest binds catalog, retention closure, payload fingerprint, root tar,
   -- byte length and the complete ordered claim selection. Build/Verify confer
   -- no ownership override, effect, publication or boot permission. The selected
   -- claim decisions still require independent site/effect authorization.
   -- UID0 refused; finite deadlines and the caller's store reservation required.
   -- Failed calls clear outputs and can leave unreferenced complete CAS blobs.
end Pkg_Root_Archive;
