-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Root_Configuration; with Pkg_Root_Archive;
with Pkg_Configured_Root_Record;
package Pkg_Configured_Root with SPARK_Mode => Off is
   Header_Size : constant := Pkg_Configured_Root_Record.Header_Size;
   Retention_Header_Size : constant := Pkg_Configured_Root_Record.Retention_Header_Size;
   Max_Objects : constant := Pkg_Configured_Root_Record.Max_Objects;
   procedure Build (Store : in out MC_Store.Store; Base_Manifest, Catalog, Catalog_Closure : Digest;
      Root_ID, Transaction : Identity; Context : Digest; Native_Architecture : String;
      Selected : Pkg_Root_Configuration.Choices; Limit, Deadline : Counter;
      Manifest, Archive, Retained : out Digest; Status : out Outcome);
   procedure Verify (Store : in out MC_Store.Store; Manifest, Retained : Digest;
      Base_Manifest, Catalog, Catalog_Closure : Digest; Root_ID, Transaction : Identity;
      Context : Digest; Native_Architecture : String; Selected : Pkg_Root_Configuration.Choices;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome);
   procedure Verify_Current (Store : in out MC_Store.Store; Root_FD : Integer;
      Manifest, Retained, Base_Manifest, Catalog, Catalog_Closure : Digest;
      Root_ID, Transaction : Identity; Context : Digest; Native_Architecture : String;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome);
   -- For a newly acquired Store reservation: inspect the complete saved closure,
   -- freshly reobserve each recorded choice against the supplied current root,
   -- then verify native ownership/layout and rebuild through the ordinary path.
   -- Every output byte, prefix/content, position and non-session binding must
   -- match. Only fresh proposal deadlines and their derived record references
   -- differ; those records are not substituted into the historical generation.
   -- Old choice closures are checked against freshly derived sources. No missing
   -- listed object is recreated before inspection. New unpinned cache/session
   -- objects may remain even on failure; the returned archive is the saved one.
   -- Does not revive an old proposal or authenticate root FD, scope, consent,
   -- request freshness or recovery permission. Callers must provide fresh managed
   -- admission, hold the current root/CAS reservations and recheck at use. Mount,
   -- inode and attribute identity changes are refused; reboot migration and
   -- accepted-state reconciliation require separate rules, not normalization.
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
   -- live proposals. Pkg_Configured_Root_Record.Load provides read-only saved
   -- reference inspection without a live proposal, never execution/GC authority.
   -- Failed calls clear outputs; unreferenced completed CAS blobs may remain.
   -- UID0, infinite deadlines and unsupported configuration effects are refused.
end Pkg_Configured_Root;
