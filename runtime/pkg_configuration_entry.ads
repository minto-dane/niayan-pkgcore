-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Conffile_Choice;
package Pkg_Configuration_Entry with SPARK_Mode => Off is
   procedure Prepare (Store : in out MC_Store.Store; Effect : Pkg_Conffile_Choice.File_Effect;
      Deadline : Counter; Prefix : out Digest; Size : out Counter; Status : out Outcome);
   -- Reobserve retained vendor payload or NIACOBS1 attributes and build one
   -- regular-file PAX/header prefix in the existing CAS. Content is the exact
   -- Effect.Content object and Size its verified byte count. The caller appends
   -- that content, padding and archive terminators when assembling the root.
   -- Numeric owner/mode assertions must match their retained source. A vendor
   -- permission override changes ACL owner/mask/other as chmod would, retaining
   -- named entries. Named ACL IDs above C int'Last are refused. ACL identities are numeric: symbolic display labels remain
   -- in the original record and never invoke the host account database.
   -- Local raw POSIX access ACLs become semantic archive ACLs; other visible
   -- xattrs retain names/values. Flags must roundtrip through the platform's
   -- archive flag vocabulary. Extent layout is observation, not a settable flag.
   -- Unknown active statx effects, unresolved local hardlink topology, malformed
   -- attributes and unsupported flag/ACL meanings are refused, never omitted.
   -- This reads retained records, not live root state. Caller must recheck the
   -- original choices, retain all sources/prefixes and obtain managed admission.
   -- No extraction/publication or UID0 use. Failures clear outputs; complete
   -- unreferenced CAS objects may remain. ctime/birthtime stay historical values.
end Pkg_Configuration_Entry;
