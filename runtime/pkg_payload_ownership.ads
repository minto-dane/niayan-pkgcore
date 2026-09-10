-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with Pkg_Payload_Index; with Pkg_Selected_Catalog; with Pkg_Root_Archive;
package Pkg_Payload_Ownership with SPARK_Mode => Off is
   type Failure_Kind is (Not_Checked, None, Invalid_Selection, Unjustified_Takeover,
      Different_Shared_File, Directory_Attributes);
   type Finding is record
      Kind : Failure_Kind := Not_Checked;
      Selected_Claim, Other_Claim : Natural := 0;
   end record;
   procedure Check (Catalog : Pkg_Selected_Catalog.Catalog; Payload : Pkg_Payload_Index.Index;
      Chosen : Pkg_Root_Archive.Selection; Native_Architecture : String; Deadline : Counter;
      Binding : out Digest; Issue : out Finding; Status : out Outcome);
   -- Validates the logical owners of a complete, explicit candidate selection.
   -- Directories may remain shared when numeric ownership, mode, ACLs, xattrs
   -- and flags agree; selected archive clocks and symbolic names are retained.
   -- Same-name/version Multi-Arch:same instances may share identical inode
   -- content/link text and security attributes. Other takeovers require the
   -- selected owner's version/architecture-qualified Replaces of the real owner.
   -- Provides never grants file ownership. Replaces is directional, not a
   -- transitive grant through a third package. All losing claims are checked.
   -- Binding covers catalog, payload, native architecture and chosen indices.
   -- Does not grant site permission, resolve administrator configuration,
   -- alternatives/diversions, script/trigger effects, or validate physical state.
   -- Root/archive structure and hardlink topology are checked by the assembler.
   -- UID0 and infinite deadlines are refused. All failure bindings are zero.
end Pkg_Payload_Ownership;
